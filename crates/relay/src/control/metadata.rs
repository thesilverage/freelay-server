//! Durable authorization and resource lifetime. All mutations are transactions.
use super::identity::{decode, principal_id, Session};
use anyhow::{ensure, Result};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, path::Path, time::Duration};
use uuid::Uuid;

#[derive(Clone)]
pub struct Owners(HashSet<String>);

impl Owners {
    pub fn new(keys: &[String]) -> Result<Self> {
        let mut owners = HashSet::new();
        for key in keys {
            let bytes = decode::<32>(key)?;
            let public = ed25519_dalek::VerifyingKey::from_bytes(&bytes)?;
            ensure!(!public.is_weak(), "weak Owner key");
            ensure!(owners.insert(principal_id(&bytes)), "duplicate Owner key");
        }
        Ok(Self(owners))
    }

    pub fn contains(&self, principal: &str) -> bool {
        self.0.contains(principal)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    Read,
    Write,
}

impl Access {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
    fn parse(s: String) -> Self {
        if s == "write" {
            Self::Write
        } else {
            Self::Read
        }
    }
    fn intersect(self, other: Self) -> Self {
        if self == Self::Write && other == Self::Write {
            Self::Write
        } else {
            Self::Read
        }
    }
}

pub fn canonical_uuid(id: &str) -> Result<()> {
    ensure!(
        Uuid::parse_str(id)?.hyphenated().to_string() == id,
        "noncanonical UUID"
    );
    Ok(())
}

pub fn connect(path: &Path) -> Result<Connection> {
    let db = Connection::open(path)?;
    db.busy_timeout(Duration::from_secs(5))?;
    db.pragma_update(None, "foreign_keys", "ON")?;
    Ok(db)
}

pub fn initialize(path: &Path) -> Result<()> {
    let mut db = connect(path)?;
    db.pragma_update(None, "journal_mode", "WAL")?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let initialized:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations')",[],|r|r.get(0))?;
    if initialized {
        let version: Option<u64> =
            tx.query_row("SELECT MAX(version) FROM schema_migrations", [], |r| {
                r.get(0)
            })?;
        ensure!(
            version == Some(1),
            "unsupported metadata schema version; use a matching server release"
        );
        // Fail closed on incomplete/development schemas rather than silently
        // adding tables to a database whose lifecycle semantics are unknown.
        tx.prepare("SELECT last_gc_error FROM relays LIMIT 0")?;
        tx.prepare("SELECT last_gc_error FROM folders LIMIT 0")?;
        tx.prepare("SELECT grace_seconds FROM retention_policy LIMIT 0")?;
    } else {
        let tables: u64 = tx.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        )?;
        ensure!(
            tables == 0,
            "refusing to initialize an unrelated metadata database"
        );
        tx.execute_batch(include_str!("schema.sql"))?;
    }
    tx.commit()?;
    Ok(())
}

pub fn register(tx: &Transaction<'_>, session: &Session, name: &str) -> Result<()> {
    ensure!(name.len() <= 200, "name too long");
    tx.execute(
        "INSERT OR IGNORE INTO principals(id,public_key,name) VALUES (?1,?2,?3)",
        params![session.principal, session.public_key, name],
    )?;
    require_principal(tx, &session.principal)
}

pub fn record_retention_policy(path: &Path, token_ttl: u64, url_ttl: u64) -> Result<()> {
    ensure!(
        (60..=3600).contains(&token_ttl) && (60..=3600).contains(&url_ttl),
        "invalid capability lifetime"
    );
    connect(path)?.execute("INSERT INTO retention_policy VALUES (1,?1) ON CONFLICT(id) DO UPDATE SET grace_seconds=MAX(grace_seconds,excluded.grace_seconds)",[token_ttl+url_ttl+360])?;
    Ok(())
}

pub fn retention_grace(db: &Connection) -> Result<u64> {
    // Refuse collection/deletion against an uninitialized policy instead of
    // guessing a shorter window from the maintenance command's configuration.
    Ok(db.query_row(
        "SELECT grace_seconds FROM retention_policy WHERE id=1",
        [],
        |r| r.get(0),
    )?)
}

pub fn require_principal(db: &Connection, principal: &str) -> Result<()> {
    let active: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM principals WHERE id=?1 AND revoked=0)",
        [principal],
        |r| r.get(0),
    )?;
    ensure!(active, "principal not registered or revoked");
    Ok(())
}

pub fn is_owner(db: &Connection, owners: &Owners, principal: &str, relay: &str) -> Result<bool> {
    if !owners.contains(principal) {
        return Ok(false);
    }
    Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM relay_owners o JOIN principals p ON p.id=o.principal WHERE o.relay=?1 AND o.principal=?2 AND p.revoked=0)", params![relay,principal], |r| r.get(0))?)
}

pub fn require_active(db: &Connection, relay: &str) -> Result<()> {
    let active: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM relays WHERE id=?1 AND state='active')",
        [relay],
        |r| r.get(0),
    )?;
    ensure!(active, "relay unavailable");
    Ok(())
}

pub fn require_owner(db: &Connection, owners: &Owners, principal: &str, relay: &str) -> Result<()> {
    require_principal(db, principal)?;
    require_active(db, relay)?;
    ensure!(
        is_owner(db, owners, principal, relay)?,
        "relay ownership required"
    );
    Ok(())
}

pub fn access(
    db: &Connection,
    owners: &Owners,
    principal: &str,
    relay: &str,
    folder: &str,
) -> Result<Access> {
    require_principal(db, principal)?;
    require_active(db, relay)?;
    let private: bool = db.query_row(
        "SELECT private FROM folders WHERE id=?1 AND relay=?2 AND deleted_at IS NULL",
        params![folder, relay],
        |r| r.get(0),
    )?;
    if is_owner(db, owners, principal, relay)? {
        return Ok(Access::Write);
    }
    let relay_access = db
        .query_row(
            "SELECT access FROM relay_members WHERE relay=?1 AND principal=?2",
            params![relay, principal],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .map(Access::parse);
    let folder_access = db
        .query_row(
            "SELECT access FROM folder_members WHERE folder=?1 AND principal=?2",
            params![folder, principal],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .map(Access::parse);
    match (relay_access, folder_access, private) {
        (Some(a), _, false) => Ok(a),
        (Some(a), Some(b), true) => Ok(a.intersect(b)),
        (None, Some(a), _) => Ok(a),
        _ => anyhow::bail!("folder access denied"),
    }
}

pub fn create_relay(
    tx: &Transaction<'_>,
    owners: &Owners,
    principal: &str,
    name: &str,
) -> Result<String> {
    require_principal(tx, principal)?;
    ensure!(owners.contains(principal), "configured Owner required");
    ensure!(!name.is_empty() && name.len() <= 200, "invalid name");
    let id = Uuid::new_v4().to_string();
    tx.execute(
        "INSERT INTO relays(id,name) VALUES (?1,?2)",
        params![id, name],
    )?;
    tx.execute(
        "INSERT INTO relay_owners(relay,principal) VALUES (?1,?2)",
        params![id, principal],
    )?;
    Ok(id)
}

pub fn create_folder(
    tx: &Transaction<'_>,
    owners: &Owners,
    principal: &str,
    relay: &str,
    id: &str,
    name: &str,
    private: bool,
    now: u64,
) -> Result<()> {
    require_owner(tx, owners, principal, relay)?;
    canonical_uuid(id)?;
    ensure!(!name.is_empty() && name.len() <= 200, "invalid name");
    tx.execute(
        "INSERT INTO folders(id,relay,name,private,creator) VALUES (?1,?2,?3,?4,?5)",
        params![id, relay, name, private, principal],
    )?;
    // Register roots too, so a preclaimed child GUID cannot become a folder and
    // acquire a second authorization path or garbage-collection owner.
    tx.execute(
        "INSERT INTO resources(relay,guid,folder,kind,first_seen_at) VALUES (?1,?2,?2,'ydoc',?3)",
        params![relay, id, now],
    )?;
    bump(tx, relay)?;
    Ok(())
}

pub fn authorize_resource(
    tx: &Transaction<'_>,
    owners: &Owners,
    principal: &str,
    relay: &str,
    folder: &str,
    guid: &str,
    kind: &str,
    now: u64,
) -> Result<Access> {
    canonical_uuid(relay)?;
    canonical_uuid(folder)?;
    canonical_uuid(guid)?;
    ensure!(kind == "ydoc" || kind == "file", "invalid resource kind");
    let grant = access(tx, owners, principal, relay, folder)?;
    let existing: Option<(String, String)> = tx
        .query_row(
            "SELECT folder,kind FROM resources WHERE relay=?1 AND guid=?2",
            params![relay, guid],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match existing {
        Some((home, resource_kind)) => ensure!(
            home == folder && resource_kind == kind,
            "resource binding conflict"
        ),
        None => {
            ensure!(grant == Access::Write, "readers cannot register resources");
            tx.execute("INSERT INTO resources(relay,guid,folder,kind,first_seen_at) VALUES (?1,?2,?3,?4,?5)",params![relay,guid,folder,kind,now])?;
        }
    }
    Ok(grant)
}

pub fn bump(tx: &Transaction<'_>, relay: &str) -> Result<()> {
    tx.execute("UPDATE relays SET revision=revision+1 WHERE id=?1", [relay])?;
    Ok(())
}

pub fn invite(
    tx: &Transaction<'_>,
    owners: &Owners,
    principal: &str,
    relay: &str,
    folder: Option<&str>,
    grant: Access,
    now: u64,
    max_uses: u32,
    ttl_seconds: u64,
) -> Result<(String, String)> {
    use sha2::{Digest, Sha256};
    require_owner(tx, owners, principal, relay)?;
    ensure!(
        max_uses > 0 && (1..=86400).contains(&ttl_seconds),
        "invitation must have finite uses and expire within 24 hours"
    );
    if let Some(folder) = folder {
        access(tx, owners, principal, relay, folder)?;
    }
    let secret = super::identity::random::<32>();
    let id = Uuid::new_v4().to_string();
    tx.execute("INSERT INTO invitations(id,relay,folder,verifier,access,expires_at,max_uses,creator) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![id,relay,folder,Sha256::digest(secret).as_slice(),grant.as_str(),now+ttl_seconds,max_uses,principal])?;
    bump(tx, relay)?;
    Ok((id, y_sweet_core::auth::b64_encode(&secret)))
}

pub fn accept(
    tx: &Transaction<'_>,
    session: &Session,
    secret: &str,
    name: &str,
    now: u64,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(decode::<32>(secret)?);
    let (id,relay,folder,grant,expires,uses,max_uses,enabled): (String,String,Option<String>,String,u64,u64,u64,bool) = tx.query_row(
        "SELECT id,relay,folder,access,expires_at,uses,max_uses,enabled FROM invitations WHERE verifier=?1",[hash.as_slice()],
        |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?)))?;
    require_active(tx, &relay)?;
    if let Some(ref folder) = folder {
        ensure!(
            tx.query_row(
                "SELECT deleted_at IS NULL FROM folders WHERE id=?1",
                [folder],
                |r| r.get::<_, bool>(0)
            )?,
            "folder deleted"
        );
    }
    let accepted: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM invitation_acceptances WHERE invitation=?1 AND principal=?2)",
        params![id, session.principal],
        |r| r.get(0),
    )?;
    // Retries never restore a grant subsequently revoked or downgraded.
    if accepted {
        require_principal(tx, &session.principal)?;
        return Ok(relay);
    }
    ensure!(
        enabled && expires > now && uses < max_uses,
        "invitation unavailable"
    );
    register(tx, session, name)?;
    if let Some(folder) = folder {
        tx.execute("INSERT INTO folder_members(folder,principal,access) VALUES (?1,?2,?3) ON CONFLICT(folder,principal) DO NOTHING",params![folder,session.principal,grant])?;
        tx.execute(
            "UPDATE folders SET revision=revision+1 WHERE id=?1",
            [folder],
        )?;
    } else {
        tx.execute("INSERT INTO relay_members(relay,principal,access) VALUES (?1,?2,?3) ON CONFLICT(relay,principal) DO NOTHING",params![relay,session.principal,grant])?;
    }
    tx.execute(
        "INSERT INTO invitation_acceptances VALUES (?1,?2)",
        params![id, session.principal],
    )?;
    tx.execute("UPDATE invitations SET uses=uses+1 WHERE id=?1", [id])?;
    bump(tx, &relay)?;
    Ok(relay)
}

pub fn delete_folder(
    tx: &Transaction<'_>,
    relay: &str,
    folder: &str,
    now: u64,
    grace: u64,
) -> Result<()> {
    ensure!(
        tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM folders WHERE id=?1 AND relay=?2)",
            params![folder, relay],
            |r| r.get::<_, bool>(0)
        )?,
        "folder unavailable"
    );
    tx.execute("UPDATE folders SET deleted_at=?3,gc_not_before=?4,revision=revision+1 WHERE id=?1 AND relay=?2 AND deleted_at IS NULL",params![folder,relay,now,now+grace])?;
    tx.execute("DELETE FROM folder_members WHERE folder=?1", [folder])?;
    tx.execute("UPDATE invitations SET enabled=0 WHERE folder=?1", [folder])?;
    bump(tx, relay)?;
    Ok(())
}

pub fn delete_relay(tx: &Transaction<'_>, relay: &str, now: u64, grace: u64) -> Result<()> {
    ensure!(
        tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM relays WHERE id=?1)",
            [relay],
            |r| r.get::<_, bool>(0)
        )?,
        "relay unavailable"
    );
    let folders: Vec<String> = tx
        .prepare("SELECT id FROM folders WHERE relay=?1 AND deleted_at IS NULL")?
        .query_map([relay], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for folder in folders {
        delete_folder(tx, relay, &folder, now, grace)?;
    }
    tx.execute("UPDATE relays SET state='deleted',deleted_at=?2,gc_not_before=?3,revision=revision+1 WHERE id=?1 AND state!='deleted'",params![relay,now,now+grace])?;
    tx.execute("DELETE FROM relay_members WHERE relay=?1", [relay])?;
    tx.execute("UPDATE invitations SET enabled=0 WHERE relay=?1", [relay])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::identity::principal_id;
    use super::*;
    use y_sweet_core::auth::b64_encode;

    #[test]
    fn bindings_prevent_relabeling_root_collision_and_post_deletion_access() -> Result<()> {
        let file = tempfile::NamedTempFile::new()?;
        initialize(file.path())?;
        let mut db = connect(file.path())?;
        let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32])
            .verifying_key()
            .to_bytes();
        let session = Session {
            principal: principal_id(&key),
            public_key: b64_encode(&key),
            expires_at: 1000,
        };
        let owners = Owners::new(&[session.public_key.clone()])?;
        let tx = db.transaction()?;
        register(&tx, &session, "Alice")?;
        let relay = create_relay(&tx, &owners, &session.principal, "test")?;
        let folder = Uuid::new_v4().to_string();
        let other = Uuid::new_v4().to_string();
        create_folder(
            &tx,
            &owners,
            &session.principal,
            &relay,
            &folder,
            "one",
            false,
            10,
        )?;
        create_folder(
            &tx,
            &owners,
            &session.principal,
            &relay,
            &other,
            "two",
            true,
            10,
        )?;
        let doc = Uuid::new_v4().to_string();
        authorize_resource(
            &tx,
            &owners,
            &session.principal,
            &relay,
            &folder,
            &doc,
            "ydoc",
            11,
        )?;
        assert!(authorize_resource(
            &tx,
            &owners,
            &session.principal,
            &relay,
            &other,
            &doc,
            "ydoc",
            11
        )
        .is_err());
        assert!(authorize_resource(
            &tx,
            &owners,
            &session.principal,
            &relay,
            &folder,
            &doc,
            "file",
            11
        )
        .is_err());
        assert!(authorize_resource(
            &tx,
            &owners,
            &session.principal,
            &relay,
            &other,
            &folder,
            "ydoc",
            11
        )
        .is_err());
        delete_folder(&tx, &relay, &folder, 12, 2160)?;
        assert!(authorize_resource(
            &tx,
            &owners,
            &session.principal,
            &relay,
            &folder,
            &doc,
            "ydoc",
            13
        )
        .is_err());
        assert_eq!(
            tx.query_row(
                "SELECT COUNT(*) FROM resources WHERE folder=?1",
                [folder],
                |r| r.get::<_, u64>(0)
            )?,
            2
        );
        tx.commit()?;
        Ok(())
    }
}
