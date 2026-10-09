//! Local-only administrative actions and conservative repeated collection.
use super::{
    http::{now, Config},
    identity::{decode, principal_id, Session},
    metadata,
};
use anyhow::{ensure, Result};
use clap::Subcommand;
use rusqlite::{params, TransactionBehavior};
use serde_json::{json, Value};
use std::{path::Path, sync::Arc};
use uuid::Uuid;
use y_sweet_core::store::Store;

#[derive(Subcommand)]
pub enum Command {
    /// List every relay, its owners and lifecycle state (local operator only).
    List,
    /// Add a configured public key as an Owner, including lost-key recovery.
    AddOwner {
        relay: String,
        public_key: String,
    },
    /// Remove a relay Owner, including one whose key was removed from config.
    RemoveOwner {
        relay: String,
        principal: String,
    },
    /// Revoke a principal everywhere. Existing scoped grants expire normally.
    RevokePrincipal {
        principal: String,
    },
    Suspend {
        relay: String,
    },
    Resume {
        relay: String,
    },
    /// Irreversibly tombstone a relay and every live shared folder.
    Delete {
        relay: String,
        #[arg(long)]
        yes: bool,
    },
    /// Report current object bytes and unclassified namespaces, without deleting.
    Usage,
    /// Collect tombstoned namespaces after their recorded safety deadline.
    Gc {
        #[arg(long)]
        dry_run: bool,
    },
}

pub async fn run(
    config: &Config,
    transfer_url_ttl: u64,
    command: &Command,
    store: Arc<dyn Store>,
) -> Result<Value> {
    metadata::initialize(&config.database)?;
    metadata::record_retention_policy(
        &config.database,
        config.token_ttl_seconds,
        transfer_url_ttl,
    )?;
    let mut db = metadata::connect(&config.database)?;
    match command {
        Command::RevokePrincipal { principal } => {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure!(
                tx.execute(
                    "UPDATE principals SET revoked=1,revision=revision+1 WHERE id=?1",
                    [principal]
                )? == 1,
                "principal unavailable"
            );
            tx.execute("UPDATE relays SET revision=revision+1 WHERE id IN (SELECT relay FROM relay_owners WHERE principal=?1 UNION SELECT relay FROM relay_members WHERE principal=?1 UNION SELECT relay FROM folders WHERE id IN (SELECT folder FROM folder_members WHERE principal=?1))",[principal])?;
            tx.execute(
                "UPDATE invitations SET enabled=0 WHERE creator=?1",
                [principal],
            )?;
            tx.commit()?;
            Ok(json!({"revoked":principal}))
        }
        Command::List => {
            let rows:Vec<Value> = db.prepare("SELECT id,name,state,deleted_at,gc_not_before,last_gc_at,gc_empty_at FROM relays ORDER BY id")?.query_map([],|r|Ok(json!({"id":r.get::<_,String>(0)?,"name":r.get::<_,String>(1)?,"state":r.get::<_,String>(2)?,"deletedAt":r.get::<_,Option<u64>>(3)?,"gcNotBefore":r.get::<_,Option<u64>>(4)?,"lastGcAt":r.get::<_,Option<u64>>(5)?,"gcEmptyAt":r.get::<_,Option<u64>>(6)?})))?.collect::<rusqlite::Result<_>>()?;
            let mut result = Vec::new();
            let owners = metadata::Owners::new(&config.owners)?;
            for mut row in rows {
                let principals:Vec<String> = db.prepare("SELECT o.principal FROM relay_owners o JOIN principals p ON p.id=o.principal WHERE o.relay=?1 AND p.revoked=0 ORDER BY o.principal")?.query_map([row["id"].as_str().unwrap()],|r|r.get(0))?.collect::<rusqlite::Result<_>>()?;
                row["ownerless"] = json!(!principals.iter().any(|p| owners.contains(p)));
                row["owners"] = json!(principals);
                row["lastGcError"] = db
                    .query_row(
                        "SELECT last_gc_error FROM relays WHERE id=?1",
                        [row["id"].as_str().unwrap()],
                        |r| r.get::<_, Option<String>>(0),
                    )?
                    .map(Value::String)
                    .unwrap_or(Value::Null);
                let folders:Vec<Value> = db.prepare("SELECT id,name,deleted_at,gc_not_before,last_gc_at,gc_empty_at,last_gc_error FROM folders WHERE relay=?1 ORDER BY id")?.query_map([row["id"].as_str().unwrap()],|r|Ok(json!({"id":r.get::<_,String>(0)?,"name":r.get::<_,String>(1)?,"deletedAt":r.get::<_,Option<u64>>(2)?,"gcNotBefore":r.get::<_,Option<u64>>(3)?,"lastGcAt":r.get::<_,Option<u64>>(4)?,"gcEmptyAt":r.get::<_,Option<u64>>(5)?,"lastGcError":r.get::<_,Option<String>>(6)?})))?.collect::<rusqlite::Result<_>>()?;
                row["folders"] = json!(folders);
                result.push(row);
            }
            Ok(json!(result))
        }
        Command::AddOwner { relay, public_key } => {
            let principal = principal_id(&decode::<32>(public_key)?);
            ensure!(
                metadata::Owners::new(&config.owners)?.contains(&principal),
                "public key must be configured first"
            );
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            metadata::register(
                &tx,
                &Session {
                    principal: principal.clone(),
                    public_key: public_key.clone(),
                    expires_at: 0,
                },
                "Recovered Owner",
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO relay_owners VALUES (?1,?2)",
                params![relay, principal],
            )?;
            tx.execute(
                "DELETE FROM relay_members WHERE relay=?1 AND principal=?2",
                params![relay, principal],
            )?;
            metadata::bump(&tx, relay)?;
            tx.commit()?;
            Ok(json!({"owner":principal}))
        }
        Command::RemoveOwner { relay, principal } => {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            tx.execute(
                "DELETE FROM relay_owners WHERE relay=?1 AND principal=?2",
                params![relay, principal],
            )?;
            metadata::bump(&tx, relay)?;
            tx.commit()?;
            Ok(json!({"removed":principal}))
        }
        Command::Suspend { relay } | Command::Resume { relay } => {
            let state = if matches!(command, Command::Suspend { .. }) {
                "suspended"
            } else {
                "active"
            };
            ensure!(db.execute("UPDATE relays SET state=?2,revision=revision+1 WHERE id=?1 AND state!='deleted'",params![relay,state])? == 1,"relay unavailable");
            Ok(json!({"id":relay,"state":state}))
        }
        Command::Delete { relay, yes } => {
            ensure!(*yes, "pass --yes to confirm irreversible deletion");
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            metadata::delete_relay(&tx, relay, now(), metadata::retention_grace(&tx)?)?;
            tx.commit()?;
            Ok(json!({"deleted":relay}))
        }
        Command::Usage => {
            let mut totals = std::collections::BTreeMap::<String, u64>::new();
            let mut cursor = None;
            let mut total = 0;
            loop {
                let page = store.list_page("", cursor.as_deref()).await?;
                for file in page.files {
                    total += file.size;
                    let key = file.key.strip_prefix("files/").unwrap_or(&file.key);
                    let relay = key
                        .get(..36)
                        .filter(|id| {
                            metadata::canonical_uuid(id).is_ok()
                                && key.as_bytes().get(36) == Some(&b'-')
                        })
                        .unwrap_or("unclassified");
                    *totals.entry(relay.to_owned()).or_default() += file.size;
                }
                cursor = page.next_continuation_token;
                if cursor.is_none() {
                    break;
                }
            }
            let mut usage = Vec::new();
            for (id, bytes) in totals {
                let known: bool = db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM relays WHERE id=?1)",
                    [&id],
                    |r| r.get(0),
                )?;
                usage.push(json!({"relay":id,"bytes":bytes,"classified":known}));
            }
            Ok(json!({"totalBytes":total,"relays":usage,"versionsIncluded":false}))
        }
        Command::Gc { dry_run } => collect(&config.database, store.as_ref(), *dry_run, now()).await,
    }
}

fn renew(path: &Path, holder: &str, time: u64) -> Result<()> {
    let db = metadata::connect(path)?;
    ensure!(db.execute("UPDATE maintenance_leases SET expires_at=?2 WHERE name='gc' AND holder=?1 AND expires_at>?3",params![holder,time+300,time])? == 1,"GC lease lost");
    Ok(())
}

pub async fn collect(path: &Path, store: &dyn Store, dry_run: bool, time: u64) -> Result<Value> {
    let db = metadata::connect(path)?;
    let holder = Uuid::new_v4().to_string();
    ensure!(db.execute("INSERT INTO maintenance_leases VALUES ('gc',?1,?2) ON CONFLICT(name) DO UPDATE SET holder=excluded.holder,expires_at=excluded.expires_at WHERE maintenance_leases.expires_at<=?3",params![holder,now()+300,now()])? == 1,"another collector holds the lease");
    let result = collect_inner(path, store, dry_run, time, &holder).await;
    db.execute(
        "DELETE FROM maintenance_leases WHERE name='gc' AND holder=?1",
        [holder],
    )?;
    result
}

async fn collect_inner(
    path: &Path,
    store: &dyn Store,
    dry_run: bool,
    time: u64,
    holder: &str,
) -> Result<Value> {
    let db = metadata::connect(path)?;
    let folders: Vec<(String, String)> = db
        .prepare("SELECT id,relay FROM folders WHERE deleted_at IS NOT NULL AND gc_not_before<=?1")?
        .query_map([time], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let mut deleted = 0u64;
    let mut bytes = 0u64;
    let mut errors = 0u64;
    for (folder, relay) in folders {
        let mut empty = true;
        let mut failed = false;
        let mut after = String::new();
        loop {
            let resources:Vec<(String,String)> = db.prepare("SELECT guid,kind FROM resources WHERE folder=?1 AND guid>?2 ORDER BY guid LIMIT 256")?.query_map(params![folder,after],|r|Ok((r.get(0)?,r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
            if resources.is_empty() {
                break;
            }
            for (guid, kind) in resources {
                metadata::canonical_uuid(&relay)?;
                metadata::canonical_uuid(&guid)?;
                let prefix = format!(
                    "{}{relay}-{guid}/",
                    if kind == "file" { "files/" } else { "" }
                );
                match sweep(path, store, &prefix, dry_run, holder).await {
                    Ok((count, size, clear)) => {
                        deleted += count;
                        bytes += size;
                        empty &= clear;
                    }
                    Err(_) => {
                        failed = true;
                        empty = false;
                        errors += 1;
                    }
                }
                after = guid;
            }
        }
        if !dry_run {
            db.execute(
                "UPDATE folders SET last_gc_at=?2,gc_empty_at=?3,last_gc_error=?4 WHERE id=?1",
                params![
                    folder,
                    time,
                    if empty { Some(time) } else { None },
                    if failed {
                        Some("store_operation_failed")
                    } else {
                        None
                    }
                ],
            )?;
        }
    }
    let relays:Vec<String> = db.prepare("SELECT id FROM relays WHERE state='deleted' AND gc_not_before<=?1 AND NOT EXISTS(SELECT 1 FROM folders WHERE relay=relays.id AND (gc_not_before>?1 OR gc_not_before IS NULL))")?.query_map([time],|r|r.get(0))?.collect::<rusqlite::Result<_>>()?;
    for relay in relays {
        metadata::canonical_uuid(&relay)?;
        let mut empty = true;
        let mut failed = false;
        for prefix in [format!("{relay}-"), format!("files/{relay}-")] {
            match sweep(path, store, &prefix, dry_run, holder).await {
                Ok((count, size, clear)) => {
                    deleted += count;
                    bytes += size;
                    empty &= clear;
                }
                Err(_) => {
                    failed = true;
                    empty = false;
                    errors += 1;
                }
            }
        }
        if !dry_run {
            db.execute(
                "UPDATE relays SET last_gc_at=?2,gc_empty_at=?3,last_gc_error=?4 WHERE id=?1",
                params![
                    relay,
                    time,
                    if empty { Some(time) } else { None },
                    if failed {
                        Some("store_operation_failed")
                    } else {
                        None
                    }
                ],
            )?;
        }
    }
    ensure!(errors==0,"GC incomplete: {errors} namespace operations failed; {deleted} objects ({bytes} bytes) processed; run control list for persisted status");
    Ok(json!({"dryRun":dry_run,"objects":deleted,"bytes":bytes,"errors":errors}))
}

async fn sweep(
    path: &Path,
    store: &dyn Store,
    prefix: &str,
    dry_run: bool,
    holder: &str,
) -> Result<(u64, u64, bool)> {
    let mut cursor = None;
    let mut count = 0;
    let mut bytes = 0;
    loop {
        renew(path, holder, now())?;
        let page = store.list_page(prefix, cursor.as_deref()).await?;
        for file in page.files {
            ensure!(
                file.key.starts_with(prefix),
                "store returned key outside GC target"
            );
            renew(path, holder, now())?;
            if !dry_run && store.exists(&file.key).await? {
                store.remove(&file.key).await?;
            }
            count += 1;
            bytes += file.size;
        }
        cursor = page.next_continuation_token;
        if cursor.is_none() {
            break;
        }
    }
    let verify = store.list_page(prefix, None).await?;
    Ok((
        count,
        bytes,
        verify.files.is_empty() && verify.next_continuation_token.is_none(),
    ))
}
