use super::{
    http::{Config, Control},
    identity::{principal_id, Challenge, Session},
    maintenance, metadata,
};
use anyhow::Result;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;
use y_sweet_core::{auth::b64_encode, store::Store};

#[tokio::test]
async fn backend_lifetime_drives_server_and_operator_retention() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let config = Config {
        database: dir.path().join("control.db"),
        owners: vec![],
        allowed_origins: vec![],
        read_only: false,
        minimum_free_bytes: 0,
        max_attachment_bytes: 250 * 1024 * 1024,
        token_ttl_seconds: 300,
    };
    for kind in ["s3", "aws", "cloudflare", "backblaze", "minio", "tigris"] {
        let source = format!("type = \"{kind}\"\nbucket = \"test\"\naccount_id = \"test\"\nendpoint = \"https://example.test/\"\n");
        let defaults = toml::from_str(&source)?;
        assert_eq!(config.transfer_url_ttl(&defaults)?, 900);
        let customized = toml::from_str(&(source.clone() + "presigned_url_expiration = 1800\n"))?;
        assert_eq!(config.transfer_url_ttl(&customized)?, 1800);
        let invalid = toml::from_str(&(source + "presigned_url_expiration = 0\n"))?;
        assert!(config.transfer_url_ttl(&invalid).is_err());
    }
    let s3 = toml::from_str("type = \"s3\"\nbucket = \"test\"\npresigned_url_expiration = 1800\n")?;
    let control = Control::new(
        config.clone(),
        "https://example.test/",
        config.transfer_url_ttl(&s3)?,
    )?;
    let db = metadata::connect(&config.database)?;
    assert_eq!(metadata::retention_grace(&db)?, 300 + 1800 + 360);
    drop(control);

    let filesystem = y_sweet_core::config::StoreConfig::Filesystem(
        y_sweet_core::config::FilesystemStoreConfig {
            path: dir.path().join("objects").display().to_string(),
        },
    );
    assert_eq!(config.transfer_url_ttl(&filesystem)?, 300);
    let store = std::sync::Arc::new(crate::stores::filesystem::FileSystemStore::new(
        dir.path().join("objects"),
    )?);
    maintenance::run(
        &config,
        config.transfer_url_ttl(&filesystem)?,
        &maintenance::Command::List,
        store,
    )
    .await?;
    // Changing backend/lifetimes must not shorten the grace for old S3 URLs.
    assert_eq!(metadata::retention_grace(&db)?, 300 + 1800 + 360);
    assert!(config
        .transfer_url_ttl(&y_sweet_core::config::StoreConfig::Memory)
        .is_err());
    Ok(())
}

async fn request(
    router: &Router,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    request_with_revision(router, method, path, token, body, None).await
}

async fn request_with_revision(
    router: &Router,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
    revision: Option<u64>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if !token.is_empty() {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    if let Some(revision) = revision {
        req = req.header("if-match", format!("\"{revision}\""));
    }
    let req = req.body(Body::from(body.to_string())).unwrap();
    let response = router.clone().oneshot(req).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn invitation_limits_revision_conflicts_and_operator_revocation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let owner = SigningKey::from_bytes(&[11; 32]);
    let user = SigningKey::from_bytes(&[12; 32]);
    let stranger = SigningKey::from_bytes(&[13; 32]);
    let config = Config {
        database: dir.path().join("control.db"),
        owners: vec![b64_encode(&owner.verifying_key().to_bytes())],
        allowed_origins: vec![],
        read_only: false,
        minimum_free_bytes: 0,
        max_attachment_bytes: 250 * 1024 * 1024,
        token_ttl_seconds: 900,
    };
    let control = Control::new(config.clone(), "https://example.test/", 900)?;
    assert!(
        Control::new(config.clone(), "https://example.test/", 900).is_err(),
        "two processes must not serve one metadata database"
    );
    #[cfg(unix)]
    {
        let alias = dir.path().join("alias.sqlite");
        std::os::unix::fs::symlink(&config.database, &alias)?;
        let mut alias_config = config.clone();
        alias_config.database = alias;
        assert!(
            Control::new(alias_config, "https://example.test/", 900).is_err(),
            "symlink aliases must share the server lock"
        );
    }
    let router = control.routes();
    let alice = login(&router, &owner).await;
    let bob = login(&router, &user).await;
    let eve = login(&router, &stranger).await;
    let (_, relay) = request(
        &router,
        "POST",
        "/api/v1/relays",
        &alice,
        json!({"name":"first"}),
    )
    .await;
    let relay = relay["id"].as_str().unwrap();
    let root = format!("/api/v1/relays/{relay}");
    let (_, state) = request(&router, "GET", "/api/v1/state", &alice, Value::Null).await;
    let revision = state["relays"][0]["revision"].as_u64().unwrap();
    assert_eq!(
        request(
            &router,
            "PATCH",
            &root,
            &alice,
            json!({"name":"missing revision"})
        )
        .await
        .0,
        StatusCode::PRECONDITION_REQUIRED
    );
    assert_eq!(
        request_with_revision(
            &router,
            "PATCH",
            &root,
            &alice,
            json!({"name":"renamed"}),
            Some(revision)
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request_with_revision(
            &router,
            "PATCH",
            &root,
            &alice,
            json!({"name":"stale"}),
            Some(revision)
        )
        .await
        .0,
        StatusCode::PRECONDITION_FAILED
    );
    for limits in [
        json!({"access":"read","maxUses":0}),
        json!({"access":"read","ttlSeconds":86401}),
    ] {
        assert_eq!(
            request(
                &router,
                "POST",
                &format!("{root}/invitations"),
                &alice,
                limits
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    let (_, invite) = request(
        &router,
        "POST",
        &format!("{root}/invitations"),
        &alice,
        json!({"access":"read","maxUses":1,"ttlSeconds":3600}),
    )
    .await;
    let acceptance = json!({"code":invite["code"],"name":"member"});
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/v1/invitations/accept",
            &bob,
            acceptance.clone()
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/v1/invitations/accept",
            &eve,
            acceptance.clone()
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &router,
            "POST",
            &format!("{root}/invitations"),
            &bob,
            json!({"access":"write"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let store = std::sync::Arc::new(crate::stores::filesystem::FileSystemStore::new(
        dir.path().join("objects"),
    )?);
    let principal = principal_id(&user.verifying_key().to_bytes());
    let (_, before) = request(&router, "GET", "/api/v1/state", &alice, Value::Null).await;
    assert!(before["memberships"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["principal"] == principal));
    maintenance::run(
        &config,
        900,
        &maintenance::Command::RevokePrincipal {
            principal: principal.clone(),
        },
        store,
    )
    .await?;
    let (_, after) = request(&router, "GET", "/api/v1/state", &alice, Value::Null).await;
    assert!(!after["memberships"]
        .as_array()
        .unwrap()
        .iter()
        .any(|m| m["principal"] == principal));
    assert_eq!(
        request(&router, "GET", "/api/v1/me", &bob, Value::Null)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/v1/invitations/accept",
            &bob,
            acceptance
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[tokio::test]
async fn low_disk_space_allows_reads_but_not_new_resource_claims() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let owner = SigningKey::from_bytes(&[21; 32]);
    let control = Control::new(
        Config {
            database: dir.path().join("control.db"),
            owners: vec![b64_encode(&owner.verifying_key().to_bytes())],
            allowed_origins: vec![],
            read_only: false,
            minimum_free_bytes: u64::MAX,
            max_attachment_bytes: 250 * 1024 * 1024,
            token_ttl_seconds: 900,
        },
        "https://example.test/",
        900,
    )?;
    assert!(!control.writes.writable());
    let router = control.routes();
    let alice = login(&router, &owner).await;
    let (_, relay) = request(
        &router,
        "POST",
        "/api/v1/relays",
        &alice,
        json!({"name":"safe"}),
    )
    .await;
    let relay = relay["id"].as_str().unwrap();
    let root = format!("/api/v1/relays/{relay}");
    let folder = Uuid::new_v4().to_string();
    assert_eq!(
        request(
            &router,
            "POST",
            &format!("{root}/folders"),
            &alice,
            json!({"id":folder,"name":"folder"})
        )
        .await
        .0,
        StatusCode::OK
    );
    let (status, token) = request(
        &router,
        "POST",
        "/token",
        &alice,
        json!({"relay":relay,"folder":folder,"docId":folder}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(token["authorization"], "read-only");
    assert_eq!(
        request(
            &router,
            "POST",
            "/token",
            &alice,
            json!({"relay":relay,"folder":folder,"docId":Uuid::new_v4().to_string()})
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        request(&router, "DELETE", &root, &alice, Value::Null)
            .await
            .0,
        StatusCode::OK
    );
    Ok(())
}

async fn login(router: &Router, key: &SigningKey) -> String {
    let public = b64_encode(&key.verifying_key().to_bytes());
    let (status, value) = request(
        router,
        "POST",
        "/api/v1/auth/challenges",
        "",
        json!({"version":1,"publicKey":public}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let c: Challenge = serde_json::from_value(value).unwrap();
    let (status,value) = request(router,"POST","/api/v1/auth/sessions","",json!({"id":c.id,"publicKey":public,"signature":b64_encode(&key.sign(&c.transcript().unwrap()).to_bytes())})).await;
    assert_eq!(status, StatusCode::OK);
    value["token"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn http_invitation_policy_bindings_and_revocation() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let owner = SigningKey::from_bytes(&[1; 32]);
    let user = SigningKey::from_bytes(&[2; 32]);
    let control = Control::new(
        Config {
            database: dir.path().join("control.db"),
            owners: vec![b64_encode(&owner.verifying_key().to_bytes())],
            allowed_origins: vec![],
            read_only: false,
            minimum_free_bytes: 0,
            max_attachment_bytes: 250 * 1024 * 1024,
            token_ttl_seconds: 900,
        },
        "https://example.test/",
        900,
    )?;
    let router = control.routes();
    let alice = login(&router, &owner).await;
    let bob = login(&router, &user).await;
    assert_eq!(
        request(&router, "GET", "/api/v1/state", &bob, Value::Null)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/v1/relays",
            &bob,
            json!({"name":"no"})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (status, relay) = request(
        &router,
        "POST",
        "/api/v1/relays",
        &alice,
        json!({"name":"one"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let relay = relay["id"].as_str().unwrap();
    let root = format!("/api/v1/relays/{relay}");
    let folder = Uuid::new_v4().to_string();
    let hidden = Uuid::new_v4().to_string();
    for id in [&folder, &hidden] {
        assert_eq!(
            request(
                &router,
                "POST",
                &format!("{root}/folders"),
                &alice,
                json!({"id":id,"name":"folder"})
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    let (status, invitation) = request(
        &router,
        "POST",
        &format!("{root}/invitations"),
        &alice,
        json!({"folder":folder,"access":"read"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let acceptance = json!({"code":invitation["code"],"name":"Bob"});
    for _ in 0..2 {
        assert_eq!(
            request(
                &router,
                "POST",
                "/api/v1/invitations/accept",
                &bob,
                acceptance.clone()
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    let (status, state) = request(&router, "GET", "/api/v1/state", &bob, Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(state["folders"].as_array().unwrap().len(), 1);
    assert_eq!(state["folders"][0]["id"], folder);
    let doc = Uuid::new_v4().to_string();
    let grant = json!({"relay":relay,"folder":folder,"docId":doc});
    assert_eq!(
        request(&router, "POST", "/token", &bob, grant.clone())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&router, "POST", "/token", &alice, grant.clone())
            .await
            .0,
        StatusCode::OK
    );
    let (status, token) = request(&router, "POST", "/token", &bob, grant.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(token["authorization"], "read-only");
    let bad = json!({"relay":relay,"folder":hidden,"docId":doc});
    assert_eq!(
        request(&router, "POST", "/token", &alice, bad).await.0,
        StatusCode::FORBIDDEN
    );
    let principal = principal_id(&user.verifying_key().to_bytes());
    assert_eq!(
        request(
            &router,
            "DELETE",
            &format!("{root}/folders/{folder}/members/{principal}"),
            &alice,
            Value::Null
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    // A response-loss retry does not resurrect a subsequently revoked grant.
    assert_eq!(
        request(
            &router,
            "POST",
            "/api/v1/invitations/accept",
            &bob,
            acceptance
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(&router, "POST", "/token", &bob, grant.clone())
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    // Wrong-relay deletion cannot revoke the real folder's grants or invitations.
    let (_, other) = request(
        &router,
        "POST",
        "/api/v1/relays",
        &alice,
        json!({"name":"two"}),
    )
    .await;
    assert_eq!(
        request(
            &router,
            "DELETE",
            &format!(
                "/api/v1/relays/{}/folders/{folder}",
                other["id"].as_str().unwrap()
            ),
            &alice,
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(&router, "POST", "/token", &alice, grant.clone())
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            &router,
            "DELETE",
            &format!("{root}/folders/{folder}"),
            &alice,
            Value::Null
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(&router, "POST", "/token", &alice, grant).await.0,
        StatusCode::FORBIDDEN
    );
    Ok(())
}

#[tokio::test]
async fn collection_retains_live_data_waits_and_repeats_after_late_writes() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("metadata.db");
    metadata::initialize(&path)?;
    metadata::record_retention_policy(&path, 3600, 3600)?;
    metadata::record_retention_policy(&path, 900, 900)?;
    let mut db = metadata::connect(&path)?;
    assert_eq!(metadata::retention_grace(&db)?, 7560);
    let key = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
    let owner = Session {
        principal: principal_id(&key),
        public_key: b64_encode(&key),
        expires_at: 99999,
    };
    let owners = metadata::Owners::new(&[owner.public_key.clone()])?;
    let folder = Uuid::new_v4().to_string();
    let live = Uuid::new_v4().to_string();
    let child = Uuid::new_v4().to_string();
    let tx = db.transaction()?;
    metadata::register(&tx, &owner, "Owner")?;
    let relay = metadata::create_relay(&tx, &owners, &owner.principal, "test")?;
    for id in [&folder, &live] {
        metadata::create_folder(
            &tx,
            &owners,
            &owner.principal,
            &relay,
            id,
            "folder",
            false,
            100,
        )?;
    }
    metadata::authorize_resource(
        &tx,
        &owners,
        &owner.principal,
        &relay,
        &folder,
        &child,
        "file",
        100,
    )?;
    metadata::delete_folder(&tx, &relay, &folder, 100, 50)?;
    tx.commit()?;
    let store = crate::stores::filesystem::FileSystemStore::new(dir.path().join("objects"))?;
    let root = format!("{relay}-{folder}/data.ysweet");
    let file = format!("files/{relay}-{child}/{}", "a".repeat(64));
    let alive = format!("{relay}-{live}/data.ysweet");
    let unknown = "unclassified-object";
    for id in [&root, &file, &alive, &unknown.to_owned()] {
        store.set(id, vec![1; 10]).await?;
    }
    // A concurrent collector must fail before touching any objects. A stale
    // lease is recoverable after a process crash without manual DB repair.
    db.execute(
        "INSERT INTO maintenance_leases VALUES ('gc','other',?1)",
        [super::http::now() + 300],
    )?;
    assert!(maintenance::collect(&path, &store, false, 150)
        .await
        .is_err());
    assert!(store.exists(&root).await?);
    db.execute(
        "UPDATE maintenance_leases SET expires_at=0 WHERE name='gc'",
        [],
    )?;
    assert_eq!(
        maintenance::collect(&path, &store, false, 149).await?["objects"],
        0
    );
    assert_eq!(
        maintenance::collect(&path, &store, true, 150).await?["objects"],
        2
    );
    assert!(store.exists(&root).await?);
    assert_eq!(
        maintenance::collect(&path, &store, false, 150).await?["objects"],
        2
    );
    assert!(!store.exists(&root).await? && !store.exists(&file).await?);
    assert!(store.exists(&alive).await? && store.exists(unknown).await?);
    store.set(&file, vec![2; 10]).await?;
    assert_eq!(
        maintenance::collect(&path, &store, false, 151).await?["objects"],
        1
    );
    assert!(store.exists(&alive).await?);
    Ok(())
}

// Exercise the collector against backend pagination/failure contracts without
// requiring live S3 credentials. Real filesystem objects remain the test data.
struct PagedStore {
    inner: crate::stores::filesystem::FileSystemStore,
    failing_prefix: String,
    failure: std::sync::atomic::AtomicBool,
    escape_prefix: std::sync::atomic::AtomicBool,
    pages: std::sync::atomic::AtomicUsize,
}

#[async_trait::async_trait]
impl Store for PagedStore {
    async fn init(&self) -> y_sweet_core::store::Result<()> {
        self.inner.init().await
    }
    async fn get(&self, key: &str) -> y_sweet_core::store::Result<Option<Vec<u8>>> {
        self.inner.get(key).await
    }
    async fn set(&self, key: &str, value: Vec<u8>) -> y_sweet_core::store::Result<()> {
        self.inner.set(key, value).await
    }
    async fn exists(&self, key: &str) -> y_sweet_core::store::Result<bool> {
        self.inner.exists(key).await
    }
    async fn remove(&self, key: &str) -> y_sweet_core::store::Result<()> {
        self.inner.remove(key).await
    }
    async fn list_page(
        &self,
        prefix: &str,
        cursor: Option<&str>,
    ) -> y_sweet_core::store::Result<y_sweet_core::store::FileListPage> {
        use std::sync::atomic::Ordering;
        use y_sweet_core::store::{FileInfo, FileListPage, StoreError};
        self.pages.fetch_add(1, Ordering::SeqCst);
        if self.failure.load(Ordering::SeqCst) && prefix == self.failing_prefix {
            return Err(StoreError::ConnectionError(
                "sensitive backend diagnostic".into(),
            ));
        }
        if self.escape_prefix.load(Ordering::SeqCst) {
            return Ok(FileListPage {
                files: vec![FileInfo {
                    key: "unrelated".into(),
                    size: 1,
                    last_modified: 0,
                }],
                common_prefixes: vec![],
                next_continuation_token: None,
            });
        }
        let mut files = self.inner.list(prefix).await?;
        files.sort_by(|a, b| a.key.cmp(&b.key));
        files.retain(|file| cursor.is_none_or(|after| file.key.as_str() > after));
        let more = files.len() > 2;
        files.truncate(2);
        let next = if more {
            files.last().map(|file| file.key.clone())
        } else {
            None
        };
        Ok(FileListPage {
            files,
            common_prefixes: vec![],
            next_continuation_token: next,
        })
    }
}

#[tokio::test]
async fn collection_pages_isolates_backend_failures_and_refuses_out_of_scope_objects() -> Result<()>
{
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("control.db");
    metadata::initialize(&path)?;
    let mut db = metadata::connect(&path)?;
    let key = SigningKey::from_bytes(&[61; 32]).verifying_key().to_bytes();
    let owner = Session {
        principal: principal_id(&key),
        public_key: b64_encode(&key),
        expires_at: 99999,
    };
    let owners = metadata::Owners::new(&[owner.public_key.clone()])?;
    let folders = [Uuid::new_v4().to_string(), Uuid::new_v4().to_string()];
    let tx = db.transaction()?;
    metadata::register(&tx, &owner, "Owner")?;
    let relay = metadata::create_relay(&tx, &owners, &owner.principal, "collection")?;
    for folder in &folders {
        metadata::create_folder(
            &tx,
            &owners,
            &owner.principal,
            &relay,
            folder,
            "folder",
            false,
            100,
        )?;
        metadata::delete_folder(&tx, &relay, folder, 100, 50)?;
    }
    tx.commit()?;
    let prefixes = folders
        .iter()
        .map(|folder| format!("{relay}-{folder}/"))
        .collect::<Vec<_>>();
    let store = PagedStore {
        inner: crate::stores::filesystem::FileSystemStore::new(dir.path().join("objects"))?,
        failing_prefix: prefixes[0].clone(),
        failure: AtomicBool::new(true),
        escape_prefix: AtomicBool::new(false),
        pages: AtomicUsize::new(0),
    };
    for prefix in &prefixes {
        for index in 0..7 {
            store.set(&format!("{prefix}{index}"), vec![1; 10]).await?;
        }
    }
    store.set("unrelated", vec![1]).await?;
    assert!(maintenance::collect(&path, &store, false, 150)
        .await
        .is_err());
    assert_eq!(store.inner.list(&prefixes[0]).await?.len(), 7);
    assert!(
        store.inner.list(&prefixes[1]).await?.is_empty(),
        "one failing namespace must not block others"
    );
    let (error, empty): (String, Option<u64>) = db.query_row(
        "SELECT last_gc_error,gc_empty_at FROM folders WHERE id=?1",
        [&folders[0]],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    assert_eq!(error, "store_operation_failed");
    assert!(empty.is_none());
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM maintenance_leases", [], |r| r
            .get::<_, u64>(0))?,
        0
    );
    store.failure.store(false, Ordering::SeqCst);
    store.escape_prefix.store(true, Ordering::SeqCst);
    assert!(maintenance::collect(&path, &store, false, 151)
        .await
        .is_err());
    assert!(store.exists("unrelated").await?);
    store.escape_prefix.store(false, Ordering::SeqCst);
    assert_eq!(
        maintenance::collect(&path, &store, false, 152).await?["objects"],
        7
    );
    assert!(store.inner.list(&prefixes[0]).await?.is_empty());
    assert!(store.pages.load(Ordering::SeqCst) > 8);
    assert!(store.exists("unrelated").await?);
    let error: Option<String> = db.query_row(
        "SELECT last_gc_error FROM folders WHERE id=?1",
        [&folders[0]],
        |r| r.get(0),
    )?;
    assert!(error.is_none());
    Ok(())
}

#[tokio::test]
async fn concurrent_owner_removal_preserves_one_owner_and_self_leave_cannot_change_strangers(
) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let alice_key = SigningKey::from_bytes(&[31; 32]);
    let bob_key = SigningKey::from_bytes(&[32; 32]);
    let config = Config {
        database: dir.path().join("control.db"),
        owners: vec![
            b64_encode(&alice_key.verifying_key().to_bytes()),
            b64_encode(&bob_key.verifying_key().to_bytes()),
        ],
        allowed_origins: vec![],
        read_only: false,
        minimum_free_bytes: 0,
        max_attachment_bytes: 250 * 1024 * 1024,
        token_ttl_seconds: 900,
    };
    let control = Control::new(config, "https://example.test/", 900)?;
    let router = control.routes();
    let alice = login(&router, &alice_key).await;
    let bob = login(&router, &bob_key).await;
    let alice_id = principal_id(&alice_key.verifying_key().to_bytes());
    let bob_id = principal_id(&bob_key.verifying_key().to_bytes());
    let (_, created) = request(
        &router,
        "POST",
        "/api/v1/relays",
        &alice,
        json!({"name":"owned"}),
    )
    .await;
    let id = created["id"].as_str().unwrap();
    let root = format!("/api/v1/relays/{id}");
    // Configured eligibility is not ownership, or even visibility.
    assert!(request(&router, "GET", "/api/v1/state", &bob, Value::Null)
        .await
        .1["relays"]
        .as_array()
        .unwrap()
        .is_empty());
    let (_, before) = request(&router, "GET", "/api/v1/state", &alice, Value::Null).await;
    assert_eq!(
        request(
            &router,
            "DELETE",
            &format!("{root}/members/{bob_id}"),
            &bob,
            Value::Null
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(&router, "GET", "/api/v1/state", &alice, Value::Null)
            .await
            .1,
        before
    );
    assert_eq!(
        request(
            &router,
            "DELETE",
            &format!("{root}/owners/{alice_id}"),
            &alice,
            Value::Null
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        request(
            &router,
            "POST",
            &format!("{root}/owners/{bob_id}"),
            &alice,
            Value::Null
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    let alice_path = format!("{root}/owners/{alice_id}");
    let bob_path = format!("{root}/owners/{bob_id}");
    let (a, b) = tokio::join!(
        request(&router, "DELETE", &alice_path, &alice, Value::Null),
        request(&router, "DELETE", &bob_path, &bob, Value::Null)
    );
    assert_eq!(
        [a.0, b.0]
            .iter()
            .filter(|s| **s == StatusCode::NO_CONTENT)
            .count(),
        1
    );
    assert_eq!(
        [a.0, b.0]
            .iter()
            .filter(|s| **s == StatusCode::FORBIDDEN)
            .count(),
        1
    );
    let db = metadata::connect(&control.config.database)?;
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM relay_owners WHERE relay=?1",
            [id],
            |r| r.get::<_, u64>(0)
        )?,
        1
    );
    Ok(())
}

#[test]
fn metadata_initialization_rejects_unrelated_and_future_schemas() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let unrelated = dir.path().join("unrelated.db");
    let db = metadata::connect(&unrelated)?;
    db.execute("CREATE TABLE unrelated (value TEXT)", [])?;
    assert!(metadata::initialize(&unrelated).is_err());
    let future = dir.path().join("future.db");
    metadata::initialize(&future)?;
    metadata::initialize(&future)?;
    metadata::connect(&future)?.execute("INSERT INTO schema_migrations VALUES (2)", [])?;
    assert!(metadata::initialize(&future).is_err());
    Ok(())
}

#[tokio::test]
async fn concurrent_acceptance_never_exceeds_invitation_limit_and_leave_revokes_folder_grants(
) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let owner = SigningKey::from_bytes(&[41; 32]);
    let users = [
        SigningKey::from_bytes(&[42; 32]),
        SigningKey::from_bytes(&[43; 32]),
    ];
    let control = Control::new(
        Config {
            database: dir.path().join("control.db"),
            owners: vec![b64_encode(&owner.verifying_key().to_bytes())],
            allowed_origins: vec![],
            read_only: false,
            minimum_free_bytes: 0,
            max_attachment_bytes: 250 * 1024 * 1024,
            token_ttl_seconds: 900,
        },
        "https://example.test/",
        900,
    )?;
    let router = control.routes();
    let alice = login(&router, &owner).await;
    let bob = login(&router, &users[0]).await;
    let eve = login(&router, &users[1]).await;
    let (_, created) = request(
        &router,
        "POST",
        "/api/v1/relays",
        &alice,
        json!({"name":"race"}),
    )
    .await;
    let relay = created["id"].as_str().unwrap();
    let root = format!("/api/v1/relays/{relay}");
    let folder = Uuid::new_v4().to_string();
    assert_eq!(
        request(
            &router,
            "POST",
            &format!("{root}/folders"),
            &alice,
            json!({"id":folder,"name":"private","private":true})
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, invitation) = request(
        &router,
        "POST",
        &format!("{root}/invitations"),
        &alice,
        json!({"access":"write","maxUses":1}),
    )
    .await;
    let acceptance = json!({"code":invitation["code"],"name":"racer"});
    let (b, e) = tokio::join!(
        request(
            &router,
            "POST",
            "/api/v1/invitations/accept",
            &bob,
            acceptance.clone()
        ),
        request(
            &router,
            "POST",
            "/api/v1/invitations/accept",
            &eve,
            acceptance
        )
    );
    assert_eq!(
        [b.0, e.0].iter().filter(|s| **s == StatusCode::OK).count(),
        1
    );
    assert_eq!(
        [b.0, e.0]
            .iter()
            .filter(|s| **s == StatusCode::FORBIDDEN)
            .count(),
        1
    );
    let (token, key) = if b.0 == StatusCode::OK {
        (&bob, &users[0])
    } else {
        (&eve, &users[1])
    };
    let principal = principal_id(&key.verifying_key().to_bytes());
    let (_, before) = request(&router, "GET", "/api/v1/state", &alice, Value::Null).await;
    let revision = before["relays"][0]["revision"].as_u64().unwrap();
    assert_eq!(
        request_with_revision(
            &router,
            "POST",
            &format!("{root}/folders/{folder}/members/{principal}"),
            &alice,
            json!({"access":"write"}),
            Some(revision)
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    let (_, before) = request(&router, "GET", "/api/v1/state", &alice, Value::Null).await;
    assert_eq!(
        request(
            &router,
            "DELETE",
            &format!("{root}/members/{principal}"),
            token,
            Value::Null
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    let (_, after) = request(&router, "GET", "/api/v1/state", &alice, Value::Null).await;
    assert!(after["folderMemberships"].as_array().unwrap().is_empty());
    assert_eq!(
        after["folders"][0]["revision"].as_u64().unwrap(),
        before["folders"][0]["revision"].as_u64().unwrap() + 1
    );
    assert!(request(&router, "GET", "/api/v1/state", token, Value::Null)
        .await
        .1["relays"]
        .as_array()
        .unwrap()
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn cors_body_limits_and_private_snapshot_caching() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let owner = SigningKey::from_bytes(&[51; 32]);
    let config = Config {
        database: dir.path().join("control.db"),
        owners: vec![b64_encode(&owner.verifying_key().to_bytes())],
        allowed_origins: vec!["app://obsidian.md".into()],
        read_only: false,
        minimum_free_bytes: 0,
        max_attachment_bytes: 250 * 1024 * 1024,
        token_ttl_seconds: 900,
    };
    let control = Control::new(config, "https://example.test/base/", 900)?;
    let token = login(&control.routes(), &owner).await;
    let router = control.mount(Router::new())?;
    for (origin, allowed) in [
        ("app://obsidian.md", true),
        ("https://untrusted.example", false),
        ("null", false),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/base/api/v1/me")
                    .header("origin", origin)
                    .header("access-control-request-method", "GET")
                    .header("access-control-request-headers", "authorization")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_some(),
            allowed
        );
        assert!(!response
            .headers()
            .contains_key("access-control-allow-credentials"));
    }
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/base/api/v1/state")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers()["cache-control"]
        .to_str()?
        .contains("private"));
    let etag = response.headers()["etag"].clone();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/base/api/v1/state")
                .header("authorization", format!("Bearer {token}"))
                .header("if-none-match", etag)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(
        request(
            &router,
            "POST",
            "/base/api/v1/auth/challenges",
            "",
            json!({"publicKey":"x".repeat(16384)})
        )
        .await
        .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let response = router
        .oneshot(
            Request::builder()
                .uri("/base/api/v1/me")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.headers()["cache-control"], "no-store");
    Ok(())
}

#[tokio::test]
async fn read_only_transition_closes_live_sockets_rejects_old_writers_and_allows_readers(
) -> Result<()> {
    use futures::StreamExt;
    use std::{
        sync::{atomic::Ordering, Arc},
        time::Duration,
    };
    use tokio_tungstenite::{
        connect_async,
        tungstenite::{Error as WsError, Message},
    };
    let dir = tempfile::tempdir()?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}/base/", listener.local_addr()?);
    let owner = SigningKey::from_bytes(&[71; 32]);
    let control = Control::new(
        Config {
            database: dir.path().join("control.db"),
            owners: vec![b64_encode(&owner.verifying_key().to_bytes())],
            allowed_origins: vec![],
            read_only: false,
            minimum_free_bytes: 0,
            max_attachment_bytes: 250 * 1024 * 1024,
            token_ttl_seconds: 900,
        },
        &base,
        900,
    )?;
    let cancel = tokio_util::sync::CancellationToken::new();
    let mut server = crate::server::Server::new(
        Some(Box::new(crate::stores::filesystem::FileSystemStore::new(
            dir.path().join("objects"),
        )?)),
        Duration::from_secs(1),
        Some(control.tokens.verifier()),
        Some(base.parse()?),
        vec![],
        cancel.clone(),
        true,
        None,
    )
    .await?;
    server.set_read_only_signal(control.writes.read_only.clone());
    let server = Arc::new(server);
    let router = control.mount(server.routes())?;
    let task = tokio::spawn(async move { axum::serve(listener, router).await });
    let routes = control.routes();
    let alice = login(&routes, &owner).await;
    let (_, relay) = request(
        &routes,
        "POST",
        "/api/v1/relays",
        &alice,
        json!({"name":"sockets"}),
    )
    .await;
    let relay = relay["id"].as_str().unwrap();
    let folder = Uuid::new_v4().to_string();
    assert_eq!(
        request(
            &routes,
            "POST",
            &format!("/api/v1/relays/{relay}/folders"),
            &alice,
            json!({"id":folder,"name":"root"})
        )
        .await
        .0,
        StatusCode::OK
    );
    let grant = json!({"relay":relay,"folder":folder,"docId":folder});
    let (_, full) = request(&routes, "POST", "/token", &alice, grant.clone()).await;
    let socket_url = |token: &Value| {
        format!(
            "{}/{}?token={}",
            token["url"].as_str().unwrap(),
            token["docId"].as_str().unwrap(),
            token["token"].as_str().unwrap()
        )
    };
    let (mut socket, _) = connect_async(socket_url(&full)).await?;
    // Drive the same signal + connection-generation transition as the disk
    // monitor, without filling the developer's filesystem.
    control.writes.read_only.store(true, Ordering::Release);
    server.interrupt_doc_sockets();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(error)) => panic!("socket failed instead of closing: {error}"),
                _ => {}
            }
        }
    })
    .await?;
    match connect_async(socket_url(&full)).await {
        Err(WsError::Http(response)) => {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE)
        }
        _ => panic!("old writable grant accepted during read-only mode"),
    }
    let (status, read) = request(&routes, "POST", "/token", &alice, grant.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read["authorization"], "read-only");
    let (mut reader, _) = connect_async(socket_url(&read)).await?;
    reader.close(None).await?;
    control.writes.read_only.store(false, Ordering::Release);
    let (_, full) = request(&routes, "POST", "/token", &alice, grant).await;
    let (mut writer, _) = connect_async(socket_url(&full)).await?;
    writer.close(None).await?;
    cancel.cancel();
    task.abort();
    Ok(())
}
