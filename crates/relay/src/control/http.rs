use super::{
    identity::{self, Identity, Proof, Session},
    metadata::{self, Access, Owners},
    tokens::TokenIssuer,
};
use anyhow::{ensure, Result};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub database: PathBuf,
    pub owners: Vec<String>,
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default = "default_minimum_free")]
    pub minimum_free_bytes: u64,
    #[serde(default = "default_attachment_size")]
    pub max_attachment_bytes: u64,
    #[serde(default = "default_ttl")]
    pub token_ttl_seconds: u64,
}

impl Config {
    /// Use the same transfer lifetime as the backend, including for local GC.
    pub fn transfer_url_ttl(&self, store: &y_sweet_core::config::StoreConfig) -> Result<u64> {
        ensure!(
            !matches!(store, y_sweet_core::config::StoreConfig::Memory),
            "Freelay requires a persistent store"
        );
        let ttl = store
            .to_s3_config()
            .map_or(self.token_ttl_seconds, |s3| s3.presigned_url_expiration);
        ensure!(
            (60..=3600).contains(&ttl),
            "transfer URL TTL must be 60..3600 seconds"
        );
        Ok(ttl)
    }
}
fn default_ttl() -> u64 {
    900
}
fn default_minimum_free() -> u64 {
    1024 * 1024 * 1024
}
fn default_attachment_size() -> u64 {
    250 * 1024 * 1024
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

pub struct Control {
    pub config: Config,
    pub public_base_url: String,
    pub owners: Owners,
    identity: Mutex<Identity>,
    pub tokens: TokenIssuer,
    pub writes: super::safety::WriteGuard,
    _instance_lock: std::fs::File,
}

impl Control {
    pub fn new(
        mut config: Config,
        public_base_url: &str,
        transfer_url_ttl: u64,
    ) -> Result<Arc<Self>> {
        let public_base_url = identity::canonical_url(public_base_url)?;
        ensure!(
            (60..=3600).contains(&transfer_url_ttl),
            "transfer URL TTL must be 60..3600 seconds"
        );
        let owners = Owners::new(&config.owners)?;
        ensure!(
            config.max_attachment_bytes > 0 && config.max_attachment_bytes <= 250 * 1024 * 1024,
            "attachment bound must be 1..250 MiB"
        );
        // Resolve existing file/parent symlinks before selecting the lock and
        // SQLite WAL paths. Two names for one DB must not start two servers.
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&config.database)?;
        config.database = config.database.canonicalize()?;
        let mut lock_path = config.database.as_os_str().to_os_string();
        lock_path.push(".server-lock");
        let instance_lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(lock_path)?;
        fs2::FileExt::try_lock_exclusive(&instance_lock)
            .map_err(|_| anyhow::anyhow!("another Freelay server holds this metadata database"))?;
        metadata::initialize(&config.database)?;
        metadata::record_retention_policy(
            &config.database,
            config.token_ttl_seconds,
            transfer_url_ttl,
        )?;
        let identity = Mutex::new(Identity::new(&public_base_url)?);
        let tokens = TokenIssuer::new(&public_base_url, config.token_ttl_seconds)?;
        let database_directory = config
            .database
            .canonicalize()?
            .parent()
            .expect("database has parent")
            .to_path_buf();
        let writes = super::safety::WriteGuard::new(
            vec![database_directory, std::env::temp_dir()],
            config.minimum_free_bytes,
            config.read_only,
        );
        Ok(Arc::new(Self {
            config,
            public_base_url,
            owners,
            identity,
            tokens,
            writes,
            _instance_lock: instance_lock,
        }))
    }

    fn session(&self, headers: &HeaderMap) -> ApiResult<Session> {
        let bearer =
            bearer(headers).ok_or(ApiError(StatusCode::UNAUTHORIZED, "session_required"))?;
        self.identity
            .lock()
            .map_err(internal)?
            .session(bearer, now())
            .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "session_expired"))
    }

    async fn transaction<T: Send + 'static>(
        self: &Arc<Self>,
        f: impl FnOnce(&Transaction<'_>, &Owners) -> Result<T> + Send + 'static,
    ) -> ApiResult<T> {
        let state = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut db = metadata::connect(&state.config.database).map_err(internal)?;
            let tx = db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(internal)?;
            let result = f(&tx, &state.owners).map_err(operation_error)?;
            tx.commit().map_err(internal)?;
            Ok(result)
        })
        .await
        .map_err(internal)?
    }

    pub fn routes(self: &Arc<Self>) -> Router {
        Router::new()
            .route("/api/v1/auth/challenges", post(challenge))
            .route("/api/v1/auth/sessions", post(authenticate))
            .route("/api/v1/auth/session", delete(logout))
            .route("/api/v1/me", get(me).patch(profile))
            .route("/api/v1/state", get(snapshot))
            .route("/api/v1/relays", post(create_relay))
            .route(
                "/api/v1/relays/:relay",
                delete(delete_relay).patch(rename_relay),
            )
            .route("/api/v1/relays/:relay/folders", post(create_folder))
            .route(
                "/api/v1/relays/:relay/folders/:folder",
                delete(delete_folder).patch(update_folder),
            )
            .route("/api/v1/relays/:relay/invitations", post(invite))
            .route(
                "/api/v1/relays/:relay/invitations/:invitation",
                delete(revoke_invite),
            )
            .route("/api/v1/invitations/accept", post(accept))
            .route(
                "/api/v1/relays/:relay/members/:principal",
                post(set_member).delete(remove_member),
            )
            .route(
                "/api/v1/relays/:relay/folders/:folder/members/:principal",
                post(set_folder_member).delete(remove_folder_member),
            )
            .route(
                "/api/v1/relays/:relay/owners/:principal",
                post(add_owner).delete(remove_owner),
            )
            .route("/token", post(document_token))
            .route("/file-token", post(file_token))
            .layer(DefaultBodyLimit::max(16 * 1024))
            .layer(axum::middleware::from_fn(no_store))
            .with_state(self.clone())
    }

    pub fn mount(self: &Arc<Self>, data_routes: Router) -> Result<Router> {
        use axum::http::{header, HeaderValue, Method};
        use tower_http::cors::{AllowOrigin, CorsLayer};
        let mut origins = Vec::new();
        for value in &self.config.allowed_origins {
            ensure!(
                value != "*" && value != "null",
                "configure explicit trusted CORS origins"
            );
            origins.push(value.parse::<HeaderValue>()?);
        }
        let cors = CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods([
                Method::GET,
                Method::HEAD,
                Method::POST,
                Method::PATCH,
                Method::DELETE,
                Method::PUT,
            ])
            .allow_headers([
                header::AUTHORIZATION,
                header::CONTENT_TYPE,
                header::IF_MATCH,
                header::IF_NONE_MATCH,
            ])
            .expose_headers([header::ETAG]);
        let data_routes = data_routes.layer(axum::middleware::from_fn_with_state(
            self.clone(),
            guard_data_writes,
        ));
        let routes = data_routes.merge(self.routes());
        let url = url::Url::parse(&self.public_base_url)?;
        let prefix = url.path().trim_end_matches('/');
        let routes = if prefix.is_empty() {
            routes
        } else {
            Router::new().nest(prefix, routes)
        };
        Ok(routes.layer(cors))
    }
}

async fn guard_data_writes(
    State(control): State<Arc<Control>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if !control.writes.writable() {
        let path = request.uri().path();
        let upload =
            path.starts_with("/f/") && (path.ends_with("/upload") || path.ends_with("/upload-url"));
        let mut mutable_document = false;
        if path.starts_with("/d/") {
            let query_token =
                url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
                    .find(|(key, _)| key == "token")
                    .map(|(_, value)| value.into_owned());
            let token = bearer(request.headers()).or(query_token.as_deref());
            mutable_document=token.and_then(|t|control.tokens.verifier().verify_token_auto(t,now()*1000).ok()).is_some_and(|p|matches!(p,y_sweet_core::auth::Permission::Doc(d) if d.authorization==y_sweet_core::api_types::Authorization::Full));
        }
        if upload || mutable_document {
            return ApiError(StatusCode::SERVICE_UNAVAILABLE, "server_read_only").into_response();
        }
    }
    next.run(request).await
}

async fn no_store(request: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .entry("cache-control")
        .or_insert(axum::http::HeaderValue::from_static("no-store"));
    response
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}
type ApiResult<T> = std::result::Result<T, ApiError>;
#[derive(Clone, Copy, Debug)]
pub struct ApiError(StatusCode, &'static str);
impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.1)
    }
}
impl std::error::Error for ApiError {}
fn internal(_: impl std::fmt::Display) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, "internal_error")
}
fn operation_error(error: anyhow::Error) -> ApiError {
    if let Some(api) = error.downcast_ref::<ApiError>() {
        return *api;
    }
    match error.downcast_ref::<rusqlite::Error>() {
        Some(rusqlite::Error::QueryReturnedNoRows) => {
            ApiError(StatusCode::FORBIDDEN, "operation_denied")
        }
        Some(rusqlite::Error::SqliteFailure(failure, _))
            if failure.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            ApiError(StatusCode::CONFLICT, "conflict")
        }
        Some(_) => internal(error),
        None if error.downcast_ref::<uuid::Error>().is_some() => {
            ApiError(StatusCode::BAD_REQUEST, "invalid_id")
        }
        None => ApiError(StatusCode::FORBIDDEN, "operation_denied"),
    }
}
fn check_revision(tx: &Transaction<'_>, relay: &str, headers: &HeaderMap) -> Result<()> {
    let expected = headers
        .get("if-match")
        .and_then(|h| h.to_str().ok())
        .ok_or(ApiError(
            StatusCode::PRECONDITION_REQUIRED,
            "revision_required",
        ))?;
    let revision: u64 = tx.query_row("SELECT revision FROM relays WHERE id=?1", [relay], |r| {
        r.get(0)
    })?;
    if expected != format!("\"{revision}\"") {
        return Err(ApiError(StatusCode::PRECONDITION_FAILED, "state_changed").into());
    }
    Ok(())
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"code":self.1}))).into_response()
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChallengeRequest {
    version: u8,
    public_key: String,
}
async fn challenge(
    State(c): State<Arc<Control>>,
    Json(r): Json<ChallengeRequest>,
) -> ApiResult<Json<identity::Challenge>> {
    if r.version != 1 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "unsupported_version"));
    }
    let result = c
        .identity
        .lock()
        .map_err(internal)?
        .challenge(&r.public_key, now())
        .map_err(|error| {
            if error.to_string() == "authentication rate limit" {
                ApiError(StatusCode::TOO_MANY_REQUESTS, "authentication_rate_limited")
            } else {
                ApiError(StatusCode::BAD_REQUEST, "challenge_unavailable")
            }
        })?;
    Ok(Json(result))
}
async fn authenticate(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Json(r): Json<Proof>,
) -> ApiResult<Json<identity::SessionResponse>> {
    let session = c
        .identity
        .lock()
        .map_err(internal)?
        .authenticate(r, bearer(&headers), now())
        .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "invalid_proof"))?;
    let identity = c
        .identity
        .lock()
        .map_err(internal)?
        .session(&session.token, now())
        .map_err(internal)?;
    // Owners can bootstrap their profile, unknown Users cannot allocate rows.
    if c.owners.contains(&identity.principal) {
        c.transaction(move |tx, _| metadata::register(tx, &identity, "Owner"))
            .await?;
    }
    Ok(Json(session))
}
async fn logout(State(c): State<Arc<Control>>, headers: HeaderMap) -> ApiResult<StatusCode> {
    if let Some(token) = bearer(&headers) {
        c.identity
            .lock()
            .map_err(internal)?
            .logout(token)
            .map_err(internal)?;
    }
    Ok(StatusCode::NO_CONTENT)
}
async fn me(State(c): State<Arc<Control>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    let s = c.session(&headers)?;
    c.transaction(move |tx,owners| {
        let revoked: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM principals WHERE id=?1 AND revoked=1)",[&s.principal],|r|r.get(0))?;
        ensure!(!revoked,"principal revoked");
        let name: Option<String> = tx.query_row("SELECT name FROM principals WHERE id=?1 AND revoked=0",[&s.principal],|r|r.get(0)).optional()?;
        Ok(Json(json!({"id":s.principal,"name":name,"publicKey":s.public_key,"ownerEligible":owners.contains(&s.principal),"registered":name.is_some()})))
    }).await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Name {
    name: String,
}
async fn profile(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Json(r): Json<Name>,
) -> ApiResult<Json<Value>> {
    let s = c.session(&headers)?;
    c.transaction(move |tx, _| {
        metadata::require_principal(tx, &s.principal)?;
        ensure!(!r.name.is_empty() && r.name.len() <= 200, "invalid name");
        tx.execute(
            "UPDATE principals SET name=?2,revision=revision+1 WHERE id=?1",
            params![s.principal, r.name],
        )?;
        Ok(Json(json!({"id":s.principal,"name":r.name})))
    })
    .await
}

// Query only visible records; hashed response bytes do not expose unrelated
// relay revisions or reveal hidden private-folder changes through an ETag.
pub fn state(db: &Connection, owners: &Owners, principal: &str) -> Result<Value> {
    metadata::require_principal(db, principal)?;
    let mut relays = Vec::new();
    let mut folders = Vec::new();
    let mut memberships = Vec::new();
    let mut folder_memberships = Vec::new();
    let mut invitations = Vec::new();
    let mut visible_principals = std::collections::BTreeSet::from([principal.to_owned()]);
    let candidates: Vec<(String, String, String, u64)> = db
        .prepare("SELECT id,name,state,revision FROM relays WHERE state!='deleted' ORDER BY id")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (id, name, status, revision) in candidates {
        let owner = metadata::is_owner(db, owners, principal, &id)?;
        let member: Option<String> = db
            .query_row(
                "SELECT access FROM relay_members WHERE relay=?1 AND principal=?2",
                params![id, principal],
                |r| r.get(0),
            )
            .optional()?;
        let visible: Vec<(String,String,bool,u64,String)> = db.prepare("SELECT id,name,private,revision,creator FROM folders WHERE relay=?1 AND deleted_at IS NULL ORDER BY id")?.query_map([&id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?.collect::<rusqlite::Result<_>>()?;
        let mut has_folder = false;
        for (folder, name, private, revision, creator) in visible {
            let direct: Option<String> = db
                .query_row(
                    "SELECT access FROM folder_members WHERE folder=?1 AND principal=?2",
                    params![folder, principal],
                    |r| r.get(0),
                )
                .optional()?;
            let grant = if owner {
                Some("write")
            } else if !private && member.is_some() {
                member.as_deref()
            } else {
                match (member.as_deref(), direct.as_deref()) {
                    (Some("read"), Some(_)) => Some("read"),
                    (_, Some(a)) => Some(a),
                    _ => None,
                }
            };
            if let Some(grant) = grant {
                has_folder = true;
                visible_principals.insert(creator.clone());
                folders.push(json!({"id":folder,"relay":id,"name":name,"private":private,"revision":revision,"access":grant,"creator":creator}));
            }
        }
        if owner || member.is_some() || has_folder {
            let mut row = json!({"id":id,"name":name,"state":status,"owner":owner,"access":member});
            if owner {
                row["revision"] = json!(revision);
            }
            relays.push(row);
            let relay_grants:Vec<(String,String)> = db.prepare("SELECT o.principal,'owner' FROM relay_owners o JOIN principals p ON p.id=o.principal WHERE o.relay=?1 AND p.revoked=0 UNION ALL SELECT m.principal,m.access FROM relay_members m JOIN principals p ON p.id=m.principal WHERE m.relay=?1 AND p.revoked=0 ORDER BY 1")?.query_map([&id],|r|Ok((r.get(0)?,r.get(1)?)))?.collect::<rusqlite::Result<_>>()?;
            for (user, role) in relay_grants {
                if role == "owner" && !metadata::is_owner(db, owners, &user, &id)? {
                    continue;
                }
                if role != "owner" && metadata::is_owner(db, owners, &user, &id)? {
                    continue;
                }
                if owner || user == principal {
                    visible_principals.insert(user.clone());
                    memberships.push(json!({"relay":id,"principal":user,"access":role}));
                }
            }
            let folder_grants:Vec<(String,String,String)> = db.prepare("SELECT m.folder,m.principal,m.access FROM folder_members m JOIN folders f ON f.id=m.folder JOIN principals p ON p.id=m.principal WHERE f.relay=?1 AND f.deleted_at IS NULL AND p.revoked=0 ORDER BY m.folder,m.principal")?.query_map([&id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?.collect::<rusqlite::Result<_>>()?;
            for (folder, user, access) in folder_grants {
                if owner || user == principal {
                    visible_principals.insert(user.clone());
                    folder_memberships
                        .push(json!({"relay":id,"folder":folder,"principal":user,"access":access}));
                }
            }
            if owner {
                let rows:Vec<Value> = db.prepare("SELECT id,folder,access,expires_at,max_uses,uses,enabled FROM invitations WHERE relay=?1 ORDER BY id")?.query_map([&id],|r|Ok(json!({"id":r.get::<_,String>(0)?,"relay":id,"folder":r.get::<_,Option<String>>(1)?,"access":r.get::<_,String>(2)?,"expiresAt":r.get::<_,u64>(3)?,"maxUses":r.get::<_,u64>(4)?,"uses":r.get::<_,u64>(5)?,"enabled":r.get::<_,bool>(6)?})))?.collect::<rusqlite::Result<_>>()?;
                invitations.extend(rows);
            }
        }
    }
    let mut profiles = Vec::new();
    for id in visible_principals {
        if let Some((name, revoked)) = db
            .query_row(
                "SELECT name,revoked FROM principals WHERE id=?1",
                [&id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, bool>(1)?)),
            )
            .optional()?
        {
            // Historical creators still need a display record after revocation;
            // displaying one does not grant that principal any access.
            profiles.push(
                json!({"id":id,"name":name,"ownerEligible":!revoked && owners.contains(&id)}),
            );
        }
    }
    Ok(
        json!({"relays":relays,"folders":folders,"memberships":memberships,"folderMemberships":folder_memberships,"invitations":invitations,"profiles":profiles}),
    )
}
async fn snapshot(State(c): State<Arc<Control>>, headers: HeaderMap) -> ApiResult<Response> {
    let s = c.session(&headers)?;
    let value = c
        .transaction(move |tx, owners| state(tx, owners, &s.principal))
        .await?;
    let etag = format!(
        "\"{}\"",
        hex::encode(Sha256::digest(
            serde_json::to_vec(&value).map_err(internal)?
        ))
    );
    let mut response = if headers.get("if-none-match").and_then(|h| h.to_str().ok()) == Some(&etag)
    {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        Json(value).into_response()
    };
    response
        .headers_mut()
        .insert("etag", etag.parse().map_err(internal)?);
    response
        .headers_mut()
        .insert("cache-control", "private, no-cache".parse().unwrap());
    Ok(response)
}
async fn create_relay(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Json(r): Json<Name>,
) -> ApiResult<Json<Value>> {
    let s = c.session(&headers)?;
    c.transaction(move |tx, owners| {
        Ok(Json(
            json!({"id":metadata::create_relay(tx,owners,&s.principal,&r.name)?,"name":r.name}),
        ))
    })
    .await
}
async fn rename_relay(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Path(relay): Path<String>,
    Json(r): Json<Name>,
) -> ApiResult<StatusCode> {
    let s = c.session(&headers)?;
    c.transaction(move |tx, owners| {
        metadata::require_owner(tx, owners, &s.principal, &relay)?;
        check_revision(tx, &relay, &headers)?;
        ensure!(!r.name.is_empty() && r.name.len() <= 200, "invalid name");
        tx.execute(
            "UPDATE relays SET name=?2,revision=revision+1 WHERE id=?1",
            params![relay, r.name],
        )?;
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Folder {
    id: String,
    name: String,
    #[serde(default)]
    private: bool,
}
async fn create_folder(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Path(relay): Path<String>,
    Json(r): Json<Folder>,
) -> ApiResult<Json<Value>> {
    let s = c.session(&headers)?;
    c.transaction(move |tx, owners| {
        metadata::create_folder(
            tx,
            owners,
            &s.principal,
            &relay,
            &r.id,
            &r.name,
            r.private,
            now(),
        )?;
        Ok(Json(
            json!({"id":r.id,"relay":relay,"name":r.name,"private":r.private}),
        ))
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FolderUpdate {
    name: String,
    private: bool,
}
async fn update_folder(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Path((relay, folder)): Path<(String, String)>,
    Json(r): Json<FolderUpdate>,
) -> ApiResult<StatusCode> {
    let s = c.session(&headers)?;
    c.transaction(move |tx,owners| {
        metadata::require_owner(tx,owners,&s.principal,&relay)?;
        check_revision(tx,&relay,&headers)?;
        ensure!(!r.name.is_empty() && r.name.len()<=200,"invalid name");
        ensure!(tx.execute("UPDATE folders SET name=?3,private=?4,revision=revision+1 WHERE id=?1 AND relay=?2 AND deleted_at IS NULL",params![folder,relay,r.name,r.private])? == 1,"folder unavailable");
        metadata::bump(tx,&relay)?; Ok(StatusCode::NO_CONTENT)
    }).await
}
async fn delete_folder(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Path((relay, folder)): Path<(String, String)>,
) -> ApiResult<Json<Value>> {
    let s = c.session(&headers)?;
    c.transaction(move |tx, owners| {
        metadata::require_owner(tx, owners, &s.principal, &relay)?;
        let grace = metadata::retention_grace(tx)?;
        let time = now();
        metadata::delete_folder(tx, &relay, &folder, time, grace)?;
        let deadline: u64 = tx.query_row(
            "SELECT gc_not_before FROM folders WHERE id=?1",
            [&folder],
            |r| r.get(0),
        )?;
        Ok(Json(
            json!({"id":folder,"deleted":true,"gcNotBefore":deadline}),
        ))
    })
    .await
}
async fn delete_relay(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Path(relay): Path<String>,
) -> ApiResult<Json<Value>> {
    let s = c.session(&headers)?;
    c.transaction(move |tx, owners| {
        metadata::require_owner(tx, owners, &s.principal, &relay)?;
        let grace = metadata::retention_grace(tx)?;
        let time = now();
        metadata::delete_relay(tx, &relay, time, grace)?;
        Ok(Json(
            json!({"id":relay,"deleted":true,"gcNotBefore":time+grace}),
        ))
    })
    .await
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Invitation {
    folder: Option<String>,
    access: Access,
    #[serde(default = "default_invite_uses")]
    max_uses: u32,
    #[serde(default = "default_invite_ttl")]
    ttl_seconds: u64,
}
fn default_invite_uses() -> u32 {
    1
}
fn default_invite_ttl() -> u64 {
    86400
}
async fn invite(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Path(relay): Path<String>,
    Json(r): Json<Invitation>,
) -> ApiResult<Json<Value>> {
    let s = c.session(&headers)?;
    if r.max_uses == 0 || !(1..=86400).contains(&r.ttl_seconds) {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "invalid_invitation_limits",
        ));
    }
    c.transaction(move |tx, owners| {
        let (id, code) = metadata::invite(
            tx,
            owners,
            &s.principal,
            &relay,
            r.folder.as_deref(),
            r.access,
            now(),
            r.max_uses,
            r.ttl_seconds,
        )?;
        Ok(Json(json!({"id":id,"code":code})))
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Acceptance {
    code: String,
    name: String,
}
async fn accept(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Json(r): Json<Acceptance>,
) -> ApiResult<Json<Value>> {
    let s = c.session(&headers)?;
    c.transaction(move |tx, _| {
        Ok(Json(
            json!({"relay":metadata::accept(tx,&s,&r.code,&r.name,now())?}),
        ))
    })
    .await
}
async fn revoke_invite(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Path((relay, id)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let s = c.session(&headers)?;
    c.transaction(move |tx, owners| {
        metadata::require_owner(tx, owners, &s.principal, &relay)?;
        tx.execute(
            "UPDATE invitations SET enabled=0 WHERE id=?1 AND relay=?2",
            params![id, relay],
        )?;
        metadata::bump(tx, &relay)?;
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    access: Access,
}
async fn set_member(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Path((relay, principal)): Path<(String, String)>,
    Json(r): Json<Grant>,
) -> ApiResult<StatusCode> {
    let s = c.session(&headers)?;
    c.transaction(move |tx,owners| {
        metadata::require_owner(tx,owners,&s.principal,&relay)?;
        check_revision(tx,&relay,&headers)?;
        metadata::require_principal(tx,&principal)?;
        // A role change is one transaction: never briefly strand a relay
        // between deleting ownership and assigning ordinary membership.
        if metadata::is_owner(tx,owners,&principal,&relay)? {
            require_other_owner(tx,owners,&relay,&principal)?;
        }
        tx.execute("DELETE FROM relay_owners WHERE relay=?1 AND principal=?2",params![relay,principal])?;
        tx.execute("INSERT INTO relay_members VALUES (?1,?2,?3) ON CONFLICT(relay,principal) DO UPDATE SET access=excluded.access",params![relay,principal,r.access.as_str()])?;
        metadata::bump(tx,&relay)?; Ok(StatusCode::NO_CONTENT)
    }).await
}
async fn remove_member(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Path((relay, principal)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let s = c.session(&headers)?;
    c.transaction(move |tx,owners| {
        metadata::require_principal(tx,&s.principal)?;
        if s.principal!=principal {metadata::require_owner(tx,owners,&s.principal,&relay)?;}
        let removed = tx.execute("DELETE FROM relay_members WHERE relay=?1 AND principal=?2",params![relay,principal])?;
        // Revocation must not leave private grants that silently turn into
        // direct-only membership when the relay membership disappears.
        tx.execute("UPDATE folders SET revision=revision+1 WHERE relay=?2 AND id IN (SELECT folder FROM folder_members WHERE principal=?1)",params![principal,relay])?;
        let folders = tx.execute("DELETE FROM folder_members WHERE principal=?1 AND folder IN (SELECT id FROM folders WHERE relay=?2)",params![principal,relay])?;
        if removed + folders > 0 {metadata::bump(tx,&relay)?;} Ok(StatusCode::NO_CONTENT)
    }).await
}
async fn set_folder_member(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Path((relay, folder, principal)): Path<(String, String, String)>,
    Json(r): Json<Grant>,
) -> ApiResult<StatusCode> {
    let s = c.session(&headers)?;
    c.transaction(move |tx,owners| {
        metadata::require_owner(tx,owners,&s.principal,&relay)?;
        check_revision(tx,&relay,&headers)?;
        metadata::access(tx,owners,&s.principal,&relay,&folder)?;
        metadata::require_principal(tx,&principal)?;
        tx.execute("INSERT INTO folder_members VALUES (?1,?2,?3) ON CONFLICT(folder,principal) DO UPDATE SET access=excluded.access",params![folder,principal,r.access.as_str()])?;
        tx.execute("UPDATE folders SET revision=revision+1 WHERE id=?1",[folder])?;
        metadata::bump(tx,&relay)?; Ok(StatusCode::NO_CONTENT)
    }).await
}
async fn remove_folder_member(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Path((relay, folder, principal)): Path<(String, String, String)>,
) -> ApiResult<StatusCode> {
    let s = c.session(&headers)?;
    c.transaction(move |tx,owners| {
        metadata::require_principal(tx,&s.principal)?;
        if s.principal!=principal {metadata::require_owner(tx,owners,&s.principal,&relay)?;}
        let removed = tx.execute("DELETE FROM folder_members WHERE folder=?1 AND principal=?2 AND folder IN (SELECT id FROM folders WHERE relay=?3)",params![folder,principal,relay])?;
        if removed > 0 {
            tx.execute("UPDATE folders SET revision=revision+1 WHERE id=?1",[folder])?;
            metadata::bump(tx,&relay)?;
        }
        Ok(StatusCode::NO_CONTENT)
    }).await
}
async fn add_owner(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Path((relay, principal)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let s = c.session(&headers)?;
    c.transaction(move |tx, owners| {
        metadata::require_owner(tx, owners, &s.principal, &relay)?;
        metadata::require_principal(tx, &principal)?;
        ensure!(owners.contains(&principal), "target not Owner eligible");
        tx.execute(
            "INSERT OR IGNORE INTO relay_owners VALUES (?1,?2)",
            params![relay, principal],
        )?;
        tx.execute(
            "DELETE FROM relay_members WHERE relay=?1 AND principal=?2",
            params![relay, principal],
        )?;
        metadata::bump(tx, &relay)?;
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}
async fn remove_owner(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Path((relay, principal)): Path<(String, String)>,
) -> ApiResult<StatusCode> {
    let s = c.session(&headers)?;
    c.transaction(move |tx, owners| {
        metadata::require_owner(tx, owners, &s.principal, &relay)?;
        require_other_owner(tx, owners, &relay, &principal)?;
        tx.execute(
            "DELETE FROM relay_owners WHERE relay=?1 AND principal=?2",
            params![relay, principal],
        )?;
        metadata::bump(tx, &relay)?;
        Ok(StatusCode::NO_CONTENT)
    })
    .await
}
fn require_other_owner(
    tx: &Transaction<'_>,
    owners: &Owners,
    relay: &str,
    principal: &str,
) -> Result<()> {
    let remaining: Vec<String> = tx.prepare("SELECT o.principal FROM relay_owners o JOIN principals p ON p.id=o.principal WHERE o.relay=?1 AND o.principal!=?2 AND p.revoked=0")?.query_map(params![relay,principal],|r|r.get(0))?.collect::<rusqlite::Result<_>>()?;
    ensure!(remaining.iter().any(|p| owners.contains(p)), "last Owner");
    Ok(())
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TokenRequest {
    relay: String,
    folder: String,
    doc_id: String,
    device: Option<String>,
    supersede: Option<String>,
}
async fn document_token(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Json(r): Json<TokenRequest>,
) -> ApiResult<Json<Value>> {
    let s = c.session(&headers)?;
    let issuer = c.clone();
    c.transaction(move |tx, owners| {
        let time = now();
        let _ = (r.device, r.supersede);
        if !issuer.writes.writable() {
            if !tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM resources WHERE relay=?1 AND guid=?2)",
                params![r.relay, r.doc_id],
                |r| r.get::<_, bool>(0),
            )? {
                return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "server_read_only").into());
            }
        }
        let access = metadata::authorize_resource(
            tx,
            owners,
            &s.principal,
            &r.relay,
            &r.folder,
            &r.doc_id,
            "ydoc",
            time,
        )?;
        Ok(Json(issuer.tokens.document(
            &r.relay,
            &r.folder,
            &r.doc_id,
            &s.principal,
            access == Access::Write && issuer.writes.writable(),
            time,
        )?))
    })
    .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FileRequest {
    relay: String,
    folder: String,
    doc_id: String,
    hash: String,
    content_type: String,
    content_length: u64,
    device: Option<String>,
}
async fn file_token(
    State(c): State<Arc<Control>>,
    headers: HeaderMap,
    Json(r): Json<FileRequest>,
) -> ApiResult<Json<Value>> {
    let s = c.session(&headers)?;
    let issuer = c.clone();
    c.transaction(move |tx, owners| {
        let time = now();
        let _ = r.device;
        ensure!(
            r.content_length <= issuer.config.max_attachment_bytes,
            "file too large"
        );
        if !issuer.writes.writable() {
            if !tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM resources WHERE relay=?1 AND guid=?2)",
                params![r.relay, r.doc_id],
                |r| r.get::<_, bool>(0),
            )? {
                return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "server_read_only").into());
            }
        }
        let access = metadata::authorize_resource(
            tx,
            owners,
            &s.principal,
            &r.relay,
            &r.folder,
            &r.doc_id,
            "file",
            time,
        )?;
        Ok(Json(issuer.tokens.file(
            &r.relay,
            &r.folder,
            &r.doc_id,
            &r.hash,
            &r.content_type,
            r.content_length,
            &s.principal,
            access == Access::Write && issuer.writes.writable(),
            time,
        )?))
    })
    .await
}
