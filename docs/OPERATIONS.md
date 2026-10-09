# Operating Freelay

This implementation is under development. Desktop/mobile Obsidian and live S3
deployment acceptance tests remain outstanding. Back up real data independently.

## Setup

Use one server process, a dedicated persistent object store, and a persistent
SQLite metadata database. Multiple instances cannot share one database. Never
share the object-store namespace with another server or deployment.

Copy `freelay.example.toml`. Create the database's parent directory, restrict
configuration and data access to the service account, and configure `[server]`,
`[store]`, and the required `[control]` section:

- `[server].url`: the exact externally reachable HTTPS URL, including any
  base path. HTTP is allowed only on literal loopback addresses for development.
  Do not derive it from Host or forwarded headers. The proxy must preserve the
  configured path prefix and support WebSockets.
- `[control].database`: persistent local SQLite path. Paths are relative to the working
  directory, not the config file. Keep its WAL/SHM alongside it.
- `[control].owners`: canonical, unpadded base64url Ed25519 public keys from the plugin.
  These keys may create relays; they are not global administrators. Each relay
  has its own ownership assignments. Config changes require a server restart.
- `[control].allowed_origins`: exact trusted browser origins if needed for mobile.
  Desktop control requests use native HTTP. Never use wildcard or `null` CORS.
- `[control].token_ttl_seconds`: data capabilities, 60–3600 seconds, default 900.
  S3 transfer URLs use `[store].presigned_url_expiration`, independently
  configurable in the same range with the same default for every S3-compatible
  backend. Filesystem transfers use the data capability directly. GC derives
  its safety deadline from these actual settings; there is no duplicate URL TTL
  in `[control]`. S3 URLs can outlive their parent capability.
- `read_only`, `minimum_free_bytes`, `max_attachment_bytes`: emergency write
  guard, local free-space reserve (default 1 GiB), and per-attachment maximum
  (default/hard ceiling 250 MiB). These are failure guards, not user quotas.

`[[auth]]` and webhook configuration are rejected. Freelay always uses the
integrated control plane and has no legacy server mode. No token
signing secret is persisted: restart invalidates sessions and data capabilities.
Object-store presigned URLs remain valid until their own expiry.

Core `FREELAY_SERVER_*` environment overrides are supported; old `RELAY_SERVER_*`
aliases are not. Configure control-plane options in the required TOML `[control]`
section. The old `--legacy`, `--auth`, `gen-auth`, `sign`, and `verify` interfaces
are removed; the server creates its own token key in memory.

The container has no embedded VPN or vendor configuration. Build from `crates/`
and mount your configuration at `/config/freelay.toml`, with persistent writable
storage at `/data` for UID 10001. Set `[server].host = "0.0.0.0"` inside the
container; publish it only to your trusted TLS proxy. Use absolute database/store
paths under `/data` there. The supplied compose file binds port 8080 to loopback.

For a disposable image smoke test, run `bash tests/container-smoke.sh IMAGE` from
the repository after building. It uses no network or host data directory: only
the test configuration is mounted read-only, and data lives on temporary memory
filesystems. The test verifies UID 10001, startup/readiness, local administration,
and a GC dry run with a read-only container root filesystem.

For initial setup the plugin can generate and display its public key without
the server being available. Add that public key to `owners`, start the server,
and connect. There is no first-client bootstrap or network administrator role.
New Users authenticate their own key and accept an Owner-created invitation.
Only Owners create invitations, with finite uses and at most 24-hour lifetime.

Terminate TLS at a trusted reverse proxy. Limit request rates/connections there,
redact Authorization headers and URL queries from logs, and restrict any metrics
listener to the operator. Application authentication has bounded challenge and
session caches but is not a complete network denial-of-service defense.

## Local administration

Use `freelay control --config freelay.toml`:

```sh
freelay control --config freelay.toml list
freelay control --config freelay.toml usage
freelay control --config freelay.toml add-owner RELAY_UUID NEW_PUBLIC_KEY
freelay control --config freelay.toml remove-owner RELAY_UUID OLD_PRINCIPAL_ID
freelay control --config freelay.toml revoke-principal PRINCIPAL_ID
freelay control --config freelay.toml suspend RELAY_UUID
freelay control --config freelay.toml resume RELAY_UUID
freelay control --config freelay.toml delete RELAY_UUID --yes
freelay control --config freelay.toml gc --dry-run
freelay control --config freelay.toml gc
```

Output is JSON. Local commands are authorized by filesystem access, not a
special client key. They may repair otherwise ownerless relays. `list` includes
folder deletion deadlines, collection results, and Owner principal IDs. `usage`
reports current object bytes, including unclassified namespaces; it excludes
object-store versions, backups, SQLite, and temporary files.

For a lost Owner key: generate a new installation key, add its public key to
configuration, restart, run `add-owner` for each affected relay, verify access,
then remove/revoke the old principal and remove its configured key. A new User
instead receives a new invitation. Revocation blocks new grants immediately;
already issued capabilities and transfer URLs age out normally. Emergency
restart invalidates process-signed grants but not existing object-store URLs.

For planned replacement, use the plugin's key-recovery panel to stage a new key
without changing the active one. Establish its memberships (or have the operator
assign its configured Owner key), check access, then explicitly activate it.
Owner activation checks that the replacement can still own every currently
owned relay. Users must verify all desired memberships; an invitation to one
folder is not evidence of access to other folders. The previous identity stays
in Secret Storage for rollback. Revoke it on the server after confirming the new
identity works; rollback cannot undo server-side revocation.

Local key erasure logs out and blanks this server profile's active, staged, and
previous secrets. It does not revoke server memberships or erase local vault
content. Obsidian's public API has no secret-entry deletion method; remove empty
entries through Obsidian's settings if desired. There is no export/import UI.

## Deletion and collection

Ordinary note, attachment, and nested-folder deletion stays in the existing
CRDT. It does not trigger physical object deletion. Offline clients can still
merge old state while the shared folder remains active.

Deleting an entire shared folder or relay is an Owner-only administrative
operation. It permanently tombstones the namespace and stops new grants. IDs
cannot be reused. Local vault copies are not remotely erased.

The collector only visits explicitly tombstoned namespaces after their safety
deadline. The grace is the largest ever configured sum of data-token lifetime,
presigned-URL lifetime, and 360 seconds of skew/transfer allowance. Lowering TTLs
or restarting cannot shorten that historical grace. Repeated collection is
required: a request authorized before expiry can finish late and recreate an
object after an earlier sweep. Empty results are observations, not a guarantee
that a late writer can never appear.

Run `gc --dry-run`, inspect the result, then schedule `gc` under the same service
account/configuration/working directory, for example hourly. A renewable SQLite
lease prevents simultaneous collectors. Operations are idempotent; failures
exit nonzero and persist coarse per-namespace status without backend secrets.
Unknown objects are reported, never automatically deleted as presumed orphans.
Metadata tombstones and resource bindings are retained permanently.

S3 version history, retention locks, multipart remnants, and backups require
operator lifecycle policies. Collection is not guaranteed secure erasure.

## Failure and recovery

Low local free space closes current document sockets on entering read-only
mode; replacement grants are read-only and new resource claims/uploads stop.
Metadata administration, downloads, and deletion remain available while the
database can still commit. Already-issued object-store PUT URLs are not revoked.
The guard monitors metadata, temporary files, and filesystem object storage;
remote store capacity and account limits require external monitoring.

Use paired metadata/object-store backups. For a simple consistent backup, stop
the server and collector, then copy the database and store together. Do not copy
only the main SQLite file while WAL writes are active. Restore to an isolated
deployment, preserve tombstones and retention-policy history, and inspect usage
before resuming collection. Never restore an old object store alongside newer
unrelated metadata and assume collection will infer the intended ownership.

Network APIs cannot enumerate another Owner's private relays or inspect global
disk use. Owners are trusted to manage their own relays responsibly; the local
administrator monitors overall usage and can suspend/delete abusive relays.
