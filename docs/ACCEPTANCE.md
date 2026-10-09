# Runtime acceptance checklist

Automated tests do not establish desktop/mobile or live object-store support.
Run these checks with disposable vaults and a dedicated store before release.
Keep independent backups; never use a production namespace for testing.

## Obsidian desktop, iOS, and Android

- Configure the same canonical HTTPS URL (including a non-root base path).
  Confirm key generation works, survives restart, and stores no private seed or
  bearer in plugin JSON, logs, invitations, or URLs. Check actual mobile CORS
  origins; configure explicit origins, never wildcard or `null`.
- Connect an Owner and a new invited User. Exercise read-only invitations,
  private folders, direct-folder-only access, finite invitation uses, revocation,
  and concurrent role/name edits. A 403 must not start an authentication loop.
- Stage a replacement key; confirm the old identity remains active until access
  is established. Test activation, rollback, local erasure, and operator recovery.
  Verify blanked secrets in Obsidian's settings, including after app restart.
- Switch server profiles and reload. Check that settings, IndexedDB, transfer
  caches, and identity are isolated while the vault's ordinary files remain.
- Sync notes, canvases, nested/empty folders, and binary attachments between two
  installations. Disconnect one, edit/delete on both, then reconnect and inspect
  convergence. Ordinary deletion must not cause server-side object collection.
- Move nested folders within a share, across shares, and out of/into a share.
  Within-share IDs stay stable; cross-share destinations get fresh IDs. Verify
  every descendant, pending upload, and any extra child rename events. Repeat
  with an offline peer and read-only source/destination permissions. The public
  method-boundary regression does not model the full vault/HSM event ordering.
- Restart the server during sync and an attachment transfer. Check automatic
  session/grant renewal and preserved content. Interrupt connectivity during
  invitation creation/acceptance and during metadata mutation; refresh canonical
  state before retrying overwrite operations.

## Deployment and storage

- Build/run the container as UID 10001 with persistent `/data` and read-only
  configuration. Verify TLS proxy WebSocket upgrades, base-path routing, private
  metrics, and redacted bearer/query logs. Verify that removed generic creation/auth and physical-delete routes remain
  inaccessible; `serve --legacy` is no longer accepted.
- Exercise both filesystem storage and the intended S3-compatible provider.
  Check large/slow PUT and GET operations across capability expiry and server
  restart, signed size/type enforcement, and actual presigned URL lifetimes.
  Provider URL validity and transfer completion are different deadlines.
- Trigger the free-space reserve using a small disposable filesystem (never
  fill the host disk). Existing sockets should close, fresh grants become
  read-only, uploads stop, and downloads/administration remain available. Restore
  space and verify writes resume. Monitor S3 capacity separately.
- Tombstone a shared folder and a relay, run GC before/after the recorded grace,
  repeat GC after a deliberately late upload, and inject a backend outage. Check
  live/unclassified objects survive, failed namespaces are reported, and retry
  clears them. Test more than one S3 listing page and versioned buckets; version
  retention and multipart cleanup require separate operator lifecycle policies.
- Stop the server and collector, take paired SQLite/store backups, and restore
  into an isolated deployment. Check ownership, tombstones, and retention grace
  before enabling GC. Never infer safe collection from object age alone.
