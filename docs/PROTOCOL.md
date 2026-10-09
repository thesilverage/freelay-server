# Freelay v1 protocol and security boundary

Machine-readable control routes: [OpenAPI](../openapi-freelay.json). The older
`openapi.yaml` retains the upstream data-plane reference; the Freelay route
allowlist below is authoritative. There is only one server mode.

The public base URL from `[server].url` is canonicalized with URL parsing, HTTPS (except literal
loopback HTTP), no userinfo/query/fragment, and exactly one trailing slash.
Both plugin and server bind identity proofs to this URL, including its path.
All byte strings below use canonical unpadded base64url in JSON. Times are Unix
seconds; data-plane JSON `expiryTime` retains upstream milliseconds.

## Authentication

`POST api/v1/auth/challenges` accepts `{version:1, publicKey}`. The response has
`version`, `id` (16 random bytes), `nonce` (32 random bytes), `audience`,
`publicKey` (32 bytes), `issuedAt`, and `expiresAt` (60 seconds later).

Sign the following exact concatenation with Ed25519:

```text
UTF8("freelay-auth-v1\0")
u32be(len(UTF8(audience))) || UTF8(audience)
u32be(len(UTF8("session"))) || UTF8("session")
raw(id) || raw(nonce) || raw(publicKey)
u64be(issuedAt) || u64be(expiresAt)
```

`POST api/v1/auth/sessions` accepts `{id, publicKey, signature}`. An optional
Authorization Bearer header names the previous session being replaced. The
challenge is consumed before verification, including on failure. Weak keys and
noncanonical encodings are rejected. Strict signature verification succeeds
only before expiry and after issuance. The returned opaque bearer is 32 random
bytes, stored only as a hash in server memory; lifetime is 15 minutes. Successful
replacement invalidates the old bearer. `DELETE api/v1/auth/session` logs out.

Principal IDs are `base64url(SHA256(UTF8("freelay-principal-v1\0") || raw(publicKey)))`.
Authentication proves key possession, not membership. Unknown keys may inspect
their own identity and accept an invitation; configured Owners register on login.
There is no server signing private key, client administrator bootstrap, password,
OAuth dependency, or public registration endpoint.

Frozen public test vectors are in `crates/relay/tests/auth-v1.json` and the plugin
test suite. Those seeds are test fixtures, never deployment identities.

## Metadata routes

All routes below require a session bearer. Reads are consolidated into one
caller-filtered `GET api/v1/state` snapshot with an opaque ETag/304 response;
there are no redundant collection GET endpoints. Responses do not reveal a
global revision or hidden relay/folder activity.

| Route relative to the public base | Methods | Purpose |
| --- | --- | --- |
| `api/v1/me` | GET, PATCH | Own identity/display name |
| `api/v1/state` | GET | Visible profiles, relays, folders, grants, invitations |
| `api/v1/relays` | POST | Configured Owner creates a relay |
| `api/v1/relays/{relay}` | PATCH, DELETE | Owner renames/tombstones relay |
| `api/v1/relays/{relay}/folders` | POST | Owner registers folder root |
| `api/v1/relays/{relay}/folders/{folder}` | PATCH, DELETE | Owner edits/tombstones folder |
| `api/v1/relays/{relay}/owners/{principal}` | POST, DELETE | Owner assigns/removes eligible co-owner |
| `api/v1/relays/{relay}/members/{principal}` | POST, DELETE | Membership; self-leave allowed |
| `api/v1/relays/{relay}/folders/{folder}/members/{principal}` | POST, DELETE | Direct/private access; self-leave allowed |
| `api/v1/relays/{relay}/invitations` | POST | Owner creates finite invitation |
| `api/v1/relays/{relay}/invitations/{invitation}` | DELETE | Owner revokes future acceptance |
| `api/v1/invitations/accept` | POST | Accept code, register principal if needed |
| `token`, `file-token` | POST | Authorize/register resource and issue scoped grant |

Owner status is relay-scoped and requires both a configured public key and a
relay ownership row. Network mutations cannot remove the last effective Owner.
Public folders inherit relay membership. Private folders require a direct grant,
capped by relay membership when present. Direct-folder Users see only that
folder and its minimal containing relay record. Owners can access every folder
in relays they own. Suspended/deleted resources cannot issue new grants.

Overwrite operations (relay/folder PATCH and member POST) require `If-Match`
containing the quoted containing-relay revision from the Owner snapshot. Missing
preconditions return 428; stale state returns 412. Additive/deletion operations
are transactional and do not require a revision. Refresh the snapshot after a
successful mutation. Mutations return an ID/resource or 204 as appropriate;
deletion includes `gcNotBefore`. Errors contain stable `code` strings; request
deserialization errors also retain Axum's HTTP validation status.

An invitation stores only a hash of its 32-byte secret, relay/optional-folder,
access (`read`/`write`), expiry, and finite use count. Defaults are one use and
24 hours; `maxUses` and `ttlSeconds` can override them within those constraints.
The code is returned once, sent out of band, and accepted only in a request body.
Acceptance is transactional and deduplicated per invitation/principal. Retrying
does not restore a subsequently removed/downgraded grant. Invitations cannot
grant Owner status or delegate invitation creation.

## Data grants and deletion

The server constructs `<relay UUID>-<resource UUID>` itself. An immutable
resource row binds that GUID to one shared folder and kind (`ydoc`/`file`).
Readers cannot register unknown resources. A folder root is also registered,
preventing root/child collisions. A cross-folder move must use a fresh GUID.

Data grants reuse upstream CWT tag 61 / COSE Mac0 tag 17, full HMAC-SHA-256 tag,
audience, expiry, user attribution, and exact resource scope. The HMAC secret
and key ID are random per process. The issuer string `relay-server` remains a
wire compatibility identifier. File scope additionally binds content length
and type. The reused decoder also understands the upstream short scope; the
Freelay issuer always includes the file metadata.

Freelay exposes the narrow document sync/fetch and file transfer
routes. Generic `/doc/*` minting/creation, document replacement, webhook routes,
store inspection, and client physical file deletion are not mounted. File
capabilities cannot authorize document routes. WebSockets close at expiry.
Object-store presigned URLs use `[store].presigned_url_expiration` as their
lifetime and receive no session
bearer. They are not bounded by the remaining parent token lifetime.

Ordinary CRDT deletion is not physical deletion. Shared-folder/relay tombstones
are irreversible, permanently reserve IDs, and drive repeated operator GC.
See [operations](OPERATIONS.md) for retention windows and late-write behavior.

## Threat model and limits

- Network observers cannot read proofs/session capabilities under HTTPS. TLS
  endpoint identity is essential; challenge signatures alone do not prevent an
  active proxy. Redirects are rejected for control requests, and returned scoped
  data URLs are pinned to the configured server/base path.
- Captured proofs cannot be reused or substituted across origins, keys, or
  challenges. A stolen bearer still works within its scope until expiry;
  revocation is deliberately bounded, not instantaneous on existing data grants.
- Only allowlisted, relay-assigned Owners administer storage namespaces. A User
  cannot invite arbitrarily distant strangers or create unowned relay storage.
  A malicious writer can still fill an authorized folder; Owners and the local
  operator are responsible for usage, not a quota subsystem.
- Private keys are stored through Obsidian Secret Storage and never in plugin
  settings. That is not isolation from malicious plugins, malware, or a
  compromised Obsidian process. Mobile persistence/crypto behavior requires
  empirical validation. There is no plaintext fallback or export/import UI.
- Content is not end-to-end encrypted against the server administrator. The
  administrator controls configuration, SQLite, object storage, and backups.
- Log redaction, reverse-proxy rate limits, reliable clocks, filesystem access
  controls, and object-store lifecycle policies are operator responsibilities.
  A backwards/forwards clock adjustment can affect expiration and retention;
  do not run collection with an untrustworthy clock.
- S3 in-flight requests, non-current versions, and backups prevent a claim of
  immediate or cryptographically guaranteed erasure. Tombstones are retained
  and collection repeats rather than assuming one sweep is final.
