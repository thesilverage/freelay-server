PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS principals (
    id TEXT PRIMARY KEY, public_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
    revision INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS relays (
    id TEXT PRIMARY KEY, name TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active' CHECK(state IN ('active','suspended','deleted')),
    revision INTEGER NOT NULL DEFAULT 1,
    deleted_at INTEGER, gc_not_before INTEGER, last_gc_at INTEGER, gc_empty_at INTEGER, last_gc_error TEXT
);
CREATE TABLE IF NOT EXISTS relay_owners (
    relay TEXT NOT NULL REFERENCES relays(id), principal TEXT NOT NULL REFERENCES principals(id),
    PRIMARY KEY(relay, principal)
);
CREATE TABLE IF NOT EXISTS relay_members (
    relay TEXT NOT NULL REFERENCES relays(id), principal TEXT NOT NULL REFERENCES principals(id),
    access TEXT NOT NULL CHECK(access IN ('read','write')),
    PRIMARY KEY(relay, principal)
);
CREATE TABLE IF NOT EXISTS folders (
    id TEXT PRIMARY KEY, relay TEXT NOT NULL REFERENCES relays(id), name TEXT NOT NULL,
    private INTEGER NOT NULL DEFAULT 0, creator TEXT NOT NULL REFERENCES principals(id),
    revision INTEGER NOT NULL DEFAULT 1,
    deleted_at INTEGER, gc_not_before INTEGER, last_gc_at INTEGER, gc_empty_at INTEGER, last_gc_error TEXT,
    UNIQUE(relay, id)
);
CREATE TABLE IF NOT EXISTS folder_members (
    folder TEXT NOT NULL REFERENCES folders(id), principal TEXT NOT NULL REFERENCES principals(id),
    access TEXT NOT NULL CHECK(access IN ('read','write')),
    PRIMARY KEY(folder, principal)
);
CREATE TABLE IF NOT EXISTS resources (
    relay TEXT NOT NULL, guid TEXT NOT NULL, folder TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('ydoc','file')), first_seen_at INTEGER NOT NULL,
    PRIMARY KEY(relay, guid), FOREIGN KEY(relay, folder) REFERENCES folders(relay, id)
);
CREATE INDEX IF NOT EXISTS resources_folder ON resources(folder);
CREATE TABLE IF NOT EXISTS invitations (
    id TEXT PRIMARY KEY, relay TEXT NOT NULL REFERENCES relays(id),
    folder TEXT, verifier BLOB NOT NULL UNIQUE,
    access TEXT NOT NULL CHECK(access IN ('read','write')), expires_at INTEGER NOT NULL,
    max_uses INTEGER NOT NULL CHECK(max_uses > 0), uses INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1, creator TEXT NOT NULL REFERENCES principals(id),
    FOREIGN KEY(relay, folder) REFERENCES folders(relay, id)
);
CREATE TABLE IF NOT EXISTS invitation_acceptances (
    invitation TEXT NOT NULL REFERENCES invitations(id), principal TEXT NOT NULL REFERENCES principals(id),
    PRIMARY KEY(invitation, principal)
);
CREATE TABLE IF NOT EXISTS maintenance_leases (name TEXT PRIMARY KEY, holder TEXT NOT NULL, expires_at INTEGER NOT NULL);
-- Never reduce the safety window when configuration changes across restarts:
-- previously issued object-store URLs survive the process that issued them.
CREATE TABLE IF NOT EXISTS retention_policy (id INTEGER PRIMARY KEY CHECK(id=1), grace_seconds INTEGER NOT NULL);
INSERT OR IGNORE INTO schema_migrations VALUES (1);
