-- Client tokens (DESIGN.md section 3.3). Times are unix milliseconds, UTC.
CREATE TABLE tokens (
    id           TEXT    PRIMARY KEY,
    name         TEXT    NOT NULL,
    secret_hash  BLOB    NOT NULL,
    last4        TEXT    NOT NULL,
    scopes       TEXT    NOT NULL,
    max_tunnels  INTEGER NOT NULL DEFAULT 0,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NULL,
    revoked_at   INTEGER NULL,
    last_used_at INTEGER NULL
);

-- A name is held only by an active token; after revoke it can be reused.
CREATE UNIQUE INDEX tokens_active_name ON tokens (name) WHERE revoked_at IS NULL;
