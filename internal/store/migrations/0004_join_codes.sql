-- One-time join codes (ADR 0005, "Least privilege and secrets"). Times are unix milliseconds, UTC. Only a hash of the
-- code secret is stored. A code is redeemed once: used_at is set in the same transaction that creates the token.
-- token_expires_at is the absolute expiry given to the token the code produces (NULL = never).
CREATE TABLE join_codes (
    id               TEXT    PRIMARY KEY,
    code_hash        BLOB    NOT NULL,
    client_name      TEXT    NOT NULL,
    scopes           TEXT    NOT NULL,
    max_tunnels      INTEGER NOT NULL DEFAULT 0,
    token_expires_at INTEGER NULL,
    remote_control   INTEGER NOT NULL DEFAULT 0,
    created_at       INTEGER NOT NULL,
    expires_at       INTEGER NOT NULL,
    used_at          INTEGER NULL,
    revoked_at       INTEGER NULL,
    created_by       TEXT    NOT NULL DEFAULT ''
);

-- Whether the machine behind a token accepts tunnels opened remotely by an operator (ADR 0005). Tokens that existed
-- before this migration keep the behaviour they had: the client's own allow_remote list decides.
ALTER TABLE tokens ADD COLUMN remote_control INTEGER NOT NULL DEFAULT 1;
