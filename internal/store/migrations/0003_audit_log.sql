-- Append-only journal of mutating admin actions (ADR 0005). `at` is unix milliseconds, UTC. `actor` is a token id or
-- "socket" (the local admin socket). `args` is a JSON object without secrets; `result` is "ok", "denied" or
-- "error: <code>".
CREATE TABLE audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    at     INTEGER NOT NULL,
    actor  TEXT    NOT NULL,
    action TEXT    NOT NULL,
    target TEXT    NOT NULL DEFAULT '',
    args   TEXT    NOT NULL DEFAULT '',
    result TEXT    NOT NULL DEFAULT ''
);
