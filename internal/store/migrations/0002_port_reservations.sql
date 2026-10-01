-- Public TCP ports remembered per (client, tunnel) so that a client gets the same port back after a server restart
-- (ADR 0003). Times are unix milliseconds, UTC. released_at is NULL while the tunnel is live; once it is closed (or the
-- server restarted) the row keeps the port reserved for a TTL counted from released_at.
CREATE TABLE port_reservations (
    client      TEXT    NOT NULL,
    tunnel      TEXT    NOT NULL,
    port        INTEGER NOT NULL UNIQUE,
    released_at INTEGER NULL,
    PRIMARY KEY (client, tunnel)
);
