-- Hostname labels and SSH gateway addresses that belong for good to the first (client, tunnel) pair that registered
-- them. A label is "<tunnel>-<client>" (the SSH tunnel named "ssh" also claims the bare client name) and both parts
-- may contain hyphens, so different pairs can compose the same string; without a permanent claim the second could
-- take the name once the first one had been offline longer than the grace period. Rows are deleted when the client's
-- token is revoked and by `portholed admin release-label`. claimed_at is unix milliseconds, UTC.
CREATE TABLE label_claims (
    label      TEXT    NOT NULL PRIMARY KEY,
    client     TEXT    NOT NULL,
    tunnel     TEXT    NOT NULL,
    claimed_at INTEGER NOT NULL
);
CREATE INDEX label_claims_client ON label_claims (client);
