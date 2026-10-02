-- When a claim was last used: set by every registration of its tunnel. Claims that nobody has used for the configured
-- label claim TTL are deleted lazily (ExpireLabelClaims); NULL (rows from before this migration) counts as claimed_at.
-- unix milliseconds, UTC.
ALTER TABLE label_claims ADD COLUMN last_used_at INTEGER NULL;
