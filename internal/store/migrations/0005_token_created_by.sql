-- Who created a token: the id of the admin token that made the join link it was redeemed from, or "socket" for the
-- local admin socket. Empty for tokens made by `portholed token create` and for tokens that existed before this
-- migration. Revoking a token revokes its unused join codes, and optionally the tokens minted from its links.
ALTER TABLE tokens ADD COLUMN created_by TEXT NOT NULL DEFAULT '';
CREATE INDEX tokens_created_by ON tokens (created_by) WHERE created_by <> '';
CREATE INDEX join_codes_created_by ON join_codes (created_by);
