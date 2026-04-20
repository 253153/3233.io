-- Speeds up the periodic purge sweep, which scans by expires_at.
CREATE INDEX IF NOT EXISTS idx_messages_expires_at ON messages(expires_at);
