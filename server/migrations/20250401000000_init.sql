CREATE TABLE IF NOT EXISTS users (
    fingerprint TEXT PRIMARY KEY,
    pubkey BLOB NOT NULL,
    created_at TEXT NOT NULL,
    last_seen TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_fingerprint TEXT NOT NULL,
    sender_fingerprint TEXT,
    ciphertext BLOB NOT NULL,
    nonce BLOB NOT NULL,
    sender_pubkey BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_fingerprint, id);
