-- SecureChat Database Schema
-- Import this file to initialize the SQLite database.
-- Usage: sqlite3 securechat.db < schema.sql

-- User accounts
-- Passwords are hashed with Argon2id (per-user random salt).
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,           -- Argon2id hash (includes embedded salt)
    otp_secret TEXT NOT NULL,              -- TOTP secret for two-factor authentication
    created_at REAL NOT NULL DEFAULT (strftime('%s', 'now')),
    is_active INTEGER NOT NULL DEFAULT 1   -- Account active flag
);

-- Session tokens for authenticated sessions
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,             -- Random 256-bit token
    created_at REAL NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at REAL NOT NULL,               -- Token expiry timestamp
    is_valid INTEGER NOT NULL DEFAULT 1,    -- 0 = revoked/logged out
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);

-- Identity public keys (Ed25519 for signatures, X25519 for DH)
-- The server stores ONLY public keys, never private keys.
CREATE TABLE IF NOT EXISTS identity_keys (
    user_id INTEGER PRIMARY KEY,
    identity_key_pub TEXT NOT NULL,         -- Ed25519 public key (hex)
    x25519_identity_pub TEXT NOT NULL,      -- X25519 public key for DH (hex)
    updated_at REAL NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Signed prekeys for X3DH key exchange
CREATE TABLE IF NOT EXISTS signed_prekeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    prekey_pub TEXT NOT NULL,               -- X25519 public key (hex)
    signature TEXT NOT NULL,                -- Ed25519 signature of the prekey (hex)
    created_at REAL NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- One-time prekeys for X3DH (consumed after use)
CREATE TABLE IF NOT EXISTS one_time_prekeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    prekey_id INTEGER NOT NULL,             -- Client-assigned prekey index
    prekey_pub TEXT NOT NULL,               -- X25519 public key (hex)
    used INTEGER NOT NULL DEFAULT 0,        -- 1 = consumed
    FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_otpk_user ON one_time_prekeys(user_id, used);

-- Friend requests with lifecycle management
CREATE TABLE IF NOT EXISTS friend_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',  -- pending, accepted, declined, cancelled
    created_at REAL NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at REAL NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id),
    UNIQUE(sender_id, receiver_id)
);

-- Established friendships (bidirectional entries)
CREATE TABLE IF NOT EXISTS friends (
    user_id INTEGER NOT NULL,
    friend_id INTEGER NOT NULL,
    created_at REAL NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (user_id, friend_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (friend_id) REFERENCES users(id)
);

-- Block list
CREATE TABLE IF NOT EXISTS blocked_users (
    user_id INTEGER NOT NULL,
    blocked_id INTEGER NOT NULL,
    created_at REAL NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (user_id, blocked_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (blocked_id) REFERENCES users(id)
);

-- Offline message queue (ciphertext store-and-forward)
-- The server stores ONLY ciphertext; it cannot decrypt messages.
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_uuid TEXT UNIQUE NOT NULL,      -- UUID for deduplication
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    ciphertext TEXT NOT NULL,               -- Encrypted message payload (hex/JSON)
    ttl_seconds INTEGER DEFAULT NULL,       -- Self-destruct timer (NULL = no expiry)
    created_at REAL NOT NULL DEFAULT (strftime('%s', 'now')),
    delivered INTEGER NOT NULL DEFAULT 0,   -- 0 = queued, 1 = delivered
    delivered_at REAL DEFAULT NULL,
    expired INTEGER NOT NULL DEFAULT 0,     -- 1 = TTL expired, pending deletion
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_msg_receiver ON messages(receiver_id, delivered);
CREATE INDEX IF NOT EXISTS idx_msg_uuid ON messages(message_uuid);

-- Rate limiting for abuse prevention
CREATE TABLE IF NOT EXISTS rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL,               -- IP address or user ID
    action TEXT NOT NULL,                   -- Action type (register, login, friend_request)
    timestamp REAL NOT NULL DEFAULT (strftime('%s', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_rate_limit ON rate_limits(identifier, action, timestamp);
