"""
database.py - Server-side SQLite database management for SecureChat.

Handles schema creation, user management, friend requests, message queue,
prekey bundles, and session tokens.

The server stores ONLY ciphertext and public keys -- never plaintext
messages or private keys. This enforces the E2EE guarantee under the
honest-but-curious (HbC) server threat model.
"""

import sqlite3
import os
import time
import uuid
from contextlib import contextmanager
from typing import Optional, List, Dict, Any

DATABASE_PATH = os.path.join(os.path.dirname(__file__), "securechat.db")


def get_connection(db_path: str = None) -> sqlite3.Connection:
    """Create a new database connection with WAL mode for concurrency."""
    if db_path is None:
        db_path = DATABASE_PATH
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_db(db_path: str = None):
    """Context manager for database connections."""
    conn = get_connection(db_path)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_database(db_path: str = None):
    """
    Initialize the database schema.

    Tables:
      - users: user accounts with hashed passwords and OTP secrets
      - sessions: authentication tokens with expiry
      - identity_keys: Ed25519 identity public keys per user
      - prekey_bundles: X25519 signed prekeys and one-time prekeys for X3DH
      - friend_requests: pending/accepted/declined friend requests
      - friends: established friendships
      - blocked_users: block list
      - messages: offline ciphertext queue (store-and-forward)
      - delivery_receipts: message delivery status tracking
      - rate_limits: rate limiting for abuse control
    """
    with get_db(db_path) as conn:
        conn.executescript("""
            -- User accounts
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                otp_secret TEXT NOT NULL,
                created_at REAL NOT NULL DEFAULT (strftime('%s', 'now')),
                is_active INTEGER NOT NULL DEFAULT 1
            );

            -- Session tokens
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at REAL NOT NULL DEFAULT (strftime('%s', 'now')),
                expires_at REAL NOT NULL,
                is_valid INTEGER NOT NULL DEFAULT 1,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);

            -- Identity public keys (Ed25519)
            CREATE TABLE IF NOT EXISTS identity_keys (
                user_id INTEGER PRIMARY KEY,
                identity_key_pub TEXT NOT NULL,
                x25519_identity_pub TEXT NOT NULL,
                updated_at REAL NOT NULL DEFAULT (strftime('%s', 'now')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            -- Prekey bundles for X3DH
            CREATE TABLE IF NOT EXISTS signed_prekeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                prekey_pub TEXT NOT NULL,
                signature TEXT NOT NULL,
                created_at REAL NOT NULL DEFAULT (strftime('%s', 'now')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS one_time_prekeys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                prekey_id INTEGER NOT NULL,
                prekey_pub TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE INDEX IF NOT EXISTS idx_otpk_user ON one_time_prekeys(user_id, used);

            -- Friend requests
            CREATE TABLE IF NOT EXISTS friend_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at REAL NOT NULL DEFAULT (strftime('%s', 'now')),
                updated_at REAL NOT NULL DEFAULT (strftime('%s', 'now')),
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id),
                UNIQUE(sender_id, receiver_id)
            );

            -- Established friendships (bidirectional)
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

            -- Offline message queue (ciphertext only)
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_uuid TEXT UNIQUE NOT NULL,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                ciphertext TEXT NOT NULL,
                ttl_seconds INTEGER DEFAULT NULL,
                created_at REAL NOT NULL DEFAULT (strftime('%s', 'now')),
                delivered INTEGER NOT NULL DEFAULT 0,
                delivered_at REAL DEFAULT NULL,
                expired INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            );
            CREATE INDEX IF NOT EXISTS idx_msg_receiver ON messages(receiver_id, delivered);
            CREATE INDEX IF NOT EXISTS idx_msg_uuid ON messages(message_uuid);

            -- Rate limiting
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp REAL NOT NULL DEFAULT (strftime('%s', 'now'))
            );
            CREATE INDEX IF NOT EXISTS idx_rate_limit ON rate_limits(identifier, action, timestamp);
        """)


def check_rate_limit(conn: sqlite3.Connection, identifier: str,
                     action: str, max_attempts: int, window_seconds: int) -> bool:
    """
    Check and enforce rate limiting.

    Returns True if the action is allowed, False if rate limit exceeded.
    Records the attempt if allowed.
    """
    cutoff = time.time() - window_seconds
    row = conn.execute(
        "SELECT COUNT(*) as cnt FROM rate_limits "
        "WHERE identifier = ? AND action = ? AND timestamp > ?",
        (identifier, action, cutoff),
    ).fetchone()

    if row["cnt"] >= max_attempts:
        return False

    conn.execute(
        "INSERT INTO rate_limits (identifier, action, timestamp) VALUES (?, ?, ?)",
        (identifier, action, time.time()),
    )
    # Cleanup old entries periodically
    conn.execute(
        "DELETE FROM rate_limits WHERE timestamp < ?",
        (time.time() - window_seconds * 2,),
    )
    return True


def cleanup_expired_messages(conn: sqlite3.Connection):
    """Delete expired self-destruct messages (best-effort server-side cleanup)."""
    now = time.time()
    conn.execute(
        "UPDATE messages SET expired = 1 "
        "WHERE ttl_seconds IS NOT NULL AND expired = 0 "
        "AND (created_at + ttl_seconds) < ?",
        (now,),
    )
    conn.execute(
        "DELETE FROM messages WHERE expired = 1",
    )
