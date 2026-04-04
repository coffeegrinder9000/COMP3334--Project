"""
server.py - SecureChat Server Application.

A Flask + Socket.IO server that handles:
  - User registration with Argon2id password hashing and TOTP setup
  - Login with password + OTP (two-factor authentication)
  - Session management with token expiry
  - Identity key and prekey bundle distribution (X3DH)
  - Friend request workflow (send/accept/decline/cancel/block)
  - Offline ciphertext message queuing (store-and-forward)
  - Real-time message relay via WebSocket
  - Message delivery status (Sent / Delivered)
  - Self-destruct message TTL enforcement (best-effort)
  - Rate limiting for registration, login, and friend requests
  - Conversation list and unread counters
  - TLS transport security

The server NEVER sees plaintext messages or private keys.
It operates under the honest-but-curious (HbC) threat model.
"""

import os
import sys
import time
import uuid
import json
import logging

from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
import argon2
import pyotp

# Add parent directory to path for common module imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from server.database import (
    get_db,
    init_database,
    check_rate_limit,
    cleanup_expired_messages,
    DATABASE_PATH,
)

# ============================================================
# Configuration
# ============================================================
HOST = "0.0.0.0"
PORT = 5050
SESSION_EXPIRY_SECONDS = 3600 * 24  # 24 hours
MAX_MESSAGE_SIZE = 65536  # 64 KB max ciphertext size
CERT_DIR = os.path.join(os.path.dirname(__file__), "..", "certs")
CERT_FILE = os.path.join(CERT_DIR, "server.crt")
KEY_FILE = os.path.join(CERT_DIR, "server.key")

# Rate limit settings
RATE_LIMIT_REGISTER = (5, 3600)       # 5 attempts per hour
RATE_LIMIT_LOGIN = (10, 300)          # 10 attempts per 5 minutes
RATE_LIMIT_FRIEND_REQUEST = (20, 60)  # 20 requests per minute

# ============================================================
# Logging Configuration
# ============================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("SecureChatServer")

# Disable verbose debug logs to prevent sensitive data leakage
logging.getLogger("werkzeug").setLevel(logging.WARNING)

# ============================================================
# App Initialization
# ============================================================
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(32).hex()
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    max_http_buffer_size=MAX_MESSAGE_SIZE * 2,
    logger=False,
    engineio_logger=False,
)

# Password hasher using Argon2id
password_hasher = argon2.PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=argon2.Type.ID,
)

# Track online users: user_id -> set of socket ids
online_users: dict = {}
# Track socket -> user mapping
socket_user_map: dict = {}


# ============================================================
# Helper Functions
# ============================================================

def authenticate_request() -> dict:
    """
    Authenticate an HTTP request using the session token in the
    Authorization header.

    Returns user dict or raises an error response.
    """
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        return None

    with get_db() as conn:
        row = conn.execute(
            "SELECT s.user_id, s.expires_at, u.username "
            "FROM sessions s JOIN users u ON s.user_id = u.id "
            "WHERE s.token = ? AND s.is_valid = 1",
            (token,),
        ).fetchone()

    if not row:
        return None
    if row["expires_at"] < time.time():
        return None

    return {"user_id": row["user_id"], "username": row["username"]}


def authenticate_socket(token: str) -> dict:
    """Authenticate a WebSocket connection."""
    if not token:
        return None
    with get_db() as conn:
        row = conn.execute(
            "SELECT s.user_id, s.expires_at, u.username "
            "FROM sessions s JOIN users u ON s.user_id = u.id "
            "WHERE s.token = ? AND s.is_valid = 1",
            (token,),
        ).fetchone()
    if not row or row["expires_at"] < time.time():
        return None
    return {"user_id": row["user_id"], "username": row["username"]}


def get_user_id_by_username(username: str) -> int:
    """Lookup user ID by username. Returns None if not found."""
    with get_db() as conn:
        row = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
    return row["id"] if row else None


# ============================================================
# HTTP API Routes - Registration & Authentication
# ============================================================

@app.route("/api/register", methods=["POST"])
def register():
    """
    Register a new user account.

    Expects JSON: { "username": str, "password": str }
    Returns: { "otp_secret": str, "otp_uri": str }

    Password requirements: minimum 8 characters.
    Password is hashed with Argon2id (per-user random salt).
    A TOTP secret is generated and returned for 2FA setup.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request body"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    # Input validation
    if not username or len(username) < 3 or len(username) > 32:
        return jsonify({"error": "Username must be 3-32 characters"}), 400
    if not username.isalnum():
        return jsonify({"error": "Username must be alphanumeric"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    with get_db() as conn:
        # Rate limiting
        if not check_rate_limit(
            conn,
            request.remote_addr,
            "register",
            RATE_LIMIT_REGISTER[0],
            RATE_LIMIT_REGISTER[1],
        ):
            return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

        # Check if username is taken
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            return jsonify({"error": "Username already taken"}), 409

        # Hash password with Argon2id
        hashed = password_hasher.hash(password)

        # Generate TOTP secret
        otp_secret = pyotp.random_base32()
        otp_uri = pyotp.TOTP(otp_secret).provisioning_uri(
            name=username, issuer_name="SecureChat"
        )

        conn.execute(
            "INSERT INTO users (username, password_hash, otp_secret) VALUES (?, ?, ?)",
            (username, hashed, otp_secret),
        )

    logger.info("User registered: %s", username)
    return jsonify({
        "message": "Registration successful",
        "otp_secret": otp_secret,
        "otp_uri": otp_uri,
    }), 201


@app.route("/api/login", methods=["POST"])
def login():
    """
    Login with password + OTP (two-factor authentication).

    Expects JSON: { "username": str, "password": str, "otp_code": str }
    Returns: { "token": str, "expires_at": float }
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request body"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")
    otp_code = data.get("otp_code", "").strip()

    with get_db() as conn:
        # Rate limiting
        if not check_rate_limit(
            conn,
            f"{request.remote_addr}:{username}",
            "login",
            RATE_LIMIT_LOGIN[0],
            RATE_LIMIT_LOGIN[1],
        ):
            return jsonify({"error": "Too many login attempts. Try again later."}), 429

        user = conn.execute(
            "SELECT id, password_hash, otp_secret FROM users WHERE username = ? AND is_active = 1",
            (username,),
        ).fetchone()

        if not user:
            return jsonify({"error": "Invalid credentials"}), 401

        # Verify password (Argon2id)
        try:
            password_hasher.verify(user["password_hash"], password)
        except argon2.exceptions.VerifyMismatchError:
            return jsonify({"error": "Invalid credentials"}), 401

        # Check if password hash needs rehashing
        if password_hasher.check_needs_rehash(user["password_hash"]):
            new_hash = password_hasher.hash(password)
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, user["id"]),
            )

        # Verify OTP
        totp = pyotp.TOTP(user["otp_secret"])
        if not totp.verify(otp_code, valid_window=1):
            return jsonify({"error": "Invalid OTP code"}), 401

        # Create session token
        token = uuid.uuid4().hex + uuid.uuid4().hex
        expires_at = time.time() + SESSION_EXPIRY_SECONDS

        conn.execute(
            "INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)",
            (user["id"], token, expires_at),
        )

    logger.info("User logged in: %s", username)
    return jsonify({
        "message": "Login successful",
        "token": token,
        "expires_at": expires_at,
        "user_id": user["id"],
        "username": username,
    }), 200


@app.route("/api/logout", methods=["POST"])
def logout():
    """Logout: invalidate the current session token."""
    user = authenticate_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    with get_db() as conn:
        conn.execute(
            "UPDATE sessions SET is_valid = 0 WHERE token = ?", (token,)
        )

    logger.info("User logged out: %s", user["username"])
    return jsonify({"message": "Logged out successfully"}), 200


# ============================================================
# HTTP API Routes - Identity Keys & Prekey Bundles
# ============================================================

@app.route("/api/keys/upload", methods=["POST"])
def upload_keys():
    """
    Upload identity public key and prekey bundle for X3DH.

    Expects JSON: {
        "identity_key_pub": hex,
        "x25519_identity_pub": hex,
        "signed_prekey_pub": hex,
        "signed_prekey_sig": hex,
        "one_time_prekeys": [hex, ...] (optional)
    }
    """
    user = authenticate_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request body"}), 400

    identity_key_pub = data.get("identity_key_pub", "")
    x25519_identity_pub = data.get("x25519_identity_pub", "")
    signed_prekey_pub = data.get("signed_prekey_pub", "")
    signed_prekey_sig = data.get("signed_prekey_sig", "")
    one_time_prekeys = data.get("one_time_prekeys", [])

    # Validate key lengths (32 bytes = 64 hex chars)
    for key_hex in [identity_key_pub, x25519_identity_pub, signed_prekey_pub]:
        if len(key_hex) != 64:
            return jsonify({"error": "Invalid key length"}), 400

    with get_db() as conn:
        # Check for identity key change
        existing = conn.execute(
            "SELECT identity_key_pub FROM identity_keys WHERE user_id = ?",
            (user["user_id"],),
        ).fetchone()

        if existing and existing["identity_key_pub"] != identity_key_pub:
            logger.warning(
                "Identity key changed for user %s", user["username"]
            )

        # Upsert identity key
        conn.execute(
            "INSERT INTO identity_keys (user_id, identity_key_pub, x25519_identity_pub, updated_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(user_id) DO UPDATE SET "
            "identity_key_pub = excluded.identity_key_pub, "
            "x25519_identity_pub = excluded.x25519_identity_pub, "
            "updated_at = excluded.updated_at",
            (user["user_id"], identity_key_pub, x25519_identity_pub, time.time()),
        )

        # Replace signed prekey
        conn.execute(
            "DELETE FROM signed_prekeys WHERE user_id = ?", (user["user_id"],)
        )
        conn.execute(
            "INSERT INTO signed_prekeys (user_id, prekey_pub, signature) VALUES (?, ?, ?)",
            (user["user_id"], signed_prekey_pub, signed_prekey_sig),
        )

        # Add one-time prekeys (clear old unused ones first)
        conn.execute(
            "DELETE FROM one_time_prekeys WHERE user_id = ? AND used = 0",
            (user["user_id"],),
        )
        for idx, otpk in enumerate(one_time_prekeys):
            if len(otpk) != 64:
                continue
            conn.execute(
                "INSERT INTO one_time_prekeys (user_id, prekey_id, prekey_pub) VALUES (?, ?, ?)",
                (user["user_id"], idx, otpk),
            )

    return jsonify({"message": "Keys uploaded successfully"}), 200


@app.route("/api/keys/bundle/<username>", methods=["GET"])
def get_prekey_bundle(username):
    """
    Fetch a user's prekey bundle for X3DH session establishment.

    Returns: {
        "identity_key_pub": hex,
        "x25519_identity_pub": hex,
        "signed_prekey_pub": hex,
        "signed_prekey_sig": hex,
        "one_time_prekey_pub": hex or null,
        "one_time_prekey_id": int or null,
    }
    """
    user = authenticate_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    with get_db() as conn:
        target = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if not target:
            return jsonify({"error": "User not found"}), 404

        target_id = target["id"]

        identity = conn.execute(
            "SELECT identity_key_pub, x25519_identity_pub FROM identity_keys WHERE user_id = ?",
            (target_id,),
        ).fetchone()
        if not identity:
            return jsonify({"error": "User has no keys uploaded"}), 404

        signed_pk = conn.execute(
            "SELECT prekey_pub, signature FROM signed_prekeys WHERE user_id = ? ORDER BY id DESC LIMIT 1",
            (target_id,),
        ).fetchone()
        if not signed_pk:
            return jsonify({"error": "User has no signed prekey"}), 404

        # Claim one one-time prekey (consumed after use)
        otpk = conn.execute(
            "SELECT id, prekey_id, prekey_pub FROM one_time_prekeys "
            "WHERE user_id = ? AND used = 0 LIMIT 1",
            (target_id,),
        ).fetchone()

        otpk_pub = None
        otpk_id = None
        if otpk:
            otpk_pub = otpk["prekey_pub"]
            otpk_id = otpk["prekey_id"]
            conn.execute(
                "UPDATE one_time_prekeys SET used = 1 WHERE id = ?",
                (otpk["id"],),
            )

    return jsonify({
        "username": username,
        "identity_key_pub": identity["identity_key_pub"],
        "x25519_identity_pub": identity["x25519_identity_pub"],
        "signed_prekey_pub": signed_pk["prekey_pub"],
        "signed_prekey_sig": signed_pk["signature"],
        "one_time_prekey_pub": otpk_pub,
        "one_time_prekey_id": otpk_id,
    }), 200


@app.route("/api/keys/identity/<username>", methods=["GET"])
def get_identity_key(username):
    """Get a user's identity public key (for fingerprint verification)."""
    user = authenticate_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    with get_db() as conn:
        target = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if not target:
            return jsonify({"error": "User not found"}), 404

        identity = conn.execute(
            "SELECT identity_key_pub FROM identity_keys WHERE user_id = ?",
            (target["id"],),
        ).fetchone()
        if not identity:
            return jsonify({"error": "No identity key found"}), 404

    return jsonify({
        "username": username,
        "identity_key_pub": identity["identity_key_pub"],
    }), 200


# ============================================================
# HTTP API Routes - Friends / Contacts
# ============================================================

@app.route("/api/friends/request", methods=["POST"])
def send_friend_request():
    """
    Send a friend request to another user.
    Non-friends cannot send chat messages (anti-spam control R16).
    """
    user = authenticate_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    target_username = data.get("username", "").strip()

    if target_username == user["username"]:
        return jsonify({"error": "Cannot add yourself"}), 400

    with get_db() as conn:
        # Rate limiting
        if not check_rate_limit(
            conn,
            str(user["user_id"]),
            "friend_request",
            RATE_LIMIT_FRIEND_REQUEST[0],
            RATE_LIMIT_FRIEND_REQUEST[1],
        ):
            return jsonify({"error": "Too many friend requests. Slow down."}), 429

        target = conn.execute(
            "SELECT id FROM users WHERE username = ?", (target_username,)
        ).fetchone()
        if not target:
            return jsonify({"error": "User not found"}), 404

        target_id = target["id"]

        # Check if blocked
        blocked = conn.execute(
            "SELECT 1 FROM blocked_users WHERE user_id = ? AND blocked_id = ?",
            (target_id, user["user_id"]),
        ).fetchone()
        if blocked:
            return jsonify({"error": "Cannot send request to this user"}), 403

        # Check if already friends
        existing_friend = conn.execute(
            "SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ?",
            (user["user_id"], target_id),
        ).fetchone()
        if existing_friend:
            return jsonify({"error": "Already friends"}), 409

        # Check existing request
        existing_req = conn.execute(
            "SELECT status FROM friend_requests "
            "WHERE sender_id = ? AND receiver_id = ?",
            (user["user_id"], target_id),
        ).fetchone()
        if existing_req:
            if existing_req["status"] == "pending":
                return jsonify({"error": "Request already pending"}), 409
            # Allow re-sending if previously declined
            conn.execute(
                "UPDATE friend_requests SET status = 'pending', updated_at = ? "
                "WHERE sender_id = ? AND receiver_id = ?",
                (time.time(), user["user_id"], target_id),
            )
        else:
            conn.execute(
                "INSERT INTO friend_requests (sender_id, receiver_id) VALUES (?, ?)",
                (user["user_id"], target_id),
            )

        # Notify target if online
        notify_user(target_id, "friend_request", {
            "from": user["username"],
            "sender_id": user["user_id"],
        })

    return jsonify({"message": f"Friend request sent to {target_username}"}), 200


@app.route("/api/friends/respond", methods=["POST"])
def respond_friend_request():
    """Accept or decline a friend request."""
    user = authenticate_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    request_id = data.get("request_id")
    action = data.get("action", "").lower()

    if action not in ("accept", "decline"):
        return jsonify({"error": "Action must be 'accept' or 'decline'"}), 400

    with get_db() as conn:
        req = conn.execute(
            "SELECT id, sender_id, receiver_id, status FROM friend_requests WHERE id = ?",
            (request_id,),
        ).fetchone()

        if not req or req["receiver_id"] != user["user_id"]:
            return jsonify({"error": "Request not found"}), 404
        if req["status"] != "pending":
            return jsonify({"error": "Request already processed"}), 409

        conn.execute(
            "UPDATE friend_requests SET status = ?, updated_at = ? WHERE id = ?",
            (action + "ed", time.time(), request_id),
        )

        if action == "accept":
            # Create bidirectional friendship
            conn.execute(
                "INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)",
                (user["user_id"], req["sender_id"]),
            )
            conn.execute(
                "INSERT OR IGNORE INTO friends (user_id, friend_id) VALUES (?, ?)",
                (req["sender_id"], user["user_id"]),
            )
            # Notify sender
            notify_user(req["sender_id"], "friend_accepted", {
                "by": user["username"],
            })

    return jsonify({"message": f"Request {action}ed"}), 200


@app.route("/api/friends/cancel", methods=["POST"])
def cancel_friend_request():
    """Cancel a pending friend request."""
    user = authenticate_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    request_id = data.get("request_id")

    with get_db() as conn:
        req = conn.execute(
            "SELECT id, sender_id, status FROM friend_requests WHERE id = ?",
            (request_id,),
        ).fetchone()

        if not req or req["sender_id"] != user["user_id"]:
            return jsonify({"error": "Request not found"}), 404
        if req["status"] != "pending":
            return jsonify({"error": "Cannot cancel a processed request"}), 409

        conn.execute(
            "UPDATE friend_requests SET status = 'cancelled', updated_at = ? WHERE id = ?",
            (time.time(), request_id),
        )

    return jsonify({"message": "Request cancelled"}), 200


@app.route("/api/friends/pending", methods=["GET"])
def get_pending_requests():
    """Get all pending friend requests (both incoming and outgoing)."""
    user = authenticate_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    with get_db() as conn:
        incoming = conn.execute(
            "SELECT fr.id, u.username as sender, fr.created_at "
            "FROM friend_requests fr JOIN users u ON fr.sender_id = u.id "
            "WHERE fr.receiver_id = ? AND fr.status = 'pending'",
            (user["user_id"],),
        ).fetchall()

        outgoing = conn.execute(
            "SELECT fr.id, u.username as receiver, fr.created_at "
            "FROM friend_requests fr JOIN users u ON fr.receiver_id = u.id "
            "WHERE fr.sender_id = ? AND fr.status = 'pending'",
            (user["user_id"],),
        ).fetchall()

    return jsonify({
        "incoming": [dict(r) for r in incoming],
        "outgoing": [dict(r) for r in outgoing],
    }), 200


@app.route("/api/friends/list", methods=["GET"])
def list_friends():
    """Get the list of all friends."""
    user = authenticate_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    with get_db() as conn:
        friends = conn.execute(
            "SELECT u.id, u.username FROM friends f "
            "JOIN users u ON f.friend_id = u.id "
            "WHERE f.user_id = ?",
            (user["user_id"],),
        ).fetchall()

    return jsonify({
        "friends": [{"id": f["id"], "username": f["username"]} for f in friends],
    }), 200


@app.route("/api/friends/remove", methods=["POST"])
def remove_friend():
    """Remove a friend from the contact list."""
    user = authenticate_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    target_username = data.get("username", "").strip()

    with get_db() as conn:
        target = conn.execute(
            "SELECT id FROM users WHERE username = ?", (target_username,)
        ).fetchone()
        if not target:
            return jsonify({"error": "User not found"}), 404

        conn.execute(
            "DELETE FROM friends WHERE user_id = ? AND friend_id = ?",
            (user["user_id"], target["id"]),
        )
        conn.execute(
            "DELETE FROM friends WHERE user_id = ? AND friend_id = ?",
            (target["id"], user["user_id"]),
        )

    return jsonify({"message": f"Removed {target_username} from friends"}), 200


@app.route("/api/friends/block", methods=["POST"])
def block_user():
    """Block a user. Blocked users cannot send requests or messages."""
    user = authenticate_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    target_username = data.get("username", "").strip()

    with get_db() as conn:
        target = conn.execute(
            "SELECT id FROM users WHERE username = ?", (target_username,)
        ).fetchone()
        if not target:
            return jsonify({"error": "User not found"}), 404

        # Add to block list
        conn.execute(
            "INSERT OR IGNORE INTO blocked_users (user_id, blocked_id) VALUES (?, ?)",
            (user["user_id"], target["id"]),
        )
        # Remove friendship if exists
        conn.execute(
            "DELETE FROM friends WHERE user_id = ? AND friend_id = ?",
            (user["user_id"], target["id"]),
        )
        conn.execute(
            "DELETE FROM friends WHERE user_id = ? AND friend_id = ?",
            (target["id"], user["user_id"]),
        )

    return jsonify({"message": f"Blocked {target_username}"}), 200


@app.route("/api/friends/unblock", methods=["POST"])
def unblock_user():
    """Unblock a previously blocked user."""
    user = authenticate_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    target_username = data.get("username", "").strip()

    with get_db() as conn:
        target = conn.execute(
            "SELECT id FROM users WHERE username = ?", (target_username,)
        ).fetchone()
        if not target:
            return jsonify({"error": "User not found"}), 404

        conn.execute(
            "DELETE FROM blocked_users WHERE user_id = ? AND blocked_id = ?",
            (user["user_id"], target["id"]),
        )

    return jsonify({"message": f"Unblocked {target_username}"}), 200


# ============================================================
# HTTP API Routes - Messages & Conversations
# ============================================================

@app.route("/api/messages/send", methods=["POST"])
def send_message():
    """
    Send an encrypted message (ciphertext) to another user.

    Expects JSON: {
        "receiver": str (username),
        "ciphertext": str (hex-encoded encrypted payload),
        "message_uuid": str (unique message ID for dedup),
        "ttl_seconds": int or null (self-destruct timer),
    }

    The server only stores ciphertext; it cannot read message contents.
    Non-friends are blocked from sending messages (R16 anti-spam).
    """
    user = authenticate_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    receiver_username = data.get("receiver", "").strip()
    ciphertext = data.get("ciphertext", "")
    message_uuid = data.get("message_uuid", "")
    ttl_seconds = data.get("ttl_seconds")

    # Input validation
    if not receiver_username or not ciphertext or not message_uuid:
        return jsonify({"error": "Missing required fields"}), 400
    if len(ciphertext) > MAX_MESSAGE_SIZE * 2:  # hex encoding doubles size
        return jsonify({"error": "Message too large"}), 413

    with get_db() as conn:
        # Cleanup expired messages periodically
        cleanup_expired_messages(conn)

        receiver = conn.execute(
            "SELECT id FROM users WHERE username = ?", (receiver_username,)
        ).fetchone()
        if not receiver:
            return jsonify({"error": "Recipient not found"}), 404

        receiver_id = receiver["id"]

        # Anti-spam: must be friends to send messages (R16)
        is_friend = conn.execute(
            "SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ?",
            (user["user_id"], receiver_id),
        ).fetchone()
        if not is_friend:
            return jsonify({"error": "Must be friends to send messages"}), 403

        # Check blocked
        is_blocked = conn.execute(
            "SELECT 1 FROM blocked_users WHERE user_id = ? AND blocked_id = ?",
            (receiver_id, user["user_id"]),
        ).fetchone()
        if is_blocked:
            return jsonify({"error": "Cannot send message to this user"}), 403

        # Duplicate check (deduplication)
        existing = conn.execute(
            "SELECT id FROM messages WHERE message_uuid = ?", (message_uuid,)
        ).fetchone()
        if existing:
            return jsonify({"error": "Duplicate message", "message_uuid": message_uuid}), 409

        # Store message in queue
        conn.execute(
            "INSERT INTO messages (message_uuid, sender_id, receiver_id, ciphertext, ttl_seconds) "
            "VALUES (?, ?, ?, ?, ?)",
            (message_uuid, user["user_id"], receiver_id, ciphertext, ttl_seconds),
        )

    # Attempt real-time delivery via WebSocket
    delivered = notify_user(receiver_id, "new_message", {
        "message_uuid": message_uuid,
        "sender": user["username"],
        "sender_id": user["user_id"],
        "ciphertext": ciphertext,
        "ttl_seconds": ttl_seconds,
        "timestamp": time.time(),
    })

    status = "delivered" if delivered else "sent"

    return jsonify({
        "message": "Message sent",
        "message_uuid": message_uuid,
        "status": status,
    }), 200


@app.route("/api/messages/pending", methods=["GET"])
def get_pending_messages():
    """
    Fetch all undelivered messages for the current user (offline queue).

    Supports pagination via query params: ?offset=0&limit=50
    """
    user = authenticate_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    offset = request.args.get("offset", 0, type=int)
    limit = min(request.args.get("limit", 50, type=int), 100)

    with get_db() as conn:
        cleanup_expired_messages(conn)

        messages = conn.execute(
            "SELECT m.message_uuid, u.username as sender, m.sender_id, "
            "m.ciphertext, m.ttl_seconds, m.created_at "
            "FROM messages m JOIN users u ON m.sender_id = u.id "
            "WHERE m.receiver_id = ? AND m.delivered = 0 AND m.expired = 0 "
            "ORDER BY m.created_at ASC LIMIT ? OFFSET ?",
            (user["user_id"], limit, offset),
        ).fetchall()

        # Do NOT mark as delivered here; client must call /api/messages/ack
        # after successful decryption to confirm delivery.

    result = []
    for m in messages:
        result.append({
            "message_uuid": m["message_uuid"],
            "sender": m["sender"],
            "sender_id": m["sender_id"],
            "ciphertext": m["ciphertext"],
            "ttl_seconds": m["ttl_seconds"],
            "timestamp": m["created_at"],
        })

    return jsonify({"messages": result, "count": len(result)}), 200


@app.route("/api/messages/ack", methods=["POST"])
def acknowledge_message():
    """
    Acknowledge message delivery (used for delivery status updates).
    The sender is notified that the message was delivered.
    """
    user = authenticate_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json()
    message_uuids = data.get("message_uuids", [])

    with get_db() as conn:
        for mid in message_uuids:
            msg = conn.execute(
                "SELECT sender_id FROM messages WHERE message_uuid = ? AND receiver_id = ?",
                (mid, user["user_id"]),
            ).fetchone()
            if msg:
                conn.execute(
                    "UPDATE messages SET delivered = 1, delivered_at = ? "
                    "WHERE message_uuid = ?",
                    (time.time(), mid),
                )
                # Notify sender about delivery
                notify_user(msg["sender_id"], "delivery_receipt", {
                    "message_uuid": mid,
                    "status": "delivered",
                    "delivered_at": time.time(),
                })

    return jsonify({"message": "Acknowledged"}), 200


@app.route("/api/conversations", methods=["GET"])
def get_conversations():
    """
    Get conversation list with last message time and unread counts.

    Returns conversations ordered by most recent activity.
    Supports pagination via ?offset=0&limit=20.
    """
    user = authenticate_request()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    offset = request.args.get("offset", 0, type=int)
    limit = min(request.args.get("limit", 20, type=int), 50)

    with get_db() as conn:
        cleanup_expired_messages(conn)

        # Get conversations with last activity and unread count
        conversations = conn.execute("""
            SELECT
                u.username,
                u.id as user_id,
                MAX(m.created_at) as last_message_time,
                SUM(CASE WHEN m.receiver_id = ? AND m.delivered = 0 AND m.expired = 0 THEN 1 ELSE 0 END) as unread_count
            FROM friends f
            JOIN users u ON f.friend_id = u.id
            LEFT JOIN messages m ON (
                (m.sender_id = f.friend_id AND m.receiver_id = ?)
                OR (m.sender_id = ? AND m.receiver_id = f.friend_id)
            ) AND m.expired = 0
            WHERE f.user_id = ?
            GROUP BY u.id
            ORDER BY last_message_time DESC NULLS LAST
            LIMIT ? OFFSET ?
        """, (
            user["user_id"], user["user_id"], user["user_id"],
            user["user_id"], limit, offset,
        )).fetchall()

    result = []
    for c in conversations:
        result.append({
            "username": c["username"],
            "user_id": c["user_id"],
            "last_message_time": c["last_message_time"],
            "unread_count": c["unread_count"] or 0,
        })

    return jsonify({"conversations": result}), 200


# ============================================================
# WebSocket Event Handlers
# ============================================================

def notify_user(user_id: int, event: str, data: dict) -> bool:
    """
    Send a real-time notification to a user via WebSocket.
    Returns True if the user was online and received the message.
    """
    if user_id in online_users and online_users[user_id]:
        for sid in online_users[user_id]:
            socketio.emit(event, data, room=sid)
        return True
    return False


@socketio.on("connect")
def handle_connect():
    """Handle WebSocket connection with token authentication."""
    token = request.args.get("token", "")
    user = authenticate_socket(token)
    if not user:
        logger.warning("Unauthorized WebSocket connection attempt")
        disconnect()
        return

    user_id = user["user_id"]
    sid = request.sid

    if user_id not in online_users:
        online_users[user_id] = set()
    online_users[user_id].add(sid)
    socket_user_map[sid] = user_id

    join_room(f"user_{user_id}")
    logger.info("WebSocket connected: %s (sid=%s)", user["username"], sid)

    # Deliver pending messages
    with get_db() as conn:
        cleanup_expired_messages(conn)
        pending = conn.execute(
            "SELECT m.message_uuid, u.username as sender, m.sender_id, "
            "m.ciphertext, m.ttl_seconds, m.created_at "
            "FROM messages m JOIN users u ON m.sender_id = u.id "
            "WHERE m.receiver_id = ? AND m.delivered = 0 AND m.expired = 0 "
            "ORDER BY m.created_at ASC",
            (user_id,),
        ).fetchall()

        for msg in pending:
            emit("new_message", {
                "message_uuid": msg["message_uuid"],
                "sender": msg["sender"],
                "sender_id": msg["sender_id"],
                "ciphertext": msg["ciphertext"],
                "ttl_seconds": msg["ttl_seconds"],
                "timestamp": msg["created_at"],
            })
            conn.execute(
                "UPDATE messages SET delivered = 1, delivered_at = ? WHERE message_uuid = ?",
                (time.time(), msg["message_uuid"]),
            )
            # Notify sender about delivery
            notify_user(msg["sender_id"], "delivery_receipt", {
                "message_uuid": msg["message_uuid"],
                "status": "delivered",
                "delivered_at": time.time(),
            })


@socketio.on("disconnect")
def handle_disconnect():
    """Handle WebSocket disconnection."""
    sid = request.sid
    user_id = socket_user_map.pop(sid, None)
    if user_id and user_id in online_users:
        online_users[user_id].discard(sid)
        if not online_users[user_id]:
            del online_users[user_id]
    logger.info("WebSocket disconnected: sid=%s", sid)


@socketio.on("send_message")
def handle_send_message(data):
    """Handle real-time message sending via WebSocket."""
    sid = request.sid
    user_id = socket_user_map.get(sid)
    if not user_id:
        emit("error", {"message": "Not authenticated"})
        return

    receiver_username = data.get("receiver", "")
    ciphertext = data.get("ciphertext", "")
    message_uuid = data.get("message_uuid", "")
    ttl_seconds = data.get("ttl_seconds")

    if not receiver_username or not ciphertext or not message_uuid:
        emit("error", {"message": "Missing required fields"})
        return

    if len(ciphertext) > MAX_MESSAGE_SIZE * 2:
        emit("error", {"message": "Message too large"})
        return

    with get_db() as conn:
        cleanup_expired_messages(conn)

        # Get sender username
        sender = conn.execute(
            "SELECT username FROM users WHERE id = ?", (user_id,)
        ).fetchone()

        receiver = conn.execute(
            "SELECT id FROM users WHERE username = ?", (receiver_username,)
        ).fetchone()
        if not receiver:
            emit("error", {"message": "Recipient not found"})
            return

        receiver_id = receiver["id"]

        # Friendship check (anti-spam R16)
        is_friend = conn.execute(
            "SELECT 1 FROM friends WHERE user_id = ? AND friend_id = ?",
            (user_id, receiver_id),
        ).fetchone()
        if not is_friend:
            emit("error", {"message": "Must be friends to send messages"})
            return

        # Block check
        is_blocked = conn.execute(
            "SELECT 1 FROM blocked_users WHERE user_id = ? AND blocked_id = ?",
            (receiver_id, user_id),
        ).fetchone()
        if is_blocked:
            emit("error", {"message": "Blocked by recipient"})
            return

        # Deduplication
        existing = conn.execute(
            "SELECT id FROM messages WHERE message_uuid = ?", (message_uuid,)
        ).fetchone()
        if existing:
            emit("message_status", {"message_uuid": message_uuid, "status": "duplicate"})
            return

        # Store in queue
        conn.execute(
            "INSERT INTO messages (message_uuid, sender_id, receiver_id, ciphertext, ttl_seconds) "
            "VALUES (?, ?, ?, ?, ?)",
            (message_uuid, user_id, receiver_id, ciphertext, ttl_seconds),
        )

    # Real-time delivery attempt
    delivered = notify_user(receiver_id, "new_message", {
        "message_uuid": message_uuid,
        "sender": sender["username"],
        "sender_id": user_id,
        "ciphertext": ciphertext,
        "ttl_seconds": ttl_seconds,
        "timestamp": time.time(),
    })

    if delivered:
        with get_db() as conn:
            conn.execute(
                "UPDATE messages SET delivered = 1, delivered_at = ? WHERE message_uuid = ?",
                (time.time(), message_uuid),
            )

    emit("message_status", {
        "message_uuid": message_uuid,
        "status": "delivered" if delivered else "sent",
    })


@socketio.on("typing")
def handle_typing(data):
    """Forward typing indicator to the other user."""
    sid = request.sid
    user_id = socket_user_map.get(sid)
    if not user_id:
        return

    receiver_username = data.get("receiver", "")
    receiver_id = get_user_id_by_username(receiver_username)
    if receiver_id:
        with get_db() as conn:
            sender = conn.execute(
                "SELECT username FROM users WHERE id = ?", (user_id,)
            ).fetchone()
        if sender:
            notify_user(receiver_id, "typing", {"sender": sender["username"]})


# ============================================================
# TLS Certificate Generation
# ============================================================

def generate_self_signed_cert():
    """Generate a self-signed TLS certificate for development/testing."""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return

    os.makedirs(CERT_DIR, exist_ok=True)
    logger.info("Generating self-signed TLS certificate...")

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes as crypto_hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization as crypto_serialization
    import datetime

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Server"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(__import__("ipaddress").IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, crypto_hashes.SHA256())
    )

    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=crypto_serialization.Encoding.PEM,
            format=crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=crypto_serialization.NoEncryption(),
        ))

    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(crypto_serialization.Encoding.PEM))

    logger.info("TLS certificate generated at %s", CERT_DIR)


# ============================================================
# Server Entry Point
# ============================================================

def main():
    """Start the SecureChat server."""
    logger.info("=" * 60)
    logger.info("  SecureChat Server - E2EE Secure Instant Messaging")
    logger.info("=" * 60)

    # Initialize database
    init_database()
    logger.info("Database initialized at %s", DATABASE_PATH)

    # Generate TLS certificate if needed
    generate_self_signed_cert()

    # Start server with TLS
    # For threading mode (werkzeug), ssl_context is a (cert, key) tuple
    ssl_ctx = None
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        ssl_ctx = (CERT_FILE, KEY_FILE)
        logger.info("TLS enabled (self-signed certificate)")
    else:
        logger.warning("TLS disabled - running in insecure mode!")

    logger.info("Server starting on %s:%d", HOST, PORT)

    socketio.run(
        app,
        host=HOST,
        port=PORT,
        ssl_context=ssl_ctx,
        debug=False,
        allow_unsafe_werkzeug=True,
    )


if __name__ == "__main__":
    main()
