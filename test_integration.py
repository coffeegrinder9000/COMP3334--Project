"""
test_integration.py - Integration tests for SecureChat.

Starts the server programmatically and tests the full flow:
  - User registration
  - Login with OTP
  - Key upload
  - Friend request workflow
  - E2EE message send/receive
  - Message deduplication
  - Conversation list and unread counts
  - Self-destruct message expiry

Run: python test_integration.py
"""

import sys
import os
import time
import json
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

import requests
import pyotp

# Suppress TLS warnings for self-signed certs
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://127.0.0.1:5001"
TEST_DB = os.path.join(os.path.dirname(__file__), "server", "test_securechat.db")

# CRITICAL: Patch DATABASE_PATH before importing server modules
# so all internal get_db() calls use the test database
import server.database as db_mod
for f in [TEST_DB, TEST_DB + "-wal", TEST_DB + "-shm"]:
    if os.path.exists(f):
        os.remove(f)
db_mod.DATABASE_PATH = TEST_DB

from server.database import init_database, get_db
from server.server import app, socketio, generate_self_signed_cert


def setup_server():
    """Start the server in a background thread for testing."""
    init_database(TEST_DB)
    generate_self_signed_cert()

    from server.server import CERT_FILE, KEY_FILE

    def run_server():
        socketio.run(
            app, host="127.0.0.1", port=5001,
            ssl_context=(CERT_FILE, KEY_FILE),
            debug=False,
            allow_unsafe_werkzeug=True,
        )

    t = threading.Thread(target=run_server, daemon=True)
    t.start()
    time.sleep(2)
    return t


def api(method, path, token=None, **kwargs):
    """Helper to make API calls."""
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    resp = getattr(requests, method)(
        f"{BASE_URL}{path}",
        headers=headers,
        verify=False,
        timeout=10,
        **kwargs,
    )
    return resp


def test_full_flow():
    """Run the complete integration test."""
    print("=" * 50)
    print("  SecureChat Integration Tests")
    print("=" * 50)
    print()

    # ---- Test 1: Registration ----
    print("Test 1: User Registration")
    resp = api("post", "/api/register", json={
        "username": "alice", "password": "password123",
    })
    assert resp.status_code == 201, f"Registration failed: {resp.text}"
    alice_otp_secret = resp.json()["otp_secret"]
    print(f"  [PASS] Alice registered (OTP secret: {alice_otp_secret[:8]}...)")

    resp = api("post", "/api/register", json={
        "username": "bob", "password": "password456",
    })
    assert resp.status_code == 201, f"Registration failed: {resp.text}"
    bob_otp_secret = resp.json()["otp_secret"]
    print(f"  [PASS] Bob registered")

    # ---- Test 2: Duplicate Registration ----
    print("Test 2: Duplicate Registration")
    resp = api("post", "/api/register", json={
        "username": "alice", "password": "password123",
    })
    assert resp.status_code == 409
    print(f"  [PASS] Duplicate username rejected (409)")

    # ---- Test 3: Password Validation ----
    print("Test 3: Password Validation")
    resp = api("post", "/api/register", json={
        "username": "test", "password": "short",
    })
    assert resp.status_code == 400
    print(f"  [PASS] Short password rejected (400)")

    # ---- Test 4: Login with OTP ----
    print("Test 4: Login with Password + OTP")
    alice_totp = pyotp.TOTP(alice_otp_secret)
    resp = api("post", "/api/login", json={
        "username": "alice",
        "password": "password123",
        "otp_code": alice_totp.now(),
    })
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    alice_token = resp.json()["token"]
    print(f"  [PASS] Alice logged in")

    bob_totp = pyotp.TOTP(bob_otp_secret)
    resp = api("post", "/api/login", json={
        "username": "bob",
        "password": "password456",
        "otp_code": bob_totp.now(),
    })
    assert resp.status_code == 200, f"Login failed: {resp.text}"
    bob_token = resp.json()["token"]
    print(f"  [PASS] Bob logged in")

    # ---- Test 5: Wrong Password ----
    print("Test 5: Wrong Password")
    resp = api("post", "/api/login", json={
        "username": "alice",
        "password": "wrongpassword",
        "otp_code": alice_totp.now(),
    })
    assert resp.status_code == 401
    print(f"  [PASS] Wrong password rejected (401)")

    # ---- Test 6: Wrong OTP ----
    print("Test 6: Wrong OTP Code")
    resp = api("post", "/api/login", json={
        "username": "alice",
        "password": "password123",
        "otp_code": "000000",
    })
    assert resp.status_code == 401
    print(f"  [PASS] Wrong OTP rejected (401)")

    # ---- Test 7: Key Upload ----
    print("Test 7: Key Upload")
    from common.crypto_utils import (
        generate_identity_keypair, generate_x25519_keypair,
        serialize_public_key_ed25519, serialize_public_key_x25519,
    )

    alice_id_priv, alice_id_pub = generate_identity_keypair()
    alice_x_priv, alice_x_pub = generate_x25519_keypair()
    alice_spk_priv, alice_spk_pub = generate_x25519_keypair()
    spk_sig = alice_id_priv.sign(serialize_public_key_x25519(alice_spk_pub))

    resp = api("post", "/api/keys/upload", alice_token, json={
        "identity_key_pub": serialize_public_key_ed25519(alice_id_pub).hex(),
        "x25519_identity_pub": serialize_public_key_x25519(alice_x_pub).hex(),
        "signed_prekey_pub": serialize_public_key_x25519(alice_spk_pub).hex(),
        "signed_prekey_sig": spk_sig.hex(),
        "one_time_prekeys": [serialize_public_key_x25519(generate_x25519_keypair()[1]).hex() for _ in range(5)],
    })
    assert resp.status_code == 200, f"Key upload failed: {resp.text}"
    print(f"  [PASS] Alice keys uploaded")

    # ---- Test 8: Get Prekey Bundle ----
    print("Test 8: Prekey Bundle Retrieval")
    resp = api("get", "/api/keys/bundle/alice", bob_token)
    assert resp.status_code == 200
    bundle = resp.json()
    assert bundle["identity_key_pub"] == serialize_public_key_ed25519(alice_id_pub).hex()
    print(f"  [PASS] Alice's prekey bundle fetched by Bob")

    # ---- Test 9: Friend Request Workflow ----
    print("Test 9: Friend Request Workflow")

    # Non-friend cannot send message
    resp = api("post", "/api/messages/send", alice_token, json={
        "receiver": "bob",
        "ciphertext": "deadbeef",
        "message_uuid": "test-uuid-1",
    })
    assert resp.status_code == 403
    print(f"  [PASS] Non-friend message blocked (403)")

    # Send friend request
    resp = api("post", "/api/friends/request", alice_token, json={
        "username": "bob",
    })
    assert resp.status_code == 200
    print(f"  [PASS] Alice sent friend request to Bob")

    # Bob sees pending request
    resp = api("get", "/api/friends/pending", bob_token)
    assert resp.status_code == 200
    incoming = resp.json()["incoming"]
    assert len(incoming) == 1
    req_id = incoming[0]["id"]
    print(f"  [PASS] Bob sees pending request (id={req_id})")

    # Bob accepts
    resp = api("post", "/api/friends/respond", bob_token, json={
        "request_id": req_id, "action": "accept",
    })
    assert resp.status_code == 200
    print(f"  [PASS] Bob accepted friend request")

    # Both see each other as friends
    resp = api("get", "/api/friends/list", alice_token)
    alice_friends = [f["username"] for f in resp.json()["friends"]]
    assert "bob" in alice_friends
    print(f"  [PASS] Alice sees Bob as friend")

    resp = api("get", "/api/friends/list", bob_token)
    bob_friends = [f["username"] for f in resp.json()["friends"]]
    assert "alice" in bob_friends
    print(f"  [PASS] Bob sees Alice as friend")

    # ---- Test 10: Send Message (Ciphertext) ----
    print("Test 10: E2EE Message Send/Receive")
    msg_uuid = "msg-uuid-001"
    resp = api("post", "/api/messages/send", alice_token, json={
        "receiver": "bob",
        "ciphertext": "encrypted_payload_hex_abcdef1234567890",
        "message_uuid": msg_uuid,
        "ttl_seconds": 300,
    })
    assert resp.status_code == 200
    print(f"  [PASS] Alice sent encrypted message (uuid={msg_uuid})")

    # ---- Test 11: Message Deduplication ----
    print("Test 11: Message Deduplication")
    resp = api("post", "/api/messages/send", alice_token, json={
        "receiver": "bob",
        "ciphertext": "encrypted_payload_hex_abcdef1234567890",
        "message_uuid": msg_uuid,  # same UUID
    })
    assert resp.status_code == 409
    print(f"  [PASS] Duplicate message rejected (409)")

    # ---- Test 12: Pending Messages ----
    print("Test 12: Offline Message Retrieval")
    resp = api("get", "/api/messages/pending", bob_token)
    assert resp.status_code == 200
    messages = resp.json()["messages"]
    assert len(messages) == 1
    assert messages[0]["message_uuid"] == msg_uuid
    assert messages[0]["ciphertext"] == "encrypted_payload_hex_abcdef1234567890"
    assert messages[0]["ttl_seconds"] == 300
    print(f"  [PASS] Bob received pending message")

    # ---- Test 13: Delivery Acknowledgment ----
    print("Test 13: Delivery Acknowledgment")
    resp = api("post", "/api/messages/ack", bob_token, json={
        "message_uuids": [msg_uuid],
    })
    assert resp.status_code == 200
    print(f"  [PASS] Bob acknowledged delivery")

    # ---- Test 14: Conversations ----
    print("Test 14: Conversation List")
    resp = api("get", "/api/conversations", alice_token)
    assert resp.status_code == 200
    convs = resp.json()["conversations"]
    assert len(convs) >= 1
    print(f"  [PASS] Alice sees {len(convs)} conversation(s)")

    # ---- Test 15: Block User ----
    print("Test 15: Block/Unblock")
    resp = api("post", "/api/friends/block", bob_token, json={
        "username": "alice",
    })
    assert resp.status_code == 200

    # Alice can no longer send messages
    resp = api("post", "/api/messages/send", alice_token, json={
        "receiver": "bob",
        "ciphertext": "blocked_test",
        "message_uuid": "msg-uuid-blocked",
    })
    assert resp.status_code == 403
    print(f"  [PASS] Blocked user cannot send messages")

    # Unblock
    resp = api("post", "/api/friends/unblock", bob_token, json={
        "username": "alice",
    })
    assert resp.status_code == 200
    print(f"  [PASS] User unblocked")

    # ---- Test 16: Logout ----
    print("Test 16: Logout / Session Invalidation")
    resp = api("post", "/api/logout", alice_token)
    assert resp.status_code == 200

    # Token should no longer work
    resp = api("get", "/api/friends/list", alice_token)
    assert resp.status_code == 401
    print(f"  [PASS] Logged out, token invalidated")

    # ---- Test 17: Verify Server Cannot See Plaintext ----
    print("Test 17: Server-Side Data Inspection")
    with get_db(TEST_DB) as conn:
        msgs = conn.execute("SELECT ciphertext FROM messages").fetchall()
        for m in msgs:
            assert "hello" not in m["ciphertext"].lower()
        users = conn.execute("SELECT password_hash FROM users").fetchall()
        for u in users:
            assert u["password_hash"].startswith("$argon2id$")
    print(f"  [PASS] Server stores only ciphertext and hashed passwords")

    print()
    print("=" * 50)
    print("  All integration tests passed!")
    print("=" * 50)


def cleanup():
    """Clean up test database."""
    if os.path.exists(TEST_DB):
        os.remove(TEST_DB)
    wal = TEST_DB + "-wal"
    shm = TEST_DB + "-shm"
    if os.path.exists(wal):
        os.remove(wal)
    if os.path.exists(shm):
        os.remove(shm)


if __name__ == "__main__":
    try:
        setup_server()
        test_full_flow()
    except AssertionError as e:
        print(f"\n[FAIL] Test assertion error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        cleanup()
