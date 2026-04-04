"""
client.py - SecureChat CLI Client Application.

A command-line client implementing:
  - User registration and login (password + TOTP 2FA)
  - Identity keypair generation (Ed25519 + X25519)
  - X3DH-like key exchange for session establishment
  - Double Ratchet for forward-secrecy E2EE messaging
  - Friend request workflow (send/accept/decline/cancel/block)
  - Timed self-destruct messages with configurable TTL
  - Offline message retrieval (store-and-forward)
  - Message delivery status (Sent / Delivered)
  - Conversation list with unread counters
  - Safety number / fingerprint verification
  - Replay protection via message UUID deduplication
  - Encrypted local storage for private keys and state

The client NEVER sends plaintext to the server.
All messages are encrypted end-to-end using AES-256-GCM via the Double Ratchet.
"""

import os
import sys
import time
import uuid
import json
import threading
import getpass
import urllib3

# Suppress InsecureRequestWarning for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
import socketio as sio_client

# Add parent directory to path for common module imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.crypto_utils import (
    generate_identity_keypair,
    generate_x25519_keypair,
    serialize_public_key_ed25519,
    serialize_public_key_x25519,
    serialize_private_key_ed25519,
    serialize_private_key_x25519,
    deserialize_public_key_ed25519,
    deserialize_public_key_x25519,
    deserialize_private_key_ed25519,
    deserialize_private_key_x25519,
    compute_safety_number,
    x3dh_sender_compute,
    x3dh_receiver_compute,
    DoubleRatchet,
)
from client.client_storage import save_client_state, load_client_state

# ============================================================
# Configuration
# ============================================================
DEFAULT_SERVER_URL = "https://localhost:5050"
MAX_SEEN_UUIDS = 10000  # Maximum stored seen message UUIDs for replay protection
DEFAULT_PAGE_SIZE = 20   # Messages per page for incremental loading


# ============================================================
# SecureChat Client
# ============================================================

class SecureChatClient:
    """
    CLI client for SecureChat with full E2EE support.

    Manages cryptographic keys, sessions, and message encryption/decryption
    while providing a terminal-based user interface.
    """

    def __init__(self, server_url: str = DEFAULT_SERVER_URL):
        self.server_url = server_url.rstrip("/")
        self.session = requests.Session()
        self.session.verify = False  # Allow self-signed TLS certs

        # Authentication state
        self.token = None
        self.username = None
        self.password = None
        self.user_id = None

        # Cryptographic keys
        self.identity_priv_ed = None
        self.identity_pub_ed = None
        self.identity_priv_x = None
        self.identity_pub_x = None
        self.signed_prekey_priv = None
        self.signed_prekey_pub = None
        self.one_time_prekey_privs = {}  # prekey_id -> private_key_hex

        # E2EE session state
        self.ratchet_sessions = {}  # peer_username -> DoubleRatchet

        # Contact management
        self.contacts = {}  # username -> {verified, identity_key_pub, ...}

        # Replay protection: set of seen message UUIDs
        self.seen_message_uuids = set()

        # Local message store
        self.messages = {}  # username -> [message_dicts]

        # WebSocket client for real-time messaging
        self.ws_client = None
        self.ws_connected = False

        # Delivery status tracking
        self.delivery_status = {}  # message_uuid -> status

    # ============================================================
    # Authentication
    # ============================================================

    def register(self):
        """Register a new user account with the server."""
        print("\n=== Register New Account ===")
        username = input("Username (3-32 alphanumeric chars): ").strip()
        password = getpass.getpass("Password (min 8 chars): ")
        password_confirm = getpass.getpass("Confirm password: ")

        if password != password_confirm:
            print("[ERROR] Passwords do not match.")
            return False

        try:
            resp = self.session.post(
                f"{self.server_url}/api/register",
                json={"username": username, "password": password},
                timeout=10,
            )
            data = resp.json()

            if resp.status_code == 201:
                print(f"\n[OK] Registration successful for '{username}'!")
                print(f"\n*** IMPORTANT: Save your TOTP secret for 2FA login ***")
                print(f"  OTP Secret: {data['otp_secret']}")
                print(f"  OTP URI: {data['otp_uri']}")
                print(f"\nAdd this to your authenticator app (Google Authenticator, etc.)")
                return True
            else:
                print(f"[ERROR] {data.get('error', 'Registration failed')}")
                return False
        except requests.exceptions.ConnectionError:
            print("[ERROR] Cannot connect to server. Is it running?")
            return False

    def login(self):
        """Login with username, password, and OTP code."""
        print("\n=== Login ===")
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        otp_code = input("OTP Code: ").strip()

        try:
            resp = self.session.post(
                f"{self.server_url}/api/login",
                json={
                    "username": username,
                    "password": password,
                    "otp_code": otp_code,
                },
                timeout=10,
            )
            data = resp.json()

            if resp.status_code == 200:
                self.token = data["token"]
                self.username = username
                self.password = password
                self.user_id = data["user_id"]
                self.session.headers["Authorization"] = f"Bearer {self.token}"

                print(f"[OK] Logged in as '{username}'")

                # Load or initialize keys
                self._load_state()
                if not self.identity_priv_ed:
                    self._generate_keys()

                # Upload keys to server
                self._upload_keys()

                # Connect WebSocket for real-time messaging
                self._connect_websocket()

                # Fetch pending messages
                self._fetch_pending_messages()

                return True
            else:
                print(f"[ERROR] {data.get('error', 'Login failed')}")
                return False
        except requests.exceptions.ConnectionError:
            print("[ERROR] Cannot connect to server. Is it running?")
            return False

    def logout(self):
        """Logout and save state."""
        if not self.token:
            return

        self._save_state()
        self._disconnect_websocket()

        try:
            self.session.post(f"{self.server_url}/api/logout", timeout=5)
        except Exception:
            pass

        self.token = None
        self.username = None
        self.user_id = None
        print("[OK] Logged out.")

    # ============================================================
    # Key Management
    # ============================================================

    def _generate_keys(self):
        """Generate all required cryptographic keypairs."""
        print("[INFO] Generating identity keypairs...")

        # Ed25519 identity keypair (for signing)
        self.identity_priv_ed, self.identity_pub_ed = generate_identity_keypair()

        # X25519 identity keypair (for DH in X3DH)
        self.identity_priv_x, self.identity_pub_x = generate_x25519_keypair()

        # Signed prekey (X25519)
        self.signed_prekey_priv, self.signed_prekey_pub = generate_x25519_keypair()

        # One-time prekeys (X25519), keyed by string ID for JSON compatibility
        self.one_time_prekey_privs = {}
        for i in range(10):
            priv, pub = generate_x25519_keypair()
            self.one_time_prekey_privs[str(i)] = serialize_private_key_x25519(priv).hex()

        print("[OK] Keys generated.")

    def _upload_keys(self):
        """Upload public keys and prekey bundle to the server."""
        if not self.identity_pub_ed:
            return

        # Sign the signed prekey with our identity key
        prekey_pub_bytes = serialize_public_key_x25519(self.signed_prekey_pub)
        signature = self.identity_priv_ed.sign(prekey_pub_bytes)

        # Prepare one-time prekey public keys in order of their IDs
        otpk_pubs = []
        for idx in sorted(self.one_time_prekey_privs.keys(), key=lambda x: int(x)):
            priv_hex = self.one_time_prekey_privs[idx]
            priv = deserialize_private_key_x25519(bytes.fromhex(priv_hex))
            pub = priv.public_key()
            otpk_pubs.append(serialize_public_key_x25519(pub).hex())

        try:
            resp = self.session.post(
                f"{self.server_url}/api/keys/upload",
                json={
                    "identity_key_pub": serialize_public_key_ed25519(
                        self.identity_pub_ed
                    ).hex(),
                    "x25519_identity_pub": serialize_public_key_x25519(
                        self.identity_pub_x
                    ).hex(),
                    "signed_prekey_pub": prekey_pub_bytes.hex(),
                    "signed_prekey_sig": signature.hex(),
                    "one_time_prekeys": otpk_pubs,
                },
                timeout=10,
            )
            if resp.status_code == 200:
                pass  # Keys uploaded silently
            else:
                print(f"[WARN] Key upload issue: {resp.json().get('error', '')}")
        except Exception as e:
            print(f"[WARN] Could not upload keys: {e}")

    # ============================================================
    # State Persistence
    # ============================================================

    def _save_state(self):
        """Save client state to encrypted local storage."""
        if not self.username or not self.password:
            return

        state = {
            "identity_priv_ed": serialize_private_key_ed25519(
                self.identity_priv_ed
            ).hex() if self.identity_priv_ed else None,
            "identity_pub_ed": serialize_public_key_ed25519(
                self.identity_pub_ed
            ).hex() if self.identity_pub_ed else None,
            "identity_priv_x": serialize_private_key_x25519(
                self.identity_priv_x
            ).hex() if self.identity_priv_x else None,
            "identity_pub_x": serialize_public_key_x25519(
                self.identity_pub_x
            ).hex() if self.identity_pub_x else None,
            "signed_prekey_priv": serialize_private_key_x25519(
                self.signed_prekey_priv
            ).hex() if self.signed_prekey_priv else None,
            "signed_prekey_pub": serialize_public_key_x25519(
                self.signed_prekey_pub
            ).hex() if self.signed_prekey_pub else None,
            "one_time_prekey_privs": self.one_time_prekey_privs,
            "ratchet_sessions": {
                k: v.export_state() for k, v in self.ratchet_sessions.items()
            },
            "contacts": self.contacts,
            "seen_message_uuids": list(self.seen_message_uuids)[-MAX_SEEN_UUIDS:],
            "messages": self.messages,
            "delivery_status": self.delivery_status,
        }
        save_client_state(self.username, self.password, state)

    def _load_state(self):
        """Load client state from encrypted local storage."""
        if not self.username or not self.password:
            return

        state = load_client_state(self.username, self.password)
        if not state:
            return

        if state.get("identity_priv_ed"):
            self.identity_priv_ed = deserialize_private_key_ed25519(
                bytes.fromhex(state["identity_priv_ed"])
            )
            self.identity_pub_ed = self.identity_priv_ed.public_key()

        if state.get("identity_priv_x"):
            self.identity_priv_x = deserialize_private_key_x25519(
                bytes.fromhex(state["identity_priv_x"])
            )
            self.identity_pub_x = self.identity_priv_x.public_key()

        if state.get("signed_prekey_priv"):
            self.signed_prekey_priv = deserialize_private_key_x25519(
                bytes.fromhex(state["signed_prekey_priv"])
            )
            self.signed_prekey_pub = self.signed_prekey_priv.public_key()

        self.one_time_prekey_privs = state.get("one_time_prekey_privs", {})

        # Restore ratchet sessions
        for peer, rstate in state.get("ratchet_sessions", {}).items():
            try:
                self.ratchet_sessions[peer] = DoubleRatchet.from_state(rstate)
            except Exception:
                pass  # Silently skip corrupted sessions

        self.contacts = state.get("contacts", {})
        self.seen_message_uuids = set(state.get("seen_message_uuids", []))
        self.messages = state.get("messages", {})
        self.delivery_status = state.get("delivery_status", {})

        print("[OK] Client state restored from local storage.")

    # ============================================================
    # E2EE Session Establishment (X3DH)
    # ============================================================

    def _establish_session(self, peer_username: str) -> bool:
        """
        Establish an E2EE session with a peer using X3DH-like protocol.

        Steps:
          1. Fetch peer's prekey bundle from server
          2. Verify the signed prekey signature
          3. Perform X3DH key agreement
          4. Initialize Double Ratchet with the shared secret
        """
        if peer_username in self.ratchet_sessions:
            return True  # Session already exists

        try:
            resp = self.session.get(
                f"{self.server_url}/api/keys/bundle/{peer_username}",
                timeout=10,
            )
            if resp.status_code != 200:
                print(f"[ERROR] Cannot fetch keys for {peer_username}: "
                      f"{resp.json().get('error', '')}")
                return False

            bundle = resp.json()
        except Exception as e:
            print(f"[ERROR] Network error: {e}")
            return False

        # Parse peer's keys
        peer_identity_ed_pub = deserialize_public_key_ed25519(
            bytes.fromhex(bundle["identity_key_pub"])
        )
        peer_identity_x_pub = deserialize_public_key_x25519(
            bytes.fromhex(bundle["x25519_identity_pub"])
        )
        peer_signed_prekey_pub = deserialize_public_key_x25519(
            bytes.fromhex(bundle["signed_prekey_pub"])
        )
        peer_signed_prekey_sig = bytes.fromhex(bundle["signed_prekey_sig"])

        # Verify signed prekey signature (R7 - authenticate the prekey)
        try:
            peer_identity_ed_pub.verify(
                peer_signed_prekey_sig,
                serialize_public_key_x25519(peer_signed_prekey_pub),
            )
        except Exception:
            print(f"[SECURITY] Signed prekey verification FAILED for {peer_username}!")
            return False

        # Key change detection (R6)
        stored_key = self.contacts.get(peer_username, {}).get("identity_key_pub")
        current_key = bundle["identity_key_pub"]
        if stored_key and stored_key != current_key:
            print(f"\n[WARNING] Identity key changed for '{peer_username}'!")
            print(f"  This could indicate:")
            print(f"  - The user reinstalled their app")
            print(f"  - A potential security issue (MITM attack)")
            print(f"  Previous key: {stored_key[:16]}...")
            print(f"  Current key:  {current_key[:16]}...")
            confirm = input("  Continue anyway? (yes/no): ").strip().lower()
            if confirm != "yes":
                print("[ABORTED] Session not established.")
                return False
            # Reset verification status
            if peer_username in self.contacts:
                self.contacts[peer_username]["verified"] = False

        # Parse optional one-time prekey
        peer_otpk_pub = None
        if bundle.get("one_time_prekey_pub"):
            peer_otpk_pub = deserialize_public_key_x25519(
                bytes.fromhex(bundle["one_time_prekey_pub"])
            )

        # Generate ephemeral keypair for X3DH
        ephemeral_priv, ephemeral_pub = generate_x25519_keypair()

        # X3DH sender computation
        shared_secret = x3dh_sender_compute(
            sender_identity_priv_x=self.identity_priv_x,
            sender_ephemeral_priv=ephemeral_priv,
            receiver_identity_pub_x=peer_identity_x_pub,
            receiver_signed_prekey_pub=peer_signed_prekey_pub,
            receiver_one_time_prekey_pub=peer_otpk_pub,
        )

        # Initialize Double Ratchet as initiator
        ratchet_dh_priv, ratchet_dh_pub = generate_x25519_keypair()
        ratchet = DoubleRatchet(
            root_key=shared_secret,
            dh_self_priv=ratchet_dh_priv,
            dh_remote_pub=peer_signed_prekey_pub,
            is_initiator=True,
        )

        self.ratchet_sessions[peer_username] = ratchet

        # Store contact info
        self.contacts[peer_username] = {
            "identity_key_pub": current_key,
            "verified": self.contacts.get(peer_username, {}).get("verified", False),
            "x3dh_ephemeral_pub": serialize_public_key_x25519(ephemeral_pub).hex(),
            "x3dh_identity_pub": serialize_public_key_x25519(
                self.identity_pub_x
            ).hex(),
            "one_time_prekey_id": bundle.get("one_time_prekey_id"),
        }

        self._save_state()
        return True

    def _handle_incoming_session(self, sender_username: str, msg_data: dict) -> bool:
        """
        Handle an incoming X3DH session from a sender.

        The initial message contains X3DH parameters needed for the receiver
        to compute the same shared secret.
        """
        x3dh_params = msg_data.get("x3dh_params")
        if not x3dh_params:
            return False

        sender_identity_x_pub = deserialize_public_key_x25519(
            bytes.fromhex(x3dh_params["identity_pub"])
        )
        sender_ephemeral_pub = deserialize_public_key_x25519(
            bytes.fromhex(x3dh_params["ephemeral_pub"])
        )
        otpk_id = x3dh_params.get("one_time_prekey_id")

        # Get the one-time prekey private key if used
        otpk_priv = None
        if otpk_id is not None and str(otpk_id) in self.one_time_prekey_privs:
            otpk_priv = deserialize_private_key_x25519(
                bytes.fromhex(self.one_time_prekey_privs[str(otpk_id)])
            )
            # Remove used one-time prekey
            del self.one_time_prekey_privs[str(otpk_id)]

        # X3DH receiver computation
        shared_secret = x3dh_receiver_compute(
            receiver_identity_priv_x=self.identity_priv_x,
            receiver_signed_prekey_priv=self.signed_prekey_priv,
            sender_identity_pub_x=sender_identity_x_pub,
            sender_ephemeral_pub=sender_ephemeral_pub,
            receiver_one_time_prekey_priv=otpk_priv,
        )

        # Initialize Double Ratchet as receiver
        ratchet = DoubleRatchet(
            root_key=shared_secret,
            dh_self_priv=self.signed_prekey_priv,
            dh_remote_pub=None,
            is_initiator=False,
        )

        self.ratchet_sessions[sender_username] = ratchet

        # Store contact identity key for key change detection
        self.contacts.setdefault(sender_username, {})
        self.contacts[sender_username]["identity_key_pub"] = x3dh_params.get(
            "identity_ed_pub", ""
        )

        self._save_state()
        return True

    # ============================================================
    # Message Encryption / Decryption
    # ============================================================

    def _encrypt_message(self, peer_username: str, plaintext: str,
                         ttl_seconds: int = None) -> dict:
        """
        Encrypt a message for a peer using the Double Ratchet.

        Returns the encrypted message dict ready for sending.
        """
        # Fetch pending messages first to pick up any incoming X3DH sessions
        # before we try to establish our own
        if peer_username not in self.ratchet_sessions:
            self._fetch_pending_messages()

        if peer_username not in self.ratchet_sessions:
            if not self._establish_session(peer_username):
                return None

        ratchet = self.ratchet_sessions[peer_username]

        # Build associated data (AD): sender + receiver + message UUID + TTL
        message_uuid = str(uuid.uuid4())
        ad_dict = {
            "sender": self.username,
            "receiver": peer_username,
            "message_uuid": message_uuid,
            "ttl_seconds": ttl_seconds,
            "timestamp": time.time(),
        }
        associated_data = json.dumps(ad_dict, sort_keys=True).encode("utf-8")

        # Encrypt with Double Ratchet
        encrypted = ratchet.ratchet_encrypt(
            plaintext.encode("utf-8"), associated_data
        )

        # Build the message payload
        payload = {
            "message_uuid": message_uuid,
            "ratchet_message": encrypted,
            "associated_data": ad_dict,
        }

        # Include X3DH params only if WE initiated the session (not receiver)
        # and this is the first message in this session
        contact_info = self.contacts.get(peer_username, {})
        is_initiator = ratchet.is_initiator
        already_sent_x3dh = contact_info.get("x3dh_params_sent", False)

        if is_initiator and not already_sent_x3dh:
            payload["x3dh_params"] = {
                "identity_pub": contact_info.get("x3dh_identity_pub", ""),
                "identity_ed_pub": serialize_public_key_ed25519(
                    self.identity_pub_ed
                ).hex(),
                "ephemeral_pub": contact_info.get("x3dh_ephemeral_pub", ""),
                "one_time_prekey_id": contact_info.get("one_time_prekey_id"),
            }
            self.contacts.setdefault(peer_username, {})
            self.contacts[peer_username]["x3dh_params_sent"] = True

        self._save_state()
        return {
            "ciphertext": json.dumps(payload),
            "message_uuid": message_uuid,
            "ttl_seconds": ttl_seconds,
        }

    def _decrypt_message(self, sender_username: str, ciphertext_json: str) -> dict:
        """
        Decrypt a message from a peer.

        Returns the decrypted message dict or None on failure.
        """
        try:
            payload = json.loads(ciphertext_json)
        except json.JSONDecodeError:
            print(f"[ERROR] Malformed message from {sender_username}")
            return None

        message_uuid = payload.get("message_uuid", "")

        # Replay protection (R9, R22): reject duplicate messages
        if message_uuid in self.seen_message_uuids:
            return None  # Silently ignore replayed message

        # Handle X3DH session setup for incoming initial message
        if "x3dh_params" in payload:
            if sender_username in self.ratchet_sessions:
                # Session conflict: both sides initiated X3DH independently.
                # Resolve by letting the receiver accept the sender's session.
                # Drop our outgoing session and rebuild from sender's params.
                del self.ratchet_sessions[sender_username]
            if not self._handle_incoming_session(sender_username, payload):
                print(f"[ERROR] Failed to establish session with {sender_username}")
                return None

        if sender_username not in self.ratchet_sessions:
            print(f"[ERROR] No session with {sender_username}")
            return None

        ratchet = self.ratchet_sessions[sender_username]
        ratchet_msg = payload.get("ratchet_message")
        ad_dict = payload.get("associated_data", {})
        associated_data = json.dumps(ad_dict, sort_keys=True).encode("utf-8")

        try:
            plaintext = ratchet.ratchet_decrypt(ratchet_msg, associated_data)
        except Exception as e:
            print(f"[ERROR] Decryption failed for message from {sender_username}: {e}")
            return None

        # Mark message as seen (replay protection)
        self.seen_message_uuids.add(message_uuid)
        if len(self.seen_message_uuids) > MAX_SEEN_UUIDS:
            self.seen_message_uuids = set(
                list(self.seen_message_uuids)[-MAX_SEEN_UUIDS:]
            )

        self._save_state()

        return {
            "message_uuid": message_uuid,
            "sender": sender_username,
            "text": plaintext.decode("utf-8"),
            "timestamp": ad_dict.get("timestamp", time.time()),
            "ttl_seconds": ad_dict.get("ttl_seconds"),
        }

    # ============================================================
    # WebSocket Real-Time Connection
    # ============================================================

    def _connect_websocket(self):
        """Establish a WebSocket connection for real-time messaging."""
        if not self.token:
            return

        try:
            self.ws_client = sio_client.Client(
                ssl_verify=False,
                logger=False,
                engineio_logger=False,
            )

            @self.ws_client.on("new_message")
            def on_new_message(data):
                self._handle_incoming_message(data)

            @self.ws_client.on("delivery_receipt")
            def on_delivery_receipt(data):
                msg_uuid = data.get("message_uuid")
                status = data.get("status", "delivered")
                self.delivery_status[msg_uuid] = status

            @self.ws_client.on("friend_request")
            def on_friend_request(data):
                print(f"\n[NOTIFICATION] Friend request from '{data.get('from')}'")
                print("  Use 'pending' to view and respond to requests.")

            @self.ws_client.on("friend_accepted")
            def on_friend_accepted(data):
                print(f"\n[NOTIFICATION] '{data.get('by')}' accepted your friend request!")

            @self.ws_client.on("message_status")
            def on_message_status(data):
                msg_uuid = data.get("message_uuid")
                status = data.get("status")
                self.delivery_status[msg_uuid] = status

            @self.ws_client.on("typing")
            def on_typing(data):
                sender = data.get("sender", "")
                print(f"\r  [{sender} is typing...]", end="", flush=True)

            self.ws_client.connect(
                self.server_url,
                transports=["websocket"],
                wait_timeout=10,
                headers={},
                auth={"token": self.token},
                socketio_path="/socket.io",
            )
            self.ws_connected = True

        except Exception as e:
            # Fallback: try with query parameter for token
            try:
                self.ws_client.connect(
                    f"{self.server_url}?token={self.token}",
                    transports=["websocket"],
                    wait_timeout=10,
                )
                self.ws_connected = True
            except Exception as e2:
                print(f"[WARN] WebSocket connection failed: {e2}")
                print("  Real-time messaging unavailable. Using HTTP polling.")
                self.ws_connected = False

    def _disconnect_websocket(self):
        """Disconnect the WebSocket connection."""
        if self.ws_client and self.ws_connected:
            try:
                self.ws_client.disconnect()
            except Exception:
                pass
            self.ws_connected = False

    def _handle_incoming_message(self, data: dict):
        """Process an incoming real-time message."""
        sender = data.get("sender", "")
        ciphertext = data.get("ciphertext", "")
        message_uuid = data.get("message_uuid", "")
        ttl_seconds = data.get("ttl_seconds")

        result = self._decrypt_message(sender, ciphertext)
        if result:
            # Store message locally
            if sender not in self.messages:
                self.messages[sender] = []
            self.messages[sender].append(result)

            # Display message
            timestamp = time.strftime(
                "%H:%M:%S", time.localtime(result["timestamp"])
            )
            ttl_str = f" [self-destruct: {ttl_seconds}s]" if ttl_seconds else ""
            print(f"\n  [{timestamp}] {sender}: {result['text']}{ttl_str}")

            # Send delivery acknowledgment
            try:
                self.session.post(
                    f"{self.server_url}/api/messages/ack",
                    json={"message_uuids": [message_uuid]},
                    timeout=5,
                )
            except Exception:
                pass

            self._save_state()

    def _fetch_pending_messages(self):
        """Fetch and process any pending offline messages."""
        try:
            resp = self.session.get(
                f"{self.server_url}/api/messages/pending",
                timeout=10,
            )
            if resp.status_code != 200:
                return

            data = resp.json()
            messages = data.get("messages", [])

            if messages:
                print(f"\n[INFO] {len(messages)} pending message(s) received.")
                ack_uuids = []
                for msg in messages:
                    result = self._decrypt_message(
                        msg["sender"], msg["ciphertext"]
                    )
                    if result:
                        if msg["sender"] not in self.messages:
                            self.messages[msg["sender"]] = []
                        self.messages[msg["sender"]].append(result)

                        timestamp = time.strftime(
                            "%H:%M:%S", time.localtime(result["timestamp"])
                        )
                        ttl = msg.get("ttl_seconds")
                        ttl_str = f" [self-destruct: {ttl}s]" if ttl else ""
                        print(f"  [{timestamp}] {msg['sender']}: {result['text']}{ttl_str}")
                        ack_uuids.append(msg["message_uuid"])

                # Acknowledge delivery
                if ack_uuids:
                    self.session.post(
                        f"{self.server_url}/api/messages/ack",
                        json={"message_uuids": ack_uuids},
                        timeout=5,
                    )
                self._save_state()
        except Exception as e:
            pass  # Silently handle errors during fetch

    # ============================================================
    # Self-Destruct Message Cleanup (R10, R11)
    # ============================================================

    def _cleanup_expired_messages(self):
        """Remove expired self-destruct messages from local storage."""
        now = time.time()
        for peer in list(self.messages.keys()):
            self.messages[peer] = [
                m for m in self.messages[peer]
                if not m.get("ttl_seconds")
                or (m["timestamp"] + m["ttl_seconds"]) > now
            ]

    # ============================================================
    # CLI Commands
    # ============================================================

    def cmd_send(self):
        """Send an encrypted message to a friend."""
        peer = input("To (username): ").strip()
        if not peer:
            return

        text = input("Message: ").strip()
        if not text:
            return

        # Optional self-destruct TTL
        ttl_input = input("Self-destruct timer (seconds, or press Enter for none): ").strip()
        ttl_seconds = None
        if ttl_input:
            try:
                ttl_seconds = int(ttl_input)
                if ttl_seconds <= 0:
                    ttl_seconds = None
            except ValueError:
                pass

        encrypted = self._encrypt_message(peer, text, ttl_seconds)
        if not encrypted:
            print("[ERROR] Failed to encrypt message.")
            return

        try:
            resp = self.session.post(
                f"{self.server_url}/api/messages/send",
                json={
                    "receiver": peer,
                    "ciphertext": encrypted["ciphertext"],
                    "message_uuid": encrypted["message_uuid"],
                    "ttl_seconds": ttl_seconds,
                },
                timeout=10,
            )
            data = resp.json()
            if resp.status_code == 200:
                status = data.get("status", "sent")
                self.delivery_status[encrypted["message_uuid"]] = status

                # Store in local messages
                if peer not in self.messages:
                    self.messages[peer] = []
                self.messages[peer].append({
                    "message_uuid": encrypted["message_uuid"],
                    "sender": self.username,
                    "text": text,
                    "timestamp": time.time(),
                    "ttl_seconds": ttl_seconds,
                    "status": status,
                })

                ttl_str = f" [self-destruct: {ttl_seconds}s]" if ttl_seconds else ""
                status_icon = "v" if status == "sent" else "vv"
                print(f"[{status_icon}] Message sent to {peer}{ttl_str} ({status})")
                self._save_state()
            else:
                print(f"[ERROR] {data.get('error', 'Send failed')}")
        except requests.exceptions.ConnectionError:
            print("[ERROR] Cannot connect to server.")

    def cmd_chat(self):
        """Open a chat session with a friend for continuous messaging."""
        peer = input("Chat with (username): ").strip()
        if not peer:
            return

        # Fetch any pending offline messages before entering chat
        self._fetch_pending_messages()
        self._cleanup_expired_messages()

        # Show chat history
        if peer in self.messages and self.messages[peer]:
            print(f"\n--- Chat with {peer} ---")
            # Pagination: show last N messages
            msgs = self.messages[peer][-DEFAULT_PAGE_SIZE:]
            for m in msgs:
                timestamp = time.strftime(
                    "%H:%M:%S", time.localtime(m["timestamp"])
                )
                sender = m.get("sender", "?")
                text = m.get("text", "")
                status = ""
                if sender == self.username:
                    msg_status = self.delivery_status.get(
                        m.get("message_uuid", ""), m.get("status", "")
                    )
                    if msg_status == "delivered":
                        status = " [vv]"
                    elif msg_status == "sent":
                        status = " [v]"
                ttl = m.get("ttl_seconds")
                ttl_str = f" [expires in {ttl}s]" if ttl else ""
                print(f"  [{timestamp}] {sender}: {text}{status}{ttl_str}")
            if len(self.messages[peer]) > DEFAULT_PAGE_SIZE:
                print(f"  ... ({len(self.messages[peer]) - DEFAULT_PAGE_SIZE} older messages)")
            print("---")

        print(f"\nChatting with {peer}. Type messages and press Enter.")
        print("Commands: /quit, /ttl N, /refresh, /history N")
        print()

        ttl_seconds = None

        while True:
            try:
                text = input(f"  [{self.username}]: ").strip()
            except (EOFError, KeyboardInterrupt):
                break

            if not text:
                continue
            if text == "/quit":
                break
            if text == "/refresh":
                self._fetch_pending_messages()
                self._cleanup_expired_messages()
                # Show new messages from this peer
                if peer in self.messages:
                    msgs = self.messages[peer][-5:]
                    for m in msgs:
                        ts = time.strftime("%H:%M:%S", time.localtime(m["timestamp"]))
                        sender = m.get("sender", "?")
                        print(f"  [{ts}] {sender}: {m.get('text','')}")
                continue
            if text.startswith("/ttl"):
                parts = text.split()
                if len(parts) == 2:
                    try:
                        ttl_seconds = int(parts[1])
                        print(f"  [Self-destruct set to {ttl_seconds}s]")
                    except ValueError:
                        print("  [Invalid TTL value]")
                elif len(parts) == 1:
                    ttl_seconds = None
                    print("  [Self-destruct disabled]")
                continue
            if text.startswith("/history"):
                # Load more history (pagination R25)
                parts = text.split()
                page_size = DEFAULT_PAGE_SIZE
                if len(parts) == 2:
                    try:
                        page_size = int(parts[1])
                    except ValueError:
                        pass
                if peer in self.messages:
                    msgs = self.messages[peer][-page_size:]
                    for m in msgs:
                        ts = time.strftime("%H:%M:%S", time.localtime(m["timestamp"]))
                        sender = m.get("sender", "?")
                        print(f"  [{ts}] {sender}: {m.get('text','')}")
                continue

            # Send the message
            encrypted = self._encrypt_message(peer, text, ttl_seconds)
            if not encrypted:
                print("  [ERROR] Encryption failed.")
                continue

            try:
                resp = self.session.post(
                    f"{self.server_url}/api/messages/send",
                    json={
                        "receiver": peer,
                        "ciphertext": encrypted["ciphertext"],
                        "message_uuid": encrypted["message_uuid"],
                        "ttl_seconds": ttl_seconds,
                    },
                    timeout=10,
                )
                data = resp.json()
                if resp.status_code == 200:
                    status = data.get("status", "sent")
                    self.delivery_status[encrypted["message_uuid"]] = status

                    if peer not in self.messages:
                        self.messages[peer] = []
                    self.messages[peer].append({
                        "message_uuid": encrypted["message_uuid"],
                        "sender": self.username,
                        "text": text,
                        "timestamp": time.time(),
                        "ttl_seconds": ttl_seconds,
                        "status": status,
                    })

                    icon = "vv" if status == "delivered" else "v"
                    print(f"  [{icon}] ({status})")
                    self._save_state()

                    # Auto-fetch new messages from peer after sending
                    self._fetch_pending_messages()
                else:
                    print(f"  [ERROR] {data.get('error', 'Send failed')}")
            except requests.exceptions.ConnectionError:
                print("  [ERROR] Connection lost.")

    def cmd_conversations(self):
        """Display conversation list with unread counters (R23, R24)."""
        try:
            resp = self.session.get(
                f"{self.server_url}/api/conversations",
                timeout=10,
            )
            if resp.status_code != 200:
                print("[ERROR] Failed to fetch conversations.")
                return

            data = resp.json()
            conversations = data.get("conversations", [])

            if not conversations:
                print("[INFO] No conversations yet.")
                return

            print("\n=== Conversations ===")
            for c in conversations:
                unread = c.get("unread_count", 0)
                last_time = c.get("last_message_time")
                time_str = ""
                if last_time:
                    time_str = time.strftime(
                        " (%Y-%m-%d %H:%M)", time.localtime(last_time)
                    )
                unread_str = f" [{unread} unread]" if unread > 0 else ""
                print(f"  {c['username']}{time_str}{unread_str}")
        except Exception as e:
            print(f"[ERROR] {e}")

    def cmd_friends(self):
        """List current friends."""
        try:
            resp = self.session.get(
                f"{self.server_url}/api/friends/list",
                timeout=10,
            )
            if resp.status_code != 200:
                print("[ERROR] Failed to fetch friends list.")
                return

            friends = resp.json().get("friends", [])
            if not friends:
                print("[INFO] No friends yet. Use 'add' to send friend requests.")
                return

            print("\n=== Friends ===")
            for f in friends:
                verified = ""
                if f["username"] in self.contacts:
                    if self.contacts[f["username"]].get("verified"):
                        verified = " [verified]"
                print(f"  {f['username']}{verified}")
        except Exception as e:
            print(f"[ERROR] {e}")

    def cmd_add_friend(self):
        """Send a friend request."""
        username = input("Username to add: ").strip()
        if not username:
            return

        try:
            resp = self.session.post(
                f"{self.server_url}/api/friends/request",
                json={"username": username},
                timeout=10,
            )
            data = resp.json()
            if resp.status_code == 200:
                print(f"[OK] {data.get('message', 'Friend request sent')}")
            else:
                print(f"[ERROR] {data.get('error', 'Failed')}")
        except Exception as e:
            print(f"[ERROR] {e}")

    def cmd_pending_requests(self):
        """View and respond to pending friend requests."""
        try:
            resp = self.session.get(
                f"{self.server_url}/api/friends/pending",
                timeout=10,
            )
            if resp.status_code != 200:
                print("[ERROR] Failed to fetch requests.")
                return

            data = resp.json()
            incoming = data.get("incoming", [])
            outgoing = data.get("outgoing", [])

            if incoming:
                print("\n=== Incoming Requests ===")
                for req in incoming:
                    ts = time.strftime(
                        "%Y-%m-%d %H:%M",
                        time.localtime(req["created_at"]),
                    )
                    print(f"  [{req['id']}] From: {req['sender']} ({ts})")

                # Prompt to accept/decline
                action = input(
                    "\nEnter request ID to respond (or press Enter to skip): "
                ).strip()
                if action:
                    choice = input("Accept or decline? (a/d): ").strip().lower()
                    if choice in ("a", "accept"):
                        self._respond_request(int(action), "accept")
                    elif choice in ("d", "decline"):
                        self._respond_request(int(action), "decline")

            if outgoing:
                print("\n=== Outgoing Requests ===")
                for req in outgoing:
                    ts = time.strftime(
                        "%Y-%m-%d %H:%M",
                        time.localtime(req["created_at"]),
                    )
                    print(f"  [{req['id']}] To: {req['receiver']} ({ts})")

            if not incoming and not outgoing:
                print("[INFO] No pending requests.")

        except Exception as e:
            print(f"[ERROR] {e}")

    def _respond_request(self, request_id: int, action: str):
        """Accept or decline a friend request."""
        try:
            resp = self.session.post(
                f"{self.server_url}/api/friends/respond",
                json={"request_id": request_id, "action": action},
                timeout=10,
            )
            data = resp.json()
            if resp.status_code == 200:
                print(f"[OK] Request {action}ed.")
            else:
                print(f"[ERROR] {data.get('error', 'Failed')}")
        except Exception as e:
            print(f"[ERROR] {e}")

    def cmd_block(self):
        """Block a user."""
        username = input("Username to block: ").strip()
        if not username:
            return

        try:
            resp = self.session.post(
                f"{self.server_url}/api/friends/block",
                json={"username": username},
                timeout=10,
            )
            data = resp.json()
            if resp.status_code == 200:
                print(f"[OK] {data.get('message', 'User blocked')}")
            else:
                print(f"[ERROR] {data.get('error', 'Failed')}")
        except Exception as e:
            print(f"[ERROR] {e}")

    def cmd_unblock(self):
        """Unblock a user."""
        username = input("Username to unblock: ").strip()
        if not username:
            return

        try:
            resp = self.session.post(
                f"{self.server_url}/api/friends/unblock",
                json={"username": username},
                timeout=10,
            )
            data = resp.json()
            if resp.status_code == 200:
                print(f"[OK] {data.get('message', 'User unblocked')}")
            else:
                print(f"[ERROR] {data.get('error', 'Failed')}")
        except Exception as e:
            print(f"[ERROR] {e}")

    def cmd_remove_friend(self):
        """Remove a friend."""
        username = input("Username to remove: ").strip()
        if not username:
            return

        try:
            resp = self.session.post(
                f"{self.server_url}/api/friends/remove",
                json={"username": username},
                timeout=10,
            )
            data = resp.json()
            if resp.status_code == 200:
                print(f"[OK] {data.get('message', 'Friend removed')}")
            else:
                print(f"[ERROR] {data.get('error', 'Failed')}")
        except Exception as e:
            print(f"[ERROR] {e}")

    def cmd_verify(self):
        """Verify a contact's identity key fingerprint (R5)."""
        peer = input("Username to verify: ").strip()
        if not peer:
            return

        if peer not in self.contacts or not self.contacts[peer].get("identity_key_pub"):
            # Fetch from server
            try:
                resp = self.session.get(
                    f"{self.server_url}/api/keys/identity/{peer}",
                    timeout=10,
                )
                if resp.status_code != 200:
                    print(f"[ERROR] Cannot fetch identity key for {peer}")
                    return
                data = resp.json()
                self.contacts.setdefault(peer, {})
                self.contacts[peer]["identity_key_pub"] = data["identity_key_pub"]
            except Exception as e:
                print(f"[ERROR] {e}")
                return

        our_key = serialize_public_key_ed25519(self.identity_pub_ed)
        their_key = bytes.fromhex(self.contacts[peer]["identity_key_pub"])

        safety_number = compute_safety_number(
            our_key, self.username, their_key, peer
        )

        print(f"\n=== Safety Number for {self.username} <-> {peer} ===")
        print(safety_number)
        print("\nCompare this with your contact through a trusted channel.")

        confirm = input("Mark as verified? (yes/no): ").strip().lower()
        if confirm == "yes":
            self.contacts[peer]["verified"] = True
            self._save_state()
            print(f"[OK] {peer} marked as verified.")

    def cmd_refresh(self):
        """Fetch new messages from server."""
        self._fetch_pending_messages()
        self._cleanup_expired_messages()
        print("[OK] Messages refreshed.")

    # ============================================================
    # Main CLI Loop
    # ============================================================

    def run(self):
        """Main CLI event loop."""
        print("=" * 60)
        print("  SecureChat - Secure E2EE Instant Messaging Client")
        print("=" * 60)
        print()

        while True:
            if not self.token:
                print("\nCommands: register, login, quit")
                cmd = input("> ").strip().lower()

                if cmd == "register":
                    self.register()
                elif cmd == "login":
                    if self.login():
                        continue
                elif cmd in ("quit", "exit", "q"):
                    break
                else:
                    print("Unknown command.")
            else:
                print(f"\n[{self.username}] Commands: chat, send, conversations, "
                      "friends, add, pending, remove, block, unblock, "
                      "verify, refresh, logout, quit")
                cmd = input("> ").strip().lower()

                if cmd == "chat":
                    self.cmd_chat()
                elif cmd == "send":
                    self.cmd_send()
                elif cmd in ("conversations", "conv"):
                    self.cmd_conversations()
                elif cmd == "friends":
                    self.cmd_friends()
                elif cmd == "add":
                    self.cmd_add_friend()
                elif cmd == "pending":
                    self.cmd_pending_requests()
                elif cmd == "remove":
                    self.cmd_remove_friend()
                elif cmd == "block":
                    self.cmd_block()
                elif cmd == "unblock":
                    self.cmd_unblock()
                elif cmd == "verify":
                    self.cmd_verify()
                elif cmd == "refresh":
                    self.cmd_refresh()
                elif cmd == "logout":
                    self.logout()
                elif cmd in ("quit", "exit", "q"):
                    self.logout()
                    break
                else:
                    print("Unknown command. Type a command from the list above.")

        print("\nGoodbye!")


# ============================================================
# Entry Point
# ============================================================

def main():
    """Start the SecureChat client."""
    import argparse

    parser = argparse.ArgumentParser(description="SecureChat E2EE Client")
    parser.add_argument(
        "--server",
        default=DEFAULT_SERVER_URL,
        help=f"Server URL (default: {DEFAULT_SERVER_URL})",
    )
    args = parser.parse_args()

    client = SecureChatClient(server_url=args.server)
    try:
        client.run()
    except KeyboardInterrupt:
        print("\n\nInterrupted. Saving state...")
        client.logout()


if __name__ == "__main__":
    main()
