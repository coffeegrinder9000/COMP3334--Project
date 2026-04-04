# SecureChat

SecureChat is a 1:1 end-to-end encrypted (E2EE) instant messaging system built in Python. It consists of a central relay server and a CLI-based client. The server follows an honest-but-curious (HbC) model — it faithfully stores and forwards messages but never has access to plaintext content or private keys.

This document covers the project architecture, cryptographic design, deployment instructions, and testing.

For a step-by-step user guide, see [use.md](use.md).

## Table of Contents

1. [Project Structure](#project-structure)
2. [Architecture Overview](#architecture-overview)
3. [Cryptographic Design](#cryptographic-design)
4. [Database Schema](#database-schema)
5. [Server API Reference](#server-api-reference)
6. [Security Analysis](#security-analysis)
7. [Deployment](#deployment)
8. [Testing](#testing)
9. [Dependencies](#dependencies)
10. [References](#references)

---

## Project Structure

```
code/
├── common/
│   └── crypto_utils.py       Cryptographic primitives, X3DH, Double Ratchet, AES-GCM
├── server/
│   ├── server.py             Flask + Socket.IO server application
│   └── database.py           SQLite database layer
├── client/
│   ├── client.py             CLI client application
│   └── client_storage.py     Encrypted local state persistence
├── certs/                    Auto-generated TLS certificates
├── client_data/              Per-user encrypted state files (created at runtime)
├── schema.sql                Standalone SQL file to initialize the database
├── requirements.txt          Python dependencies
├── test_crypto.py            Cryptographic module unit tests
├── test_integration.py       Server integration tests
├── README.md                 This file
└── use.md                    User guide
```

---

## Architecture Overview

The system has two components: a **server** and one or more **clients**.

### Server

The server is a Python application built on Flask (HTTP) and Flask-SocketIO (WebSocket). It runs on a single machine and listens on port 5050 over TLS. Its responsibilities include:

- **Account management**: registration (with Argon2id password hashing and TOTP secret generation), login (password + OTP verification), session token issuance and revocation.
- **Public key directory**: storing each user's Ed25519 identity public key, X25519 identity public key, signed prekey, and a pool of one-time prekeys. These are uploaded by clients and fetched by other clients during X3DH session establishment.
- **Friend request brokering**: maintaining the request/accept/decline/cancel lifecycle and the bidirectional friendship table. Non-friends cannot exchange chat messages (anti-spam).
- **Message relay and offline queue**: accepting ciphertext from senders, attempting real-time delivery via WebSocket, and queuing undelivered messages in SQLite for later retrieval. The server stores only ciphertext; it cannot decrypt anything.
- **Delivery status**: tracking whether a message has been acknowledged by the recipient and notifying the sender.
- **Self-destruct enforcement**: periodically deleting queued ciphertext whose TTL has expired (best-effort).
- **Rate limiting**: throttling registration, login, and friend request operations per IP or user.
- **Conversation metadata**: providing conversation lists ordered by last activity, with per-conversation unread counts.

The server uses SQLite with WAL mode for storage. TLS is provided via a self-signed certificate generated on first startup.

### Client

The client is a CLI application. It manages all cryptographic operations locally — the server never sees private keys or plaintext. Its responsibilities include:

- **Key generation**: on first login, the client generates an Ed25519 identity keypair (for signatures), an X25519 identity keypair (for DH), a signed prekey, and a batch of one-time prekeys. Public portions are uploaded to the server.
- **Session establishment (X3DH)**: when sending the first message to a contact, the client fetches the contact's prekey bundle from the server, verifies the signed prekey signature, and performs 3 or 4 Diffie-Hellman exchanges to derive a shared secret.
- **Message encryption (Double Ratchet)**: the shared secret seeds a Double Ratchet, which derives per-message keys via HKDF-SHA256. Each message is encrypted with AES-256-GCM. The ratchet performs a new DH exchange on each send/receive turn, providing forward secrecy.
- **Replay protection**: the client maintains a set of seen message UUIDs. Duplicates are silently dropped. The server also enforces UUID uniqueness.
- **Key change detection**: if a contact's identity key changes between sessions, the client warns the user and resets the "verified" flag.
- **Safety number verification**: the client can display a numeric fingerprint derived from both parties' identity keys. Users can compare these out-of-band to detect MITM.
- **Encrypted local storage**: all private keys, ratchet state, contacts, and message history are serialized to JSON, encrypted with AES-256-GCM using a key derived from the user's password via HKDF, and written to disk. Each write uses a fresh random nonce.

Communication between client and server uses HTTPS for REST calls and WSS for WebSocket. Due to CLI limitations (`input()` blocks the thread), incoming messages are fetched on-demand rather than displayed in real time.

---

## Cryptographic Design

### Primitives and Libraries

All cryptographic operations use the `cryptography` library (v44.0.0), which is backed by OpenSSL.

| Primitive | Algorithm | Parameters | Purpose |
|-----------|-----------|------------|---------|
| Identity signing | Ed25519 | 256-bit | Long-term identity, prekey signatures |
| Key exchange | X25519 | 256-bit | DH operations in X3DH and Double Ratchet |
| Authenticated encryption | AES-256-GCM | 256-bit key, 96-bit nonce | Message encryption with integrity |
| Key derivation | HKDF-SHA256 | RFC 5869 | Expanding DH outputs into root/chain/message keys |
| Password hashing | Argon2id | t=3, m=64MB, p=4, 16B salt, 32B hash | Server-side credential storage |
| OTP | TOTP | HMAC-SHA1, 6 digits, 30s period | Second factor authentication |
| Randomness | os.urandom | OS CSPRNG | All nonces, keys, salts |

### X3DH Session Establishment

When Alice wants to message Bob for the first time:

1. Alice fetches Bob's prekey bundle from the server: identity public key (Ed25519 + X25519), signed prekey (X25519), and optionally a one-time prekey.
2. Alice verifies the signed prekey signature using Bob's Ed25519 identity key.
3. Alice generates an ephemeral X25519 keypair.
4. Alice computes:
   - DH1 = DH(Alice_identity, Bob_signed_prekey)
   - DH2 = DH(Alice_ephemeral, Bob_identity)
   - DH3 = DH(Alice_ephemeral, Bob_signed_prekey)
   - DH4 = DH(Alice_ephemeral, Bob_one_time_prekey) — if available
5. The concatenation of DH outputs is fed into HKDF-SHA256 with info="SecureChat-SessionSetup" to produce a 64-byte shared secret.
6. The first 32 bytes become the initial root key; the second 32 bytes become the initial chain key.
7. Alice's first message includes her X3DH parameters (identity pub, ephemeral pub, one-time prekey ID) so Bob can perform the same computation.

Bob performs the symmetric DH operations using his private keys, arrives at the same shared secret, and initializes his ratchet as the receiver.

One-time prekeys are consumed on first use (the server marks them as used). This prevents replay of the initial key exchange.

### Double Ratchet

After X3DH, both parties maintain a Double Ratchet session:

- **Symmetric ratchet**: each message advances a chain key via HKDF. A separate message key is derived for each message. Old chain keys are overwritten, so compromising the current state does not reveal past message keys (forward secrecy).
- **DH ratchet**: on each send/receive direction change, the sender generates a fresh X25519 keypair and performs a new DH with the receiver's last ratchet public key. The output ratchets the root key forward, producing a new chain key. This limits the damage of a state compromise to at most one "turn" of messages.
- **Out-of-order handling**: the ratchet stores up to 256 skipped message keys, indexed by (DH public key, counter), so messages arriving out of order can still be decrypted.

### Authenticated Associated Data (AAD)

Every AES-256-GCM encryption binds the following into the AAD:

- The Double Ratchet header (sender's current DH public key, previous chain length, message counter)
- Sender and receiver usernames
- Message UUID
- TTL (self-destruct duration, if set)
- Timestamp

Tampering with any of these fields causes decryption to fail (GCM tag verification).

### Session Conflict Resolution

If both users try to send their first message simultaneously (each performing X3DH independently with the other's prekeys), they end up with incompatible sessions. The client resolves this by always accepting an incoming X3DH initial message: if a message arrives with `x3dh_params` and a local session already exists, the local session is discarded and rebuilt from the incoming parameters. The first message sent by the other party that triggered the conflict will need to be re-sent.

---

## Database Schema

The server uses SQLite. The schema (also available as `schema.sql`) contains 10 tables:

- **users**: id, username (unique), password_hash (Argon2id), otp_secret, created_at, is_active
- **sessions**: user_id, token (unique), created_at, expires_at, is_valid
- **identity_keys**: user_id (PK), identity_key_pub (Ed25519 hex), x25519_identity_pub (hex)
- **signed_prekeys**: user_id, prekey_pub (hex), signature (hex)
- **one_time_prekeys**: user_id, prekey_id, prekey_pub (hex), used (0/1)
- **friend_requests**: sender_id, receiver_id, status (pending/accepted/declined/cancelled)
- **friends**: user_id, friend_id (bidirectional, composite PK)
- **blocked_users**: user_id, blocked_id (composite PK)
- **messages**: message_uuid (unique), sender_id, receiver_id, ciphertext, ttl_seconds, delivered, expired
- **rate_limits**: identifier, action, timestamp

The database is auto-created on first server startup. It can also be manually initialized with `sqlite3 server/securechat.db < schema.sql`.

---

## Server API Reference

All endpoints are served over HTTPS. Authentication is via a Bearer token in the `Authorization` header.

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/register | Register a new account. Returns OTP secret. |
| POST | /api/login | Login with password + OTP. Returns session token. |
| POST | /api/logout | Invalidate the current session token. |

### Key Management

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/keys/upload | Upload identity keys, signed prekey, and one-time prekeys. |
| GET | /api/keys/bundle/\<username\> | Fetch a user's prekey bundle for X3DH. Consumes one one-time prekey. |
| GET | /api/keys/identity/\<username\> | Fetch a user's Ed25519 identity public key. |

### Friends

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/friends/request | Send a friend request. |
| POST | /api/friends/respond | Accept or decline a friend request. |
| POST | /api/friends/cancel | Cancel a pending outgoing request. |
| GET | /api/friends/pending | List pending incoming and outgoing requests. |
| GET | /api/friends/list | List all friends. |
| POST | /api/friends/remove | Remove a friend. |
| POST | /api/friends/block | Block a user. |
| POST | /api/friends/unblock | Unblock a user. |

### Messaging

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/messages/send | Submit a ciphertext message for delivery. |
| GET | /api/messages/pending | Fetch undelivered messages (offline queue). |
| POST | /api/messages/ack | Acknowledge delivery of messages (marks them as delivered). |
| GET | /api/conversations | List conversations with last activity time and unread counts. |

### WebSocket Events

| Event | Direction | Description |
|-------|-----------|-------------|
| connect | Client→Server | Authenticate with token query param. Server delivers queued messages. |
| new_message | Server→Client | Real-time message delivery. |
| delivery_receipt | Server→Client | Notification that a sent message was delivered. |
| friend_request | Server→Client | Notification of an incoming friend request. |
| friend_accepted | Server→Client | Notification that a friend request was accepted. |
| send_message | Client→Server | Send a message via WebSocket (alternative to HTTP). |

---

## Security Analysis

### What the server cannot do

- **Read messages**: all message content is encrypted with AES-256-GCM using keys derived through X3DH and Double Ratchet. The server stores only ciphertext.
- **Forge messages**: AEAD tags bind sender/receiver/UUID/TTL into the ciphertext. Tampering is detected on decryption.
- **Recover past messages after a key compromise**: the Double Ratchet provides forward secrecy through DH ratchet steps and chain key advancement.
- **Replay messages**: clients track seen UUIDs; the server enforces UUID uniqueness in the database.

### What the server can observe (metadata)

Under the HbC model, the server necessarily learns:

- Who is registered and who is friends with whom (the social graph).
- When messages are sent and delivered (timestamps).
- The size of each ciphertext.
- When users are online (WebSocket connection events).
- Delivery acknowledgment timing.

These metadata leaks are inherent to any client-server relay architecture without onion routing or padding.

### Limitations

- Self-destruct messages are best-effort. A malicious client can screenshot or save content before deletion. The server deletes expired ciphertext periodically, but timing is approximate.
- The self-signed TLS certificate does not prevent a network attacker who can install a trusted root CA. In production, a CA-signed certificate should be used.
- CLI `input()` is blocking, so incoming messages are not displayed in real time. They are fetched when the user sends a message or manually refreshes.
- If both users send their first message simultaneously, the session conflict resolution discards one session. The first message from the "losing" side will fail to decrypt and must be re-sent.

### Abuse Controls

- Registration: 5 attempts per IP per hour.
- Login: 10 attempts per IP+username per 5 minutes.
- Friend requests: 20 per user per minute.
- Non-friends cannot send chat messages (only friend requests).
- Blocked users cannot send messages or friend requests.
- Password policy: minimum 8 characters.
- Session tokens expire after 24 hours.

---

## Deployment

### Prerequisites

- Python 3.9 or later
- pip
- SQLite 3 (bundled with Python)

### Windows 11

```powershell
# Install Python from https://www.python.org/downloads/
# Check "Add Python to PATH" during installation.

python --version
pip --version

cd path\to\code
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# Terminal 1: start the server
python -m server.server

# Terminal 2: start a client
python -m client.client

# Terminal 3: start a second client for testing
python -m client.client
```

### Ubuntu Linux / macOS

```bash
# Ubuntu: install Python if needed
sudo apt update && sudo apt install -y python3 python3-pip python3-venv

cd /path/to/code
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Terminal 1
python -m server.server

# Terminal 2
python -m client.client

# Terminal 3
python -m client.client
```

The server auto-generates a self-signed TLS certificate in `certs/` and initializes the SQLite database on first run. No manual setup is needed.

To connect a client to a server on another machine:
```bash
python -m client.client --server https://192.168.1.100:5050
```

---

## Testing

### Unit Tests (Cryptographic Module)

```bash
python test_crypto.py
```

Covers: key generation, AES-GCM round-trip, AAD tamper rejection, safety number computation, X3DH agreement (sender == receiver), Double Ratchet bidirectional messaging, state export/import, replay detection.

### Integration Tests (Server API)

```bash
python test_integration.py
```

Starts an in-process server on port 5001 with a temporary database and tests: registration, duplicate rejection, password validation, login with correct/wrong password/OTP, key upload, prekey bundle retrieval, friend request lifecycle, anti-spam enforcement, message send/dedup/delivery/ack, conversation list, block/unblock, logout/token invalidation, and server-side data inspection (verifying only ciphertext and Argon2id hashes are stored).

### Manual Verification

After sending messages, inspect the database directly:

```bash
sqlite3 server/securechat.db "SELECT message_uuid, ciphertext FROM messages LIMIT 3;"
```

Only hex-encoded ciphertext is visible. No plaintext.

```bash
sqlite3 server/securechat.db "SELECT username, password_hash FROM users;"
```

Passwords are stored as Argon2id hashes (e.g., `$argon2id$v=19$m=65536,t=3,p=4$...`).

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| flask | 3.1.0 | HTTP server framework |
| flask-socketio | 5.5.1 | WebSocket support |
| simple-websocket | 1.1.0 | WebSocket transport for threading mode |
| cryptography | 44.0.0 | All cryptographic primitives (Ed25519, X25519, AES-GCM, HKDF) |
| pyotp | 2.9.0 | TOTP generation and verification |
| qrcode | 8.0 | OTP URI encoding (optional, for QR display) |
| argon2-cffi | 23.1.0 | Argon2id password hashing |
| python-socketio[client] | 5.12.1 | Client-side WebSocket |
| requests | 2.32.3 | Client-side HTTP |

---

## References

- Signal Protocol specification: https://signal.org/docs/
- X3DH Key Agreement Protocol: https://signal.org/docs/specifications/x3dh/
- Double Ratchet Algorithm: https://signal.org/docs/specifications/doubleratchet/
- HKDF (RFC 5869): https://tools.ietf.org/html/rfc5869
- AES-GCM (NIST SP 800-38D): https://csrc.nist.gov/publications/detail/sp/800-38d/final
- Argon2 (RFC 9106): https://tools.ietf.org/html/rfc9106
- TOTP (RFC 6238): https://tools.ietf.org/html/rfc6238
- PyCA cryptography library: https://cryptography.io/
