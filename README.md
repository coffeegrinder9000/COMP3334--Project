# COMP3334--Project
## Project summary

Our project implements a secure 1:1 instant messaging (IM) system with end-to-end encryption (E2EE). It focuses on private peer-to-peer chat (no group chat, no multi-device sync) and includes server-assisted message relay with ciphertext store-and-forward for offline delivery. The server is treated as honest-but-curious (HbC): it follows protocols but may inspect anything it can access. The system is designed to meet the functional and security requirements described in the project specification.

## Key features

* End-to-end encrypted 1:1 messaging (client-side keying; server cannot decrypt message plaintext).
* Timed self-destruct messages (TTL support; expiry included in authenticated metadata).
* Account registration and login with password + OTP (2FA).
* Friend request workflow (request → accept/decline), contact list, blocking/removal.
* Offline messaging via ciphertext queue on the server (store-and-forward).
* Message delivery statuses: Sent and Delivered (semantics documented).
* Conversation list, unread counters, and basic pagination.
* Replay protection and message de-duplication.
* Per-device identity keypairs and fingerprint/verification UI.
* Secure transport (TLS) and secure local storage of private keys.
