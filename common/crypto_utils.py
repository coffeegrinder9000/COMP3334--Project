"""
crypto_utils.py - Cryptographic utilities for SecureChat E2EE messaging.

This module provides:
  - X25519 key exchange (Diffie-Hellman on Curve25519)
  - Ed25519 digital signatures for identity keys
  - X3DH-like session establishment protocol
  - Double Ratchet symmetric ratchet for forward secrecy
  - AES-256-GCM authenticated encryption (AEAD)
  - HKDF key derivation
  - Fingerprint / safety number generation

Libraries used:
  - cryptography (v44.0.0) for all primitives

All randomness is sourced from os.urandom (CSPRNG).
"""

import os
import hashlib
import struct
import json
import time
from typing import Tuple, Optional, Dict, Any

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

# ============================================================
# Constants
# ============================================================
AES_KEY_SIZE = 32          # AES-256
NONCE_SIZE = 12            # 96-bit nonce for AES-GCM
HKDF_INFO_ROOT = b"SecureChat-RootKey"
HKDF_INFO_CHAIN = b"SecureChat-ChainKey"
HKDF_INFO_MSG = b"SecureChat-MessageKey"
HKDF_INFO_SESSION = b"SecureChat-SessionSetup"
MAX_SKIP = 256             # Maximum skipped message keys to store


# ============================================================
# Key Generation Helpers
# ============================================================

def generate_identity_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 identity keypair for signing."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def generate_x25519_keypair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """Generate an X25519 keypair for Diffie-Hellman key exchange."""
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key_ed25519(pub: Ed25519PublicKey) -> bytes:
    """Serialize an Ed25519 public key to raw 32-byte format."""
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def deserialize_public_key_ed25519(data: bytes) -> Ed25519PublicKey:
    """Deserialize raw 32-byte Ed25519 public key."""
    return Ed25519PublicKey.from_public_bytes(data)


def serialize_public_key_x25519(pub: X25519PublicKey) -> bytes:
    """Serialize an X25519 public key to raw 32-byte format."""
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def deserialize_public_key_x25519(data: bytes) -> X25519PublicKey:
    """Deserialize raw 32-byte X25519 public key."""
    return X25519PublicKey.from_public_bytes(data)


def serialize_private_key_ed25519(priv: Ed25519PrivateKey) -> bytes:
    """Serialize Ed25519 private key to raw bytes."""
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key_ed25519(data: bytes) -> Ed25519PrivateKey:
    """Deserialize raw Ed25519 private key."""
    return Ed25519PrivateKey.from_private_bytes(data)


def serialize_private_key_x25519(priv: X25519PrivateKey) -> bytes:
    """Serialize X25519 private key to raw bytes."""
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key_x25519(data: bytes) -> X25519PrivateKey:
    """Deserialize raw X25519 private key."""
    return X25519PrivateKey.from_private_bytes(data)


# ============================================================
# Key Derivation (HKDF-SHA256)
# ============================================================

def hkdf_derive(input_key_material: bytes, info: bytes, length: int = 32,
                salt: Optional[bytes] = None) -> bytes:
    """Derive a key using HKDF-SHA256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt or b"\x00" * 32,
        info=info,
    )
    return hkdf.derive(input_key_material)


# ============================================================
# AES-256-GCM Authenticated Encryption
# ============================================================

def aes_gcm_encrypt(key: bytes, plaintext: bytes,
                    associated_data: Optional[bytes] = None) -> bytes:
    """
    Encrypt with AES-256-GCM.

    Returns: nonce (12 bytes) || ciphertext+tag
    The associated_data is authenticated but not encrypted (AAD).
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext


def aes_gcm_decrypt(key: bytes, nonce_and_ciphertext: bytes,
                    associated_data: Optional[bytes] = None) -> bytes:
    """
    Decrypt AES-256-GCM.

    Input: nonce (12 bytes) || ciphertext+tag
    Raises InvalidTag on tampered data.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"Key must be {AES_KEY_SIZE} bytes, got {len(key)}")
    nonce = nonce_and_ciphertext[:NONCE_SIZE]
    ciphertext = nonce_and_ciphertext[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)


# ============================================================
# Fingerprint / Safety Number Generation
# ============================================================

def compute_fingerprint(identity_key_bytes: bytes, user_id: str) -> str:
    """
    Compute a human-readable fingerprint (safety number) for an identity key.

    The fingerprint is a 60-digit numeric string derived from hashing the
    identity public key concatenated with the user identifier.
    """
    data = user_id.encode("utf-8") + identity_key_bytes
    # Iterative hashing for fingerprint stability (similar to Signal)
    digest = data
    for _ in range(5200):
        digest = hashlib.sha512(digest + identity_key_bytes).digest()
    # Convert first 30 bytes to 60 decimal digits (each 2 bytes -> 5 digits)
    result = ""
    for i in range(0, 30, 2):
        val = struct.unpack(">H", digest[i : i + 2])[0] % 100000
        result += f"{val:05d}"
    # Format as groups of 5 digits separated by spaces
    return " ".join(result[i : i + 5] for i in range(0, len(result), 5))


def compute_safety_number(
    our_identity_key: bytes, our_user_id: str,
    their_identity_key: bytes, their_user_id: str,
) -> str:
    """
    Compute a combined safety number for a conversation between two users.
    The result is deterministic and identical for both parties.
    """
    our_fp = compute_fingerprint(our_identity_key, our_user_id)
    their_fp = compute_fingerprint(their_identity_key, their_user_id)
    # Canonical order: smaller fingerprint first
    if our_fp < their_fp:
        return our_fp + "\n" + their_fp
    else:
        return their_fp + "\n" + our_fp


# ============================================================
# X3DH-like Key Agreement Protocol
# ============================================================

def x3dh_sender_compute(
    sender_identity_priv_x: X25519PrivateKey,
    sender_ephemeral_priv: X25519PrivateKey,
    receiver_identity_pub_x: X25519PublicKey,
    receiver_signed_prekey_pub: X25519PublicKey,
    receiver_one_time_prekey_pub: Optional[X25519PublicKey] = None,
) -> bytes:
    """
    X3DH sender side: compute the shared secret from 3 or 4 DH exchanges.

    DH1 = DH(sender_identity, receiver_signed_prekey)
    DH2 = DH(sender_ephemeral, receiver_identity)
    DH3 = DH(sender_ephemeral, receiver_signed_prekey)
    DH4 = DH(sender_ephemeral, receiver_one_time_prekey) [optional]

    The shared secret is derived via HKDF over the concatenation of all DH outputs.
    """
    dh1 = sender_identity_priv_x.exchange(receiver_signed_prekey_pub)
    dh2 = sender_ephemeral_priv.exchange(receiver_identity_pub_x)
    dh3 = sender_ephemeral_priv.exchange(receiver_signed_prekey_pub)

    dh_concat = dh1 + dh2 + dh3
    if receiver_one_time_prekey_pub is not None:
        dh4 = sender_ephemeral_priv.exchange(receiver_one_time_prekey_pub)
        dh_concat += dh4

    return hkdf_derive(dh_concat, HKDF_INFO_SESSION, length=64)


def x3dh_receiver_compute(
    receiver_identity_priv_x: X25519PrivateKey,
    receiver_signed_prekey_priv: X25519PrivateKey,
    sender_identity_pub_x: X25519PublicKey,
    sender_ephemeral_pub: X25519PublicKey,
    receiver_one_time_prekey_priv: Optional[X25519PrivateKey] = None,
) -> bytes:
    """
    X3DH receiver side: compute the same shared secret.
    """
    dh1 = receiver_signed_prekey_priv.exchange(sender_identity_pub_x)
    dh2 = receiver_identity_priv_x.exchange(sender_ephemeral_pub)
    dh3 = receiver_signed_prekey_priv.exchange(sender_ephemeral_pub)

    dh_concat = dh1 + dh2 + dh3
    if receiver_one_time_prekey_priv is not None:
        dh4 = receiver_one_time_prekey_priv.exchange(sender_ephemeral_pub)
        dh_concat += dh4

    return hkdf_derive(dh_concat, HKDF_INFO_SESSION, length=64)


# ============================================================
# Double Ratchet Implementation
# ============================================================

class DoubleRatchet:
    """
    Simplified Double Ratchet for E2EE messaging with forward secrecy.

    Each ratchet state contains:
      - root_key: 32-byte key ratcheted on each DH exchange
      - send_chain_key / recv_chain_key: chain keys for symmetric ratchet
      - send_count / recv_count: message counters
      - dh_self: our current ratchet keypair (X25519)
      - dh_remote: their current ratchet public key
      - skipped_keys: dict of (ratchet_pub_hex, counter) -> message_key
    """

    def __init__(
        self,
        root_key: bytes,
        dh_self_priv: X25519PrivateKey,
        dh_remote_pub: Optional[X25519PublicKey],
        is_initiator: bool,
    ):
        """
        Initialize the Double Ratchet.

        Args:
            root_key: 64-byte initial shared secret from X3DH
            dh_self_priv: Our current ratchet X25519 private key
            dh_remote_pub: Their current ratchet public key (None for receiver init)
            is_initiator: True if we initiated the session (sender in X3DH)
        """
        self.is_initiator = is_initiator
        self.dh_self_priv = dh_self_priv
        self.dh_self_pub = dh_self_priv.public_key()
        self.dh_remote_pub = dh_remote_pub

        # Split root_key into root_key and initial chain key
        self.root_key = root_key[:32]
        initial_chain = root_key[32:]

        if is_initiator:
            # Initiator has the remote pub, do initial DH ratchet
            if dh_remote_pub is not None:
                self.root_key, self.send_chain_key = self._kdf_rk(
                    self.root_key,
                    self.dh_self_priv.exchange(dh_remote_pub),
                )
            else:
                self.send_chain_key = initial_chain
            self.recv_chain_key = initial_chain
        else:
            # Receiver waits for first message to perform DH ratchet
            self.send_chain_key = initial_chain
            self.recv_chain_key = initial_chain

        self.send_count = 0
        self.recv_count = 0
        self.prev_send_count = 0
        self.skipped_keys: Dict[str, bytes] = {}  # (pub_hex, counter) -> key

    def _kdf_rk(self, root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
        """Root key KDF: derive new root key and chain key from DH output."""
        derived = hkdf_derive(root_key + dh_output, HKDF_INFO_ROOT, length=64)
        return derived[:32], derived[32:]

    def _kdf_ck(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """Chain key KDF: derive next chain key and message key."""
        new_chain = hkdf_derive(chain_key, HKDF_INFO_CHAIN, length=32)
        msg_key = hkdf_derive(chain_key, HKDF_INFO_MSG, length=32)
        return new_chain, msg_key

    def ratchet_encrypt(self, plaintext: bytes, associated_data: bytes) -> dict:
        """
        Encrypt a message with the Double Ratchet.

        Returns a dict with:
          - header: {dh_pub, prev_count, msg_count}
          - ciphertext: AES-256-GCM encrypted data
        """
        self.send_chain_key, msg_key = self._kdf_ck(self.send_chain_key)

        header = {
            "dh_pub": serialize_public_key_x25519(self.dh_self_pub).hex(),
            "prev_count": self.prev_send_count,
            "msg_count": self.send_count,
        }

        # Build AD: header JSON + external associated data
        header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")
        full_ad = header_bytes + associated_data

        ciphertext = aes_gcm_encrypt(msg_key, plaintext, full_ad)
        self.send_count += 1

        return {
            "header": header,
            "ciphertext": ciphertext.hex(),
        }

    def ratchet_decrypt(self, message: dict, associated_data: bytes) -> bytes:
        """
        Decrypt a message with the Double Ratchet.

        Handles DH ratchet steps and out-of-order message decryption.
        """
        header = message["header"]
        ciphertext = bytes.fromhex(message["ciphertext"])
        dh_pub_hex = header["dh_pub"]
        msg_count = header["msg_count"]

        header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")
        full_ad = header_bytes + associated_data

        # Check skipped keys first
        skip_key = f"{dh_pub_hex}:{msg_count}"
        if skip_key in self.skipped_keys:
            msg_key = self.skipped_keys.pop(skip_key)
            return aes_gcm_decrypt(msg_key, ciphertext, full_ad)

        dh_pub = deserialize_public_key_x25519(bytes.fromhex(dh_pub_hex))

        # Check if we need a DH ratchet step
        current_remote_hex = (
            serialize_public_key_x25519(self.dh_remote_pub).hex()
            if self.dh_remote_pub
            else None
        )

        if dh_pub_hex != current_remote_hex:
            # Skip any remaining messages in current receiving chain
            self._skip_messages(current_remote_hex, self.recv_count, msg_count)
            # Perform DH ratchet
            self._dh_ratchet(dh_pub)

        # Skip messages if counter is ahead
        while self.recv_count < msg_count:
            self.recv_chain_key, skipped_key = self._kdf_ck(self.recv_chain_key)
            sk = f"{dh_pub_hex}:{self.recv_count}"
            self.skipped_keys[sk] = skipped_key
            self.recv_count += 1
            if len(self.skipped_keys) > MAX_SKIP:
                # Remove oldest
                oldest = next(iter(self.skipped_keys))
                del self.skipped_keys[oldest]

        self.recv_chain_key, msg_key = self._kdf_ck(self.recv_chain_key)
        self.recv_count += 1

        return aes_gcm_decrypt(msg_key, ciphertext, full_ad)

    def _skip_messages(self, dh_pub_hex: Optional[str], start: int, until: int):
        """Store skipped message keys for out-of-order decryption."""
        if dh_pub_hex is None:
            return
        count = start
        chain_key = self.recv_chain_key
        while count < until and len(self.skipped_keys) < MAX_SKIP:
            chain_key, msg_key = self._kdf_ck(chain_key)
            sk = f"{dh_pub_hex}:{count}"
            self.skipped_keys[sk] = msg_key
            count += 1
        self.recv_chain_key = chain_key
        self.recv_count = until

    def _dh_ratchet(self, new_remote_pub: X25519PublicKey):
        """Perform a DH ratchet step with a new remote public key."""
        self.dh_remote_pub = new_remote_pub
        self.prev_send_count = self.send_count
        self.send_count = 0
        self.recv_count = 0

        # Receiving chain ratchet
        dh_recv = self.dh_self_priv.exchange(self.dh_remote_pub)
        self.root_key, self.recv_chain_key = self._kdf_rk(self.root_key, dh_recv)

        # Generate new DH keypair for sending
        self.dh_self_priv = X25519PrivateKey.generate()
        self.dh_self_pub = self.dh_self_priv.public_key()

        # Sending chain ratchet
        dh_send = self.dh_self_priv.exchange(self.dh_remote_pub)
        self.root_key, self.send_chain_key = self._kdf_rk(self.root_key, dh_send)

    def export_state(self) -> dict:
        """Export ratchet state for persistent storage."""
        state = {
            "root_key": self.root_key.hex(),
            "send_chain_key": self.send_chain_key.hex(),
            "recv_chain_key": self.recv_chain_key.hex(),
            "send_count": self.send_count,
            "recv_count": self.recv_count,
            "prev_send_count": self.prev_send_count,
            "is_initiator": self.is_initiator,
            "dh_self_priv": serialize_private_key_x25519(self.dh_self_priv).hex(),
            "dh_self_pub": serialize_public_key_x25519(self.dh_self_pub).hex(),
            "dh_remote_pub": (
                serialize_public_key_x25519(self.dh_remote_pub).hex()
                if self.dh_remote_pub
                else None
            ),
            "skipped_keys": {k: v.hex() for k, v in self.skipped_keys.items()},
        }
        return state

    @classmethod
    def from_state(cls, state: dict) -> "DoubleRatchet":
        """Restore ratchet from exported state."""
        dh_self_priv = deserialize_private_key_x25519(
            bytes.fromhex(state["dh_self_priv"])
        )
        dh_remote_pub = (
            deserialize_public_key_x25519(bytes.fromhex(state["dh_remote_pub"]))
            if state["dh_remote_pub"]
            else None
        )
        # Create instance with dummy init, then override fields
        ratchet = cls.__new__(cls)
        ratchet.root_key = bytes.fromhex(state["root_key"])
        ratchet.send_chain_key = bytes.fromhex(state["send_chain_key"])
        ratchet.recv_chain_key = bytes.fromhex(state["recv_chain_key"])
        ratchet.send_count = state["send_count"]
        ratchet.recv_count = state["recv_count"]
        ratchet.prev_send_count = state["prev_send_count"]
        ratchet.is_initiator = state["is_initiator"]
        ratchet.dh_self_priv = dh_self_priv
        ratchet.dh_self_pub = dh_self_priv.public_key()
        ratchet.dh_remote_pub = dh_remote_pub
        ratchet.skipped_keys = {
            k: bytes.fromhex(v) for k, v in state["skipped_keys"].items()
        }
        return ratchet
