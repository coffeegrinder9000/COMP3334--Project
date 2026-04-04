"""
client_storage.py - Encrypted local storage for SecureChat client.

Stores private keys, session state, ratchet state, contacts, and messages
in an encrypted JSON file protected by a key derived from the user's password.

Security properties:
  - All private keys are encrypted at rest using AES-256-GCM
  - The encryption key is derived from the user password via HKDF
  - Each write uses a fresh random nonce
"""

import os
import json
import hashlib
from typing import Optional, Dict, Any

from common.crypto_utils import aes_gcm_encrypt, aes_gcm_decrypt, hkdf_derive

STORAGE_DIR = os.path.join(os.path.dirname(__file__), "..", "client_data")


def _get_storage_path(username: str) -> str:
    """Get the encrypted storage file path for a user."""
    os.makedirs(STORAGE_DIR, exist_ok=True)
    return os.path.join(STORAGE_DIR, f"{username}.enc")


def _derive_storage_key(username: str, password: str) -> bytes:
    """Derive an encryption key for local storage from username + password."""
    material = f"{username}:{password}".encode("utf-8")
    salt = hashlib.sha256(f"SecureChat-Storage-{username}".encode()).digest()
    return hkdf_derive(material, b"SecureChat-LocalStorage", length=32, salt=salt)


def save_client_state(username: str, password: str, state: dict):
    """
    Encrypt and save client state to local storage.

    The state dict may contain:
      - identity_key_priv, identity_key_pub
      - x25519_identity_priv, x25519_identity_pub
      - signed_prekey_priv, signed_prekey_pub
      - one_time_prekey_privs: list of private keys
      - ratchet_sessions: {peer_username: ratchet_state_dict}
      - contacts: {username: {verified, identity_key_pub, ...}}
      - seen_message_uuids: list of processed message UUIDs (for dedup)
      - messages: {username: [message_dicts]}
    """
    key = _derive_storage_key(username, password)
    plaintext = json.dumps(state, indent=2).encode("utf-8")
    ciphertext = aes_gcm_encrypt(key, plaintext)

    path = _get_storage_path(username)
    with open(path, "wb") as f:
        f.write(ciphertext)


def load_client_state(username: str, password: str) -> Optional[dict]:
    """
    Load and decrypt client state from local storage.

    Returns None if the file does not exist or decryption fails.
    """
    path = _get_storage_path(username)
    if not os.path.exists(path):
        return None

    key = _derive_storage_key(username, password)
    with open(path, "rb") as f:
        ciphertext = f.read()

    try:
        plaintext = aes_gcm_decrypt(key, ciphertext)
        return json.loads(plaintext.decode("utf-8"))
    except Exception:
        return None


def delete_client_state(username: str):
    """Delete the local storage file for a user."""
    path = _get_storage_path(username)
    if os.path.exists(path):
        os.remove(path)
