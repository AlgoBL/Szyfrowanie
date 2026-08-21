"""
crypto/key_manager.py – Key pair generation, storage and loading.

Key pairs are stored as JSON files in the keys/ directory.
Private keys are ALWAYS protected with Argon2id-derived AES-256-GCM encryption.
Using an empty password is allowed but discouraged.

Key file format ({name}.json):
{
  "name": "alice",
  "created": "ISO-8601 timestamp",
  "x25519_pub": "hex",
  "x25519_priv_enc": "hex",          # Argon2id → AES-GCM encrypted
  "p521_pub": "hex",                  # compressed point, only if paranoid
  "p521_priv_enc": "hex",             # only if paranoid
  "ed25519_pub": "hex",
  "ed25519_priv_enc": "hex",
  "argon2_salt": "hex",              # shared Argon2id salt for all keys in this pair
  "argon2_time": int,
  "argon2_memory": int,
  "argon2_threads": int,
}
"""

from __future__ import annotations

import json
import os
import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from argon2.low_level import hash_secret_raw, Type as Argon2Type

from .aes_cipher import encrypt_small, decrypt_small, KEY_SIZE
from .ecc_core import (
    generate_x25519_keypair,
    generate_p521_keypair,
    generate_ed25519_keypair,
)

# ── Argon2id parameters (OWASP recommended / strong) ──────────────────────────
ARGON2_TIME_COST   = 3
ARGON2_MEMORY_COST = 65536   # 64 MiB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN    = 32      # Produces 256-bit key
ARGON2_SALT_LEN    = 32


class KeyManager:
    """Manages ECC key pairs stored on disk, protected by Argon2id."""

    def __init__(self, keys_dir: Path):
        self.keys_dir = keys_dir
        self.keys_dir.mkdir(parents=True, exist_ok=True)

    # ── Private: Argon2id key derivation ──────────────────────────────────────

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive a 256-bit key from *password* + *salt* using Argon2id."""
        return hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            type=Argon2Type.ID,
        )

    def _encrypt_key_bytes(self, password: str, salt: bytes, key_bytes: bytes) -> str:
        """Return hex of Argon2id-encrypted key material."""
        kek = self._derive_key(password, salt)
        return encrypt_small(kek, key_bytes).hex()

    def _decrypt_key_bytes(self, password: str, salt: bytes, enc_hex: str) -> bytes:
        """Decrypt and return raw key bytes."""
        kek = self._derive_key(password, salt)
        return decrypt_small(kek, bytes.fromhex(enc_hex))

    # ── Public API ─────────────────────────────────────────────────────────────

    def generate(self, name: str, password: str, paranoid: bool = False) -> Dict[str, str]:
        """
        Generate a new key pair and save it.

        Returns:
            Dict with public key hexes (safe to display).
        """
        if self._key_path(name).exists():
            raise FileExistsError(f"Key '{name}' already exists.")

        argon2_salt = os.urandom(ARGON2_SALT_LEN)

        x25519_priv, x25519_pub = generate_x25519_keypair()
        ed25519_priv, ed25519_pub = generate_ed25519_keypair()

        record: Dict[str, Any] = {
            'name': name,
            'created': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'paranoid': paranoid,
            'x25519_pub': x25519_pub.hex(),
            'x25519_priv_enc': self._encrypt_key_bytes(password, argon2_salt, x25519_priv),
            'ed25519_pub': ed25519_pub.hex(),
            'ed25519_priv_enc': self._encrypt_key_bytes(password, argon2_salt, ed25519_priv),
            'argon2_salt': argon2_salt.hex(),
            'argon2_time': ARGON2_TIME_COST,
            'argon2_memory': ARGON2_MEMORY_COST,
            'argon2_threads': ARGON2_PARALLELISM,
        }

        if paranoid:
            p521_priv, p521_pub = generate_p521_keypair()
            record['p521_pub'] = p521_pub.hex()
            record['p521_priv_enc'] = self._encrypt_key_bytes(password, argon2_salt, p521_priv)

        self._key_path(name).write_text(json.dumps(record, indent=2), encoding='utf-8')

        return {
            'name': name,
            'x25519_pub': x25519_pub.hex(),
            'ed25519_pub': ed25519_pub.hex(),
            'p521_pub': record.get('p521_pub', ''),
        }

    def list_keys(self) -> list[str]:
        """Return names of all stored key pairs."""
        return [p.stem for p in self.keys_dir.glob('*.json')]

    def get_public_info(self, name: str) -> Dict[str, Any]:
        """Return public information about a key pair (no password needed)."""
        record = self._load_record(name)
        return {
            'name': record['name'],
            'created': record['created'],
            'paranoid': record.get('paranoid', False),
            'x25519_pub': record['x25519_pub'],
            'ed25519_pub': record['ed25519_pub'],
            'p521_pub': record.get('p521_pub', ''),
        }

    def load_x25519_private(self, name: str, password: str) -> bytes:
        """Return raw X25519 private key bytes."""
        record = self._load_record(name)
        salt = bytes.fromhex(record['argon2_salt'])
        return self._decrypt_key_bytes(password, salt, record['x25519_priv_enc'])

    def load_x25519_public(self, name: str) -> bytes:
        record = self._load_record(name)
        return bytes.fromhex(record['x25519_pub'])

    def load_p521_private(self, name: str, password: str) -> bytes:
        record = self._load_record(name)
        if 'p521_priv_enc' not in record:
            raise KeyError(f"Key '{name}' has no P-521 component.")
        salt = bytes.fromhex(record['argon2_salt'])
        return self._decrypt_key_bytes(password, salt, record['p521_priv_enc'])

    def load_p521_public(self, name: str) -> bytes:
        record = self._load_record(name)
        return bytes.fromhex(record['p521_pub'])

    def load_ed25519_private(self, name: str, password: str) -> bytes:
        record = self._load_record(name)
        salt = bytes.fromhex(record['argon2_salt'])
        return self._decrypt_key_bytes(password, salt, record['ed25519_priv_enc'])

    def load_ed25519_public(self, name: str) -> bytes:
        record = self._load_record(name)
        return bytes.fromhex(record['ed25519_pub'])

    def delete(self, name: str) -> None:
        """Permanently delete a key pair."""
        path = self._key_path(name)
        if not path.exists():
            raise FileNotFoundError(f"Key '{name}' not found.")
        path.unlink()

    def export_public_pem(self, name: str) -> str:
        """Export the X25519 public key as PEM for sharing with others."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        from cryptography.hazmat.primitives import serialization

        pub_bytes = self.load_x25519_public(name)
        pub_key = X25519PublicKey.from_public_bytes(pub_bytes)
        return pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def import_public_key_from_pem(self, name: str, pem_text: str) -> str:
        """
        Import a foreign X25519 public key (PEM) as a recipient-only entry.
        Returns the raw hex public key.
        """
        from cryptography.hazmat.primitives import serialization

        pub_key = serialization.load_pem_public_key(pem_text.encode())
        pub_bytes = pub_key.public_bytes_raw()

        record = {
            'name': name,
            'created': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'paranoid': False,
            'x25519_pub': pub_bytes.hex(),
            'recipient_only': True,
            'ed25519_pub': '',
            'argon2_salt': '',
        }
        self._key_path(name).write_text(json.dumps(record, indent=2), encoding='utf-8')
        return pub_bytes.hex()

    def is_recipient_only(self, name: str) -> bool:
        """True if this is an imported public-only key (cannot decrypt)."""
        record = self._load_record(name)
        return record.get('recipient_only', False)

    # ── Private helpers ────────────────────────────────────────────────────────

    def _key_path(self, name: str) -> Path:
        return self.keys_dir / f'{name}.json'

    def _load_record(self, name: str) -> Dict[str, Any]:
        path = self._key_path(name)
        if not path.exists():
            raise FileNotFoundError(f"Key '{name}' not found in {self.keys_dir}.")
        return json.loads(path.read_text(encoding='utf-8'))
