"""
crypto/aes_cipher.py – AES-256-GCM symmetric encryption helpers.

All operations use authenticated encryption (AEAD) via GCM mode.
The 16-byte authentication tag is appended to / expected at the end
of every ciphertext blob.
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Public API ─────────────────────────────────────────────────────────────────

KEY_SIZE = 32  # 256-bit
IV_SIZE  = 12  # 96-bit recommended for GCM
TAG_SIZE = 16  # 128-bit auth tag


def generate_key() -> bytes:
    """Return a cryptographically random 256-bit AES key."""
    return os.urandom(KEY_SIZE)


def generate_iv() -> bytes:
    """Return a cryptographically random 96-bit IV (nonce) for GCM."""
    return os.urandom(IV_SIZE)


def encrypt(key: bytes, iv: bytes, plaintext: bytes,
            associated_data: bytes | None = None) -> bytes:
    """
    Encrypt *plaintext* with AES-256-GCM.

    Args:
        key:             32-byte AES key.
        iv:              12-byte nonce.
        plaintext:       Arbitrary-length bytes to encrypt.
        associated_data: Optional AAD authenticated but not encrypted.

    Returns:
        ciphertext || tag  (tag is the last 16 bytes).
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f'AES key must be {KEY_SIZE} bytes, got {len(key)}.')
    if len(iv) != IV_SIZE:
        raise ValueError(f'GCM IV must be {IV_SIZE} bytes, got {len(iv)}.')

    aesgcm = AESGCM(key)
    return aesgcm.encrypt(iv, plaintext, associated_data)


def decrypt(key: bytes, iv: bytes, ciphertext_with_tag: bytes,
            associated_data: bytes | None = None) -> bytes:
    """
    Decrypt *ciphertext_with_tag* with AES-256-GCM.

    Raises:
        cryptography.exceptions.InvalidTag if authentication fails.
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f'AES key must be {KEY_SIZE} bytes.')
    if len(iv) != IV_SIZE:
        raise ValueError(f'GCM IV must be {IV_SIZE} bytes.')

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext_with_tag, associated_data)


def encrypt_small(key: bytes, plaintext: bytes,
                  associated_data: bytes | None = None) -> bytes:
    """
    Convenience: generate a fresh IV, encrypt, and prepend IV to result.

    Returns:
        iv (12 bytes) || ciphertext || tag
    """
    iv = generate_iv()
    ct = encrypt(key, iv, plaintext, associated_data)
    return iv + ct


def decrypt_small(key: bytes, blob: bytes,
                  associated_data: bytes | None = None) -> bytes:
    """
    Convenience: split IV from blob then decrypt.

    Expects blob = iv (12 bytes) || ciphertext || tag
    """
    if len(blob) < IV_SIZE + TAG_SIZE:
        raise ValueError('Blob too short to contain IV + tag.')
    iv = blob[:IV_SIZE]
    ct = blob[IV_SIZE:]
    return decrypt(key, iv, ct, associated_data)
