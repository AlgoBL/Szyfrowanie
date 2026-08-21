"""
crypto/ecc_core.py – Core ECIES encryption / decryption logic.

Scheme: ECIES (Elliptic Curve Integrated Encryption Scheme)
─────────────────────────────────────────────────────────────
Encryption (per recipient):
  1. Generate ephemeral X25519 key pair.
  2. Compute ECDH: shared_x = DH(ephemeral_private, recipient_public).
  3. In paranoid mode also:
       Generate ephemeral P-521 key pair.
       shared_p = DH(ephemeral_p521_private, recipient_p521_public).
  4. Derive session-key-encryption-key via HKDF-SHA-512:
       kek = HKDF(shared_x [XOR shared_p if paranoid], salt, info)
  5. Wrap (encrypt) the random 32-byte session key with AES-256-GCM.
  6. Store ephemeral public keys + encrypted session key in the header.

File content:
  7. Encrypt plaintext bytes with AES-256-GCM using session key + IV.

Signature (optional):
  8. Sign (header_bytes + ciphertext) with Ed25519 signer private key.
  9. Append signer pubkey + signature to the file.

Decryption:
  1. Read and parse header.
  2. For each recipient block: try to unwrap session key using our private key.
  3. Decrypt file content with recovered session key.
  4. (Optional) Verify Ed25519 signature from appended signature block.
"""

from __future__ import annotations

import os
import hashlib
from pathlib import Path
from typing import Callable, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, EllipticCurvePublicKey, generate_private_key, SECP521R1,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

from .aes_cipher import (
    generate_key, generate_iv, encrypt, decrypt,
    encrypt_small, decrypt_small,
    IV_SIZE, TAG_SIZE,
)
from .file_format import (
    ECCFileHeader, RecipientBlock,
    MAGIC, VERSION, FILE_EXTENSION,
    FLAG_PARANOID, FLAG_SIGNED,
    SALT_SIZE, X25519_PUBKEY_SIZE, P521_PUBKEY_COMPRESSED,
    ENC_SESSION_KEY_SIZE, ED25519_PUBKEY_SIZE, ED25519_SIG_SIZE,
    SIGNATURE_BLOCK_SIZE,
    pack_header, unpack_header,
)

HKDF_INFO = b'ECC-FILE-ENCRYPTOR-v1'


# ── Key generation ─────────────────────────────────────────────────────────────

def generate_x25519_keypair() -> Tuple[bytes, bytes]:
    """Return (private_raw_bytes, public_raw_bytes) for X25519."""
    priv = X25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = priv.public_key().public_bytes_raw()
    return priv_bytes, pub_bytes


def generate_p521_keypair() -> Tuple[bytes, bytes]:
    """Return (private_der_bytes, public_compressed_bytes) for P-521."""
    priv = generate_private_key(SECP521R1())
    priv_bytes = priv.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.CompressedPoint,
    )
    return priv_bytes, pub_bytes


def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    """Return (private_raw_bytes, public_raw_bytes) for Ed25519."""
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes_raw()
    pub_bytes = priv.public_key().public_bytes_raw()
    return priv_bytes, pub_bytes


# ── Internal ECDH / KDF helpers ────────────────────────────────────────────────

def _x25519_ecdh(private_raw: bytes, peer_public_raw: bytes) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(private_raw)
    pub  = X25519PublicKey.from_public_bytes(peer_public_raw)
    return priv.exchange(pub)


def _p521_ecdh(private_der: bytes, peer_public_compressed: bytes) -> bytes:
    priv = serialization.load_der_private_key(private_der, password=None)
    pub  = EllipticCurvePublicKey.from_encoded_point(SECP521R1(), peer_public_compressed)
    return priv.exchange(ECDH(), pub)


def _derive_kek(shared_x: bytes, salt: bytes,
                shared_p: bytes | None = None) -> bytes:
    """
    Derive a 32-byte Key-Encryption-Key with HKDF-SHA-512.

    In paranoid mode the two shared secrets are XOR'd before hashing.
    """
    if shared_p is not None:
        # Pad to same length and XOR
        len_x, len_p = len(shared_x), len(shared_p)
        max_len = max(len_x, len_p)
        shared_x = shared_x.ljust(max_len, b'\x00')
        shared_p = shared_p.ljust(max_len, b'\x00')
        ikm = bytes(a ^ b for a, b in zip(shared_x, shared_p))
    else:
        ikm = shared_x

    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        info=HKDF_INFO,
    )
    return hkdf.derive(ikm)


def _wrap_session_key(kek: bytes, session_key: bytes) -> bytes:
    """Encrypt session_key (32 bytes) with AES-256-GCM using kek."""
    return encrypt_small(kek, session_key)  # IV(12) + CT(32) + TAG(16) = 60


def _unwrap_session_key(kek: bytes, blob: bytes) -> bytes:
    """Decrypt a 60-byte wrapped session key."""
    return decrypt_small(kek, blob)


# ── Main encryption function ───────────────────────────────────────────────────

def encrypt_file(
    input_path: Path,
    output_path: Path,
    recipient_x25519_pub_keys: List[bytes],
    signing_ed25519_priv_key: Optional[bytes] = None,
    paranoid: bool = False,
    recipient_p521_pub_keys: Optional[List[bytes]] = None,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> None:
    """
    Encrypt *input_path* for one or more recipients, write to *output_path*.

    Args:
        input_path:                 File to encrypt (any type).
        output_path:                Destination .ecc file.
        recipient_x25519_pub_keys:  List of raw X25519 public keys (32 bytes each).
        signing_ed25519_priv_key:   Optional raw Ed25519 private key for signing.
        paranoid:                   If True, also use P-521 for double-curve mode.
        recipient_p521_pub_keys:    Required when paranoid=True; same order as x25519 list.
        progress_callback:          Called with (bytes_done, total_bytes).
    """
    if paranoid and (recipient_p521_pub_keys is None or
                     len(recipient_p521_pub_keys) != len(recipient_x25519_pub_keys)):
        raise ValueError('Paranoid mode requires matching P-521 public keys for each recipient.')

    # ── Read plaintext ────────────────────────────────────────────────────────
    plaintext = input_path.read_bytes()
    total = len(plaintext)

    # ── Generate session key + IV ─────────────────────────────────────────────
    session_key = generate_key()          # 32 bytes
    salt        = os.urandom(SALT_SIZE)   # 32 bytes HKDF salt
    iv          = generate_iv()           # 12 bytes AES-GCM IV

    # ── Build flags ───────────────────────────────────────────────────────────
    flags = 0
    if paranoid:
        flags |= FLAG_PARANOID
    if signing_ed25519_priv_key is not None:
        flags |= FLAG_SIGNED

    # ── Build recipient blocks ─────────────────────────────────────────────────
    recipients: List[RecipientBlock] = []
    for i, rec_x25519_pub in enumerate(recipient_x25519_pub_keys):
        # Ephemeral X25519
        eph_x25519_priv, eph_x25519_pub = generate_x25519_keypair()
        shared_x = _x25519_ecdh(eph_x25519_priv, rec_x25519_pub)

        shared_p: bytes | None = None
        eph_p521_pub: bytes | None = None

        if paranoid:
            rec_p521_pub = recipient_p521_pub_keys[i]
            eph_p521_priv, eph_p521_pub = generate_p521_keypair()
            shared_p = _p521_ecdh(eph_p521_priv, rec_p521_pub)

        kek = _derive_kek(shared_x, salt, shared_p)
        enc_sk = _wrap_session_key(kek, session_key)

        recipients.append(RecipientBlock(
            ephemeral_x25519_pub=eph_x25519_pub,
            encrypted_session_key=enc_sk,
            ephemeral_p521_pub=eph_p521_pub,
        ))

    # ── Assemble header ───────────────────────────────────────────────────────
    header = ECCFileHeader(
        version=VERSION,
        flags=flags,
        original_filename=input_path.name,
        salt=salt,
        iv=iv,
        recipients=recipients,
    )
    header_bytes = pack_header(header)

    # ── Encrypt content ───────────────────────────────────────────────────────
    # AAD = header bytes (ensures header integrity is authenticated)
    ciphertext = encrypt(session_key, iv, plaintext, associated_data=header_bytes)

    if progress_callback:
        progress_callback(total, total)

    # ── Write file (header + ciphertext) ─────────────────────────────────────
    payload = header_bytes + ciphertext

    # ── Sign if requested ─────────────────────────────────────────────────────
    if signing_ed25519_priv_key is not None:
        signer_priv = Ed25519PrivateKey.from_private_bytes(signing_ed25519_priv_key)
        signer_pub  = signer_priv.public_key().public_bytes_raw()
        signature   = signer_priv.sign(payload)
        payload = payload + signer_pub + signature

    output_path.write_bytes(payload)


# ── Main decryption function ───────────────────────────────────────────────────

def decrypt_file(
    input_path: Path,
    output_path: Path,
    recipient_x25519_priv_key: bytes,
    paranoid_p521_priv_key: Optional[bytes] = None,
    verify_signature: bool = True,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> Optional[str]:
    """
    Decrypt an .ecc file.

    Args:
        input_path:               .ecc file to decrypt.
        output_path:              Where to write the decrypted output.
        recipient_x25519_priv_key: Raw X25519 private key (32 bytes).
        paranoid_p521_priv_key:   DER-encoded P-521 private key (paranoid mode).
        verify_signature:         If True, verify Ed25519 signature when present.
        progress_callback:        Called with (bytes_done, total_bytes).

    Returns:
        Base64 signer public key string if the file was signed and verified,
        None otherwise.

    Raises:
        ValueError:         On format errors.
        InvalidSignature:   On signature mismatch.
        cryptography.exceptions.InvalidTag: On decryption failure / wrong key.
    """
    raw = input_path.read_bytes()
    total = len(raw)

    # ── Detect and strip signature block ─────────────────────────────────────
    header_tmp, _ = unpack_header(raw)
    has_signature  = header_tmp.is_signed

    if has_signature:
        sig_block   = raw[-SIGNATURE_BLOCK_SIZE:]
        payload_raw = raw[:-SIGNATURE_BLOCK_SIZE]
        signer_pub_bytes = sig_block[:ED25519_PUBKEY_SIZE]
        signature        = sig_block[ED25519_PUBKEY_SIZE:]
    else:
        payload_raw = raw
        signer_pub_bytes = None
        signature        = None

    # ── Parse header ─────────────────────────────────────────────────────────
    header, ciphertext_offset = unpack_header(payload_raw)
    header_bytes = payload_raw[:ciphertext_offset]
    ciphertext   = payload_raw[ciphertext_offset:]

    # ── Verify signature before decrypting (fail-fast) ───────────────────────
    signer_pub_hex: Optional[str] = None
    if has_signature and verify_signature:
        try:
            signer_pub = Ed25519PublicKey.from_public_bytes(signer_pub_bytes)
            signer_pub.verify(signature, payload_raw)
            signer_pub_hex = signer_pub_bytes.hex()
        except InvalidSignature:
            raise InvalidSignature('Ed25519 signature verification FAILED – file may be tampered!')

    # ── Find recipient block and unwrap session key ───────────────────────────
    session_key: bytes | None = None

    for rec in header.recipients:
        try:
            shared_x = _x25519_ecdh(recipient_x25519_priv_key, rec.ephemeral_x25519_pub)

            shared_p: bytes | None = None
            if header.is_paranoid:
                if paranoid_p521_priv_key is None:
                    continue   # Can't decrypt this recipient block without P-521 key
                shared_p = _p521_ecdh(paranoid_p521_priv_key, rec.ephemeral_p521_pub)

            kek = _derive_kek(shared_x, header.salt, shared_p)
            session_key = _unwrap_session_key(kek, rec.encrypted_session_key)
            break  # Found and unwrapped successfully
        except Exception:
            continue  # Try next recipient block

    if session_key is None:
        raise ValueError('Decryption failed: no matching recipient key found.')

    # ── Decrypt file content ──────────────────────────────────────────────────
    plaintext = decrypt(session_key, header.iv, ciphertext, associated_data=header_bytes)

    if progress_callback:
        progress_callback(total, total)

    # ── Write output ──────────────────────────────────────────────────────────
    output_path.write_bytes(plaintext)

    return signer_pub_hex


# ── Utility: recover original filename from .ecc header ────────────────────────

def peek_filename(input_path: Path) -> str:
    """Read the original filename stored inside an .ecc file without decrypting."""
    with open(input_path, 'rb') as f:
        raw = f.read(512)
    header, _ = unpack_header(raw)
    return header.original_filename
