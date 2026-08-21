"""
crypto/file_format.py – Defines the binary format for .ecc encrypted files.

File layout:
  [8]  magic = b'ECCRYPT\x00'
  [1]  version
  [1]  flags  (bit0=paranoid, bit1=signed)
  [1]  num_recipients
  [2]  filename_len (uint16 LE)
  [N]  original_filename (UTF-8)
  [32] hkdf_salt
  [12] aes_iv
  --- per recipient (repeated num_recipients times) ---
  [32] ephemeral_x25519_pub
  [67] ephemeral_p521_pub  (only if FLAG_PARANOID)
  [60] encrypted_session_key  (12 IV + 32 ciphertext + 16 GCM tag)
  --- end recipient blocks ---
  [M]  ciphertext (AES-256-GCM, last 16 bytes = GCM auth tag)
  --- if FLAG_SIGNED (appended at very end) ---
  [32] ed25519 signer public key
  [64] ed25519 signature of all bytes preceding this block
"""

import struct
from dataclasses import dataclass, field
from typing import List, Optional

# ── Constants ─────────────────────────────────────────────────────────────────

MAGIC = b'ECCRYPT\x00'
VERSION = 1
FILE_EXTENSION = '.ecc'

FLAG_PARANOID = 0x01   # Double-curve mode: X25519 + P-521
FLAG_SIGNED   = 0x02   # Ed25519 signature appended

# Sizes (bytes)
SALT_SIZE             = 32
AES_IV_SIZE           = 12
X25519_PUBKEY_SIZE    = 32
P521_PUBKEY_COMPRESSED= 67
SESSION_KEY_SIZE      = 32
ENC_SESSION_KEY_SIZE  = 60   # 12 (IV) + 32 (ct) + 16 (tag)
ED25519_PUBKEY_SIZE   = 32
ED25519_SIG_SIZE      = 64

SIGNATURE_BLOCK_SIZE  = ED25519_PUBKEY_SIZE + ED25519_SIG_SIZE  # 96


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class RecipientBlock:
    """Stores per-recipient ECIES data."""
    ephemeral_x25519_pub: bytes            # 32 bytes
    encrypted_session_key: bytes           # 60 bytes (IV + ct + tag)
    ephemeral_p521_pub: Optional[bytes] = None  # 67 bytes if paranoid


@dataclass
class ECCFileHeader:
    """Parsed header of an .ecc file."""
    version: int = VERSION
    flags: int = 0
    original_filename: str = ''
    salt: bytes = b'\x00' * SALT_SIZE
    iv: bytes = b'\x00' * AES_IV_SIZE
    recipients: List[RecipientBlock] = field(default_factory=list)

    @property
    def is_paranoid(self) -> bool:
        return bool(self.flags & FLAG_PARANOID)

    @property
    def is_signed(self) -> bool:
        return bool(self.flags & FLAG_SIGNED)


# ── Serialisation helpers ──────────────────────────────────────────────────────

def _recipient_size(paranoid: bool) -> int:
    """Returns byte size of a single recipient block."""
    size = X25519_PUBKEY_SIZE + ENC_SESSION_KEY_SIZE
    if paranoid:
        size += P521_PUBKEY_COMPRESSED
    return size


def pack_header(header: ECCFileHeader) -> bytes:
    """Serialise the file header to bytes (without ciphertext/signature)."""
    fn_bytes = header.original_filename.encode('utf-8')
    fn_len = len(fn_bytes)
    num_rec = len(header.recipients)

    parts: List[bytes] = [
        MAGIC,
        struct.pack('<BBBH', header.version, header.flags, num_rec, fn_len),
        fn_bytes,
        header.salt,
        header.iv,
    ]

    for rec in header.recipients:
        parts.append(rec.ephemeral_x25519_pub)
        if header.is_paranoid:
            if rec.ephemeral_p521_pub is None:
                raise ValueError('Paranoid mode requires ephemeral_p521_pub in each RecipientBlock.')
            parts.append(rec.ephemeral_p521_pub)
        parts.append(rec.encrypted_session_key)

    return b''.join(parts)


def unpack_header(data: bytes) -> tuple[ECCFileHeader, int]:
    """
    Parse header from raw bytes.

    Returns:
        (header, bytes_consumed)  where bytes_consumed is the offset
        at which ciphertext begins.
    """
    if len(data) < 13:
        raise ValueError('File too short to be a valid .ecc file.')
    if data[:8] != MAGIC:
        raise ValueError('Invalid magic bytes – not an .ecc file.')

    version, flags, num_rec, fn_len = struct.unpack_from('<BBBH', data, 8)

    if version != VERSION:
        raise ValueError(f'Unsupported .ecc version: {version}')

    offset = 13  # 8 (magic) + 1+1+1+2 (version,flags,num_rec,fn_len)
    fn_bytes = data[offset:offset + fn_len]
    offset += fn_len
    original_filename = fn_bytes.decode('utf-8')

    salt = data[offset:offset + SALT_SIZE];       offset += SALT_SIZE
    iv   = data[offset:offset + AES_IV_SIZE];     offset += AES_IV_SIZE

    paranoid = bool(flags & FLAG_PARANOID)
    recipients: List[RecipientBlock] = []

    for _ in range(num_rec):
        x25519_pub = data[offset:offset + X25519_PUBKEY_SIZE]; offset += X25519_PUBKEY_SIZE

        p521_pub: Optional[bytes] = None
        if paranoid:
            p521_pub = data[offset:offset + P521_PUBKEY_COMPRESSED]; offset += P521_PUBKEY_COMPRESSED

        enc_sk = data[offset:offset + ENC_SESSION_KEY_SIZE];  offset += ENC_SESSION_KEY_SIZE
        recipients.append(RecipientBlock(x25519_pub, enc_sk, p521_pub))

    header = ECCFileHeader(
        version=version,
        flags=flags,
        original_filename=original_filename,
        salt=salt,
        iv=iv,
        recipients=recipients,
    )
    return header, offset
