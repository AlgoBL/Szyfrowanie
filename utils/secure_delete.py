"""
utils/secure_delete.py – Secure file deletion (data shredding).

Overwrites a file with random data multiple times before deletion,
making recovery significantly harder.

NOTE: On SSDs / NTFS with journaling, forensic recovery may still be
possible. For strongest protection consider full-disk encryption.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

DEFAULT_PASSES = 3


def secure_delete(path: Path, passes: int = DEFAULT_PASSES) -> None:
    """
    Overwrite *path* with random bytes *passes* times, then delete it.

    Args:
        path:   File to shred.
        passes: Number of overwrite passes (default: 3).
    """
    if not path.is_file():
        raise FileNotFoundError(f'File not found: {path}')

    file_size = path.stat().st_size

    with open(path, 'r+b') as f:
        for _ in range(passes):
            f.seek(0)
            # Write in 64 KiB chunks to avoid large allocations
            remaining = file_size
            while remaining > 0:
                chunk = min(remaining, 65536)
                f.write(secrets.token_bytes(chunk))
                remaining -= chunk
            f.flush()
            os.fsync(f.fileno())

    path.unlink()
