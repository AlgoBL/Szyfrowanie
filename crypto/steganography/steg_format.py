"""
crypto/steganography/steg_format.py – Mini-nagłówek steganograficzny.

Struktura nagłówka (32 bajty), osadzana jako pierwsze dane w nośniku:

  [4 B]  magic     = b'STEG'
  [4 B]  payload_len  (uint32 LE) – długość ukrytych danych w bajtach
  [8 B]  nonce     (losowe, do MAC)
  [16 B] BLAKE2b-MAC (klucz=master_key, dane=magic+payload_len+nonce)

Walidacja MAC przy ekstrakcji chroni przed fałszywą ekstrakcją z losowego obrazu.
"""

from __future__ import annotations

import os
import struct
import hashlib

STEG_MAGIC      = b'STEG'
HEADER_SIZE     = 32          # 4 + 4 + 8 + 16
NONCE_SIZE      = 8
MAC_SIZE        = 16


def _mac(key: bytes, data: bytes) -> bytes:
    """16-bajtowy BLAKE2b-MAC (truncated do 16 B)."""
    return hashlib.blake2b(data, key=key[:32], digest_size=MAC_SIZE).digest()


def pack_steg_header(payload_len: int, master_key: bytes) -> bytes:
    """
    Buduje 32-bajtowy nagłówek steganograficzny.

    Args:
        payload_len: Liczba bajtów ładunku (bez nagłówka).
        master_key:  Klucz pochodny od hasła (>=16 B).

    Returns:
        32-bajtowy nagłówek gotowy do osadzenia.
    """
    nonce   = os.urandom(NONCE_SIZE)
    pl_pack = struct.pack('<I', payload_len)
    mac_data = STEG_MAGIC + pl_pack + nonce
    mac      = _mac(master_key, mac_data)
    return STEG_MAGIC + pl_pack + nonce + mac


def unpack_steg_header(header_bytes: bytes, master_key: bytes) -> int:
    """
    Parsuje i weryfikuje 32-bajtowy nagłówek.

    Returns:
        payload_len (int)

    Raises:
        ValueError: Jeśli magic lub MAC nie pasuje.
    """
    if len(header_bytes) < HEADER_SIZE:
        raise ValueError('Nagłówek steganograficzny jest za krótki.')

    magic   = header_bytes[0:4]
    pl_pack = header_bytes[4:8]
    nonce   = header_bytes[8:16]
    mac_got = header_bytes[16:32]

    if magic != STEG_MAGIC:
        raise ValueError('Nieprawidłowy magic – brak danych steganograficznych lub błędne hasło.')

    mac_expected = _mac(master_key, magic + pl_pack + nonce)
    if not hmac_compare(mac_got, mac_expected):
        raise ValueError('Błąd weryfikacji MAC – złe hasło lub plik nie zawiera danych.')

    (payload_len,) = struct.unpack('<I', pl_pack)
    return payload_len


def hmac_compare(a: bytes, b: bytes) -> bool:
    """Porównanie w czasie stałym (constant-time)."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0
