"""
crypto/steganography/channel_splitter.py – Warstwa 3: rozkład R/G/B.

Dane wejściowe dzielone są na 3 równe (lub prawie równe) porcje,
każda przypisana do osobnego kanału koloru (R, G, B).

Każda porcja jest XOR-owana z unikalnym kluczem kanałowym wyprowadzonym
przez HKDF, co zapewnia, że:
  - Odczyt jednego kanału nie ujawnia nic o danych
  - Rekonstrukcja wymaga wszystkich 3 kanałów (schema 3-z-3)
"""

from __future__ import annotations

import math
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

CHANNEL_LABELS = (b'CH_R', b'CH_G', b'CH_B')


def _channel_key(master_key: bytes, label: bytes, length: int) -> bytes:
    """
    Wyprowadza strumień kluczowy XOR dla kanału przez BLAKE2b w trybie licznikowym.

    Obsługuje arbitralnie duże długości (brak limitu jak w HKDF).
    """
    import hashlib, struct
    stream = bytearray()
    counter = 0
    while len(stream) < length:
        h = hashlib.blake2b(
            label + struct.pack('<Q', counter),
            key=master_key[:32],
            digest_size=64,
        ).digest()
        stream.extend(h)
        counter += 1
    return bytes(stream[:length])


def _xor_bytes(data: bytes, key_stream: bytes) -> bytes:
    """XOR bajt po bajcie."""
    return bytes(d ^ k for d, k in zip(data, key_stream))


def split_payload(payload: bytes, master_key: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Dzieli ładunek na 3 porcje i XOR-uje każdą z kluczem kanałowym.

    Args:
        payload:    Dane do podziału (np. zaszyfrowany .ecc).
        master_key: Klucz główny (>=16 B), zwykle z HKDF hasła.

    Returns:
        (chunk_R, chunk_G, chunk_B) – każda zaszyfrowana XOR kluczem kanałowym.
        Chunki mogą różnić się długością o 1-2 bajty (ostatni jest najdłuższy).
    """
    n = len(payload)
    size_r = n // 3
    size_g = n // 3
    size_b = n - size_r - size_g   # ostatni dostaje resztę

    raw_r = payload[0:size_r]
    raw_g = payload[size_r:size_r + size_g]
    raw_b = payload[size_r + size_g:]

    chunk_r = _xor_bytes(raw_r, _channel_key(master_key, CHANNEL_LABELS[0], size_r))
    chunk_g = _xor_bytes(raw_g, _channel_key(master_key, CHANNEL_LABELS[1], size_g))
    chunk_b = _xor_bytes(raw_b, _channel_key(master_key, CHANNEL_LABELS[2], size_b))

    return chunk_r, chunk_g, chunk_b


def merge_payload(chunk_r: bytes, chunk_g: bytes, chunk_b: bytes,
                  master_key: bytes) -> bytes:
    """
    Odwraca split_payload – XOR z kluczami kanałowymi i łączy porcje.

    Args:
        chunk_r/g/b: Porcje z kanałów (wyodrębnione z nośnika).
        master_key:  Klucz główny (musi być identyczny jak przy osadzaniu).

    Returns:
        Oryginalny ładunek (bajty).
    """
    raw_r = _xor_bytes(chunk_r, _channel_key(master_key, CHANNEL_LABELS[0], len(chunk_r)))
    raw_g = _xor_bytes(chunk_g, _channel_key(master_key, CHANNEL_LABELS[1], len(chunk_g)))
    raw_b = _xor_bytes(chunk_b, _channel_key(master_key, CHANNEL_LABELS[2], len(chunk_b)))
    return raw_r + raw_g + raw_b


def chunk_sizes(total: int) -> tuple[int, int, int]:
    """Zwraca (size_r, size_g, size_b) – pomocnicze przy alokacji bitów na kanał."""
    size_r = total // 3
    size_g = total // 3
    size_b = total - size_r - size_g
    return size_r, size_g, size_b
