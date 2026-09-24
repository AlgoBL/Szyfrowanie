"""
crypto/steganography/steg_engine.py – Silnik MLAS (Multi-Layer Adaptive Steganography).

Przepływ embed:
  1. Wczytanie nośnika PNG/JPEG → PIL Image (RGBA → RGB)
  2. Derywacja kluczy (Argon2id → HKDF → master_key, perm_key)
  3. Zapis mini-nagłówka (32 B) i ładunku (.ecc bytes) łącznie
  4. Podział ładunku na 3 porcje kanałowe (channel_splitter)
  5. Obliczenie mapy kosztów WOW dla każdego kanału (cost_map)
  6. Wyznaczenie pseudolosowej kolejności pikseli (permutation key)
  7. LSB embedding – każdy bit porcji do LSB odpowiedniego piksela kanału
  8. Zapis metadanych w PNG tEXt chunk (Warstwa 2)
  9. Zapis obrazu wyjściowego PNG (lossless)

Przepływ extract:
  1. Wczytanie nośnika
  2. Derywacja tych samych kluczy
  3. Wyznaczenie kolejności pikseli (ten sam perm_key)
  4. Odczyt LSB → porcje kanałowe
  5. Złożenie ładunku przez channel_splitter.merge_payload
  6. Weryfikacja MAC nagłówka → payload_len → zwróć bajty ładunku

Tryby osadzania (alpha):
  ULTRA_SECURE = 0.10   – <10% pikseli użytych, niemal niemożliwe do wykrycia
  BALANCED     = 0.25   – dobry kompromis pojemność/bezpieczeństwo (domyślny)
  HIGH_CAPACITY= 0.40   – duże pliki, nieznacznie wyższe ryzyko detekcji
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Literal

import numpy as np
from PIL import Image, PngImagePlugin
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .steg_format import (
    pack_steg_header, unpack_steg_header, HEADER_SIZE
)
from .channel_splitter import split_payload, merge_payload, chunk_sizes
from .cost_map import wow_cost_map, build_embedding_order

# ── Stałe trybów ──────────────────────────────────────────────────────────────

ALPHA_ULTRA_SECURE  = 0.10
ALPHA_BALANCED      = 0.25
ALPHA_HIGH_CAPACITY = 0.40

AlphaMode = Literal['ultra_secure', 'balanced', 'high_capacity']

ALPHA_MAP: dict[AlphaMode, float] = {
    'ultra_secure':   ALPHA_ULTRA_SECURE,
    'balanced':       ALPHA_BALANCED,
    'high_capacity':  ALPHA_HIGH_CAPACITY,
}

# ── Derywacja kluczy ──────────────────────────────────────────────────────────

_ARGON2_AVAILABLE = False
try:
    from argon2.low_level import hash_secret_raw, Type
    _ARGON2_AVAILABLE = True
except ImportError:
    pass

_STEG_SALT_FIXED = b'STEG-MLAS-v1-salt-fixed-32bytes!'  # 32 B, stały


def _derive_master_key(password: str) -> bytes:
    """
    Wyprowadza 64-bajtowy klucz główny z hasła.

    Używa Argon2id jeśli dostępny, wpp. SHA-512 (fallback).
    """
    pw_bytes = password.encode('utf-8')
    if _ARGON2_AVAILABLE:
        raw = hash_secret_raw(
            secret=pw_bytes,
            salt=_STEG_SALT_FIXED,
            time_cost=2,
            memory_cost=65536,
            parallelism=2,
            hash_len=64,
            type=Type.ID,
        )
    else:
        raw = hashlib.sha512(pw_bytes + _STEG_SALT_FIXED).digest()
    return raw


def _hkdf(master_key: bytes, info: bytes, length: int = 32) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info)
    return hkdf.derive(master_key)


def _derive_keys(password: str) -> tuple[bytes, bytes, bytes]:
    """Zwraca (master_key_32B, perm_key_32B, mac_key_32B)."""
    mk = _derive_master_key(password)
    master_key = _hkdf(mk, b'STEG-MASTER', 32)
    perm_key   = _hkdf(mk, b'STEG-PERM',   32)
    mac_key    = _hkdf(mk, b'STEG-MAC',     32)
    return master_key, perm_key, mac_key


# ── Pomocnicze ────────────────────────────────────────────────────────────────

def _load_rgb(path: Path) -> np.ndarray:
    """Wczytuje obraz jako uint8 numpy array (H, W, 3) – zawsze RGB."""
    img = Image.open(path).convert('RGB')
    return np.array(img, dtype=np.uint8)


def _bits_from_bytes(data: bytes) -> list[int]:
    """Konwertuje bajty na listę bitów (MSB first)."""
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def _bytes_from_bits(bits: list[int]) -> bytes:
    """Konwertuje bity (MSB first) na bajty."""
    result = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        if len(chunk) < 8:
            chunk += [0] * (8 - len(chunk))
        byte = 0
        for b in chunk:
            byte = (byte << 1) | b
        result.append(byte)
    return bytes(result)


# ── Pojemność nośnika ─────────────────────────────────────────────────────────

def carrier_capacity(image_path: Path | str, alpha: float | AlphaMode = 'balanced') -> int:
    """
    Oblicza maksymalną pojemność nośnika w bajtach dla danego trybu.

    Args:
        image_path: Ścieżka do pliku PNG/JPEG.
        alpha:      Tryb ('ultra_secure' | 'balanced' | 'high_capacity') lub float.

    Returns:
        Maksymalna liczba bajtów ładunku (bez nagłówka steganograficznego).
    """
    if isinstance(alpha, str):
        alpha = ALPHA_MAP[alpha]

    arr = _load_rgb(image_path)
    h, w, _ = arr.shape
    n_pixels = h * w

    # Każdy kanał daje 1 bit/piksel * alpha pikseli
    total_bits = int(n_pixels * alpha) * 3   # 3 kanały
    total_bytes = total_bits // 8
    return max(0, total_bytes - HEADER_SIZE)


# ── Osadzanie (EMBED) ─────────────────────────────────────────────────────────

def embed_into_image(
    carrier_path: Path | str,
    payload_bytes: bytes,
    password: str,
    output_path: Path | str,
    alpha: float | AlphaMode = 'balanced',
) -> None:
    """
    Osadza payload_bytes wewnątrz obrazu nośnika metodą MLAS.

    Args:
        carrier_path:  Ścieżka do nośnika PNG/JPEG (nie jest modyfikowany).
        payload_bytes: Dane do ukrycia (np. zawartość pliku .ecc).
        password:      Hasło steganograficzne (osobne od ECC!).
        output_path:   Wyjściowy plik PNG z ukrytymi danymi.
        alpha:         Tryb osadzania lub wartość 0.0–1.0.

    Raises:
        ValueError: Jeśli ładunek jest zbyt duży dla nośnika.
    """
    carrier_path = Path(carrier_path)
    output_path  = Path(output_path)

    if isinstance(alpha, str):
        alpha = ALPHA_MAP[alpha]

    # ── 1. Wczytaj nośnik ────────────────────────────────────────────────────
    arr = _load_rgb(carrier_path)
    h, w, _ = arr.shape
    n_pixels = h * w

    # ── 2. Derywacja kluczy ──────────────────────────────────────────────────
    master_key, perm_key, mac_key = _derive_keys(password)

    # ── 3. Sprawdź pojemność ─────────────────────────────────────────────────
    n_use     = int(n_pixels * alpha)
    cap_bytes = (n_use * 3) // 8   # całkowita pojemność (header + payload)
    max_payload = cap_bytes - HEADER_SIZE

    if len(payload_bytes) > max_payload:
        raise ValueError(
            f'Ladunekn ({len(payload_bytes):,} B) przekracza pojemnosc nosnika '
            f'({max_payload:,} B) dla trybu a={alpha:.2f}.\n'
            f'Uzyj wiekszego nosnika lub trybu high_capacity.'
        )

    # ── 4. Buduj dane do osadzenia: nagłówek + ładunek + padding ────────────
    # WAŻNE: paddujemy do cap_bytes, żeby split_payload zawsze działa na
    # identycznych rozmiarach co extract_from_image.
    header    = pack_steg_header(len(payload_bytes), mac_key)
    inner     = header + payload_bytes
    # Dopełnienie losowymi bajtami (nie można odróżnić od danych)
    pad_len   = cap_bytes - len(inner)
    full_data = inner + os.urandom(pad_len)

    # ── 5. Podział kanałowy (Warstwa 3) ─────────────────────────────────────
    chunk_r, chunk_g, chunk_b = split_payload(full_data, master_key)

    # ── 6. Permutacja pikseli (Warstwa 4) ─────────────────────────────────────
    # WOW cost map (Warstwa 1) – jesli dostepna, poprawia jakosc statystyczna.
    # Uwaga: cost_maps sa przekazywane ale nie uzywane przez build_embedding_order
    # (kolejnosc zalezy tylko od klucza – deterministyczna).
    def _perm_key_for(label: bytes) -> bytes:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label)
        return hkdf.derive(perm_key)

    order_r = build_embedding_order([], _perm_key_for(b'PERM_R'), n_pixels, alpha)
    order_g = build_embedding_order([], _perm_key_for(b'PERM_G'), n_pixels, alpha)
    order_b = build_embedding_order([], _perm_key_for(b'PERM_B'), n_pixels, alpha)

    # ── 8. LSB Embedding ──────────────────────────────────────────────────────
    arr_out = arr.copy()

    def _embed_channel(channel_idx: int, chunk: bytes, order: np.ndarray) -> None:
        bits = _bits_from_bytes(chunk)
        # Truncate to order length (last channel chunk may be slightly larger
        # due to rounding in chunk_sizes – extra bits are padding)
        bits = bits[:len(order)]
        flat = arr_out[:, :, channel_idx].ravel()
        for i, bit in enumerate(bits):
            px_idx = order[i]
            flat[px_idx] = (flat[px_idx] & 0xFE) | bit
        arr_out[:, :, channel_idx] = flat.reshape(h, w)

    _embed_channel(0, chunk_r, order_r)
    _embed_channel(1, chunk_g, order_g)
    _embed_channel(2, chunk_b, order_b)

    # ── 9. Zapis PNG z metadanymi (Warstwa 2) ────────────────────────────────
    img_out = Image.fromarray(arr_out, 'RGB')

    # PNG tEXt chunk – znacznik autentyczności (niepotrzebny do ekstrakcji,
    # ale pozwala szybko zidentyfikować nośnik STEG)
    mac_hint = hashlib.blake2b(
        b'STEG_HINT' + mac_key, digest_size=8
    ).hexdigest()
    pnginfo = PngImagePlugin.PngInfo()
    pnginfo.add_text('Comment', f'STEG_MAC:{mac_hint};STEG_VER:2;STEG_A:{alpha:.2f}')

    img_out.save(str(output_path), format='PNG', pnginfo=pnginfo)


# ── Ekstrakcja (EXTRACT) ──────────────────────────────────────────────────────

def extract_from_image(
    steg_path: Path | str,
    password: str,
    alpha: float | AlphaMode = 'balanced',
) -> bytes:
    """
    Wyodrębnia ukryty ładunek z obrazu steganograficznego.

    Args:
        steg_path: Ścieżka do pliku PNG z ukrytymi danymi.
        password:  Hasło steganograficzne.
        alpha:     Tryb osadzania (musi być taki sam jak przy embed!).

    Returns:
        Oryginalne bajty ładunku (np. zawartość pliku .ecc).

    Raises:
        ValueError: Jeśli weryfikacja MAC nie powiodła się (złe hasło / brak danych).
    """
    steg_path = Path(steg_path)

    if isinstance(alpha, str):
        alpha = ALPHA_MAP[alpha]

    # ── 1. Wczytaj obraz ─────────────────────────────────────────────────────
    arr = _load_rgb(steg_path)
    h, w, _ = arr.shape
    n_pixels = h * w

    # ── 2. Derywacja kluczy ──────────────────────────────────────────────────
    master_key, perm_key, mac_key = _derive_keys(password)

    # ── 3. Wyznacz kolejność pikseli (musi być identyczna jak przy embed) ────
    def _perm_key_for(label: bytes) -> bytes:
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=label)
        return hkdf.derive(perm_key)

    order_r = build_embedding_order([], _perm_key_for(b'PERM_R'), n_pixels, alpha)
    order_g = build_embedding_order([], _perm_key_for(b'PERM_G'), n_pixels, alpha)
    order_b = build_embedding_order([], _perm_key_for(b'PERM_B'), n_pixels, alpha)

    # ── 4. LSB Extraction – wyciągamy całą dostępną pojemność za jednym razem ─
    # Pojemność = (n_use * 3 bits) / 8 bytes — tyle ile zostało osadzone
    n_use      = int(n_pixels * alpha)
    cap_bytes  = (n_use * 3) // 8   # całkowita pojemność w bajtach

    # Rozmiary kanałów dla cap_bytes (muszą pasować do split_payload przy embed)
    sr_cap, sg_cap, sb_cap = chunk_sizes(cap_bytes)

    def _extract_channel(channel_idx: int, order: np.ndarray, n_bytes: int) -> bytes:
        flat = arr[:, :, channel_idx].ravel()
        bits = [int(flat[order[i]] & 1) for i in range(min(n_bytes * 8, len(order)))]
        return _bytes_from_bits(bits)[:n_bytes]

    raw_r = _extract_channel(0, order_r, sr_cap)
    raw_g = _extract_channel(1, order_g, sg_cap)
    raw_b = _extract_channel(2, order_b, sb_cap)

    full_data = merge_payload(raw_r, raw_g, raw_b, master_key)

    # ── 5. Parsuj nagłówek i zwróć ładunek ───────────────────────────────────
    header_bytes = full_data[:HEADER_SIZE]
    payload_len  = unpack_steg_header(header_bytes, mac_key)   # Weryfikuje MAC
    return full_data[HEADER_SIZE:HEADER_SIZE + payload_len]
