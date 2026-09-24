"""
crypto/steganography/cost_map.py – Mapa kosztów WOW (Wavelet Obtained Weights).

Wyznacza dla każdego piksela koszt rho_ij osadzenia jednego bitu:
  - Niski koszt  → piksel w obszarze tekstury/szumu (trudny do analizy statystycznej)
  - Wysoki koszt → piksel w obszarze gładkim (łatwo wykryć modyfikację)

Algorytm WOW (Holub & Fridrich, 2012):
  1. Filtr Wiener w 3 kierunkach (poziomy, pionowy, przekątny) na falce Haar 2D
  2. rho = 1 / (|H_ij| + |V_ij| + |D_ij| + epsilon)
  3. Opcjonalna kara za krawędzie (gradient Sobel)

Referencja:
  Holub V., Fridrich J. (2012). Designing steganographic distortion using directional filters.
  IEEE WIFS 2012.
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

EPSILON = 1e-8  # Ochrona przed dzieleniem przez zero


def _haar_subbands(channel: NDArray[np.float64]) -> tuple[
        NDArray[np.float64], NDArray[np.float64], NDArray[np.float64]]:
    """
    Jednopoziomowa 2D transformacja falkowa Haar.

    Zwraca (LL, LH, HL, HH) ale tu zwracamy reszt high-pass:
      H – poziomy high-pass (LH)
      V – pionowy  high-pass (HL)
      D – przekątny high-pass (HH)
    """
    h, w = channel.shape
    # Upewniamy się, że wymiary parzyste (kadrowanie)
    h2, w2 = h - (h % 2), w - (w % 2)
    c = channel[:h2, :w2]

    # Haar 1D wzdłuż osi X (poziomy)
    lo_x = (c[:, 0::2] + c[:, 1::2]) / 2.0
    hi_x = (c[:, 0::2] - c[:, 1::2]) / 2.0

    # Haar 1D wzdłuż osi Y (pionowy)
    LL = (lo_x[0::2, :] + lo_x[1::2, :]) / 2.0   # noqa: N806  (unused, for reference)
    LH = (lo_x[0::2, :] - lo_x[1::2, :]) / 2.0   # noqa: N806
    HL = (hi_x[0::2, :] + hi_x[1::2, :]) / 2.0   # noqa: N806
    HH = (hi_x[0::2, :] - hi_x[1::2, :]) / 2.0   # noqa: N806

    return LH, HL, HH   # H, V, D high-pass subbands


def _wiener_residual(subband: NDArray[np.float64],
                     kernel_size: int = 3) -> NDArray[np.float64]:
    """
    Residual filtra Wiener: |subband - Wiener(subband)|.

    Przybliżona wersja: różnica między surowym pasmem a lokalnie wygładzonym
    oknem kernel_size×kernel_size (median lub mean filter approx).
    """
    from numpy.lib.stride_tricks import sliding_window_view

    pad = kernel_size // 2
    padded = np.pad(subband, pad, mode='reflect')
    windows = sliding_window_view(padded, (kernel_size, kernel_size))
    local_mean = windows.mean(axis=(-2, -1))
    local_var  = windows.var(axis=(-2, -1))

    # Wiener estimate
    noise_var = np.mean(local_var)
    wiener    = local_mean + np.clip(
        local_var - noise_var, 0, None
    ) / (local_var + EPSILON) * (subband - local_mean)

    return np.abs(subband - wiener)


def wow_cost_map(channel: NDArray[np.float64],
                 sobel_penalty: float = 0.5) -> NDArray[np.float64]:
    """
    Oblicza mapę kosztów WOW dla jednego kanału obrazu.

    Args:
        channel:       2D tablica float64 [0, 255].
        sobel_penalty: Mnożnik kary za piksele krawędziowe (Sobel > próg).
                       0.0 = brak kary, 1.0 = pełna kara.

    Returns:
        rho: 2D tablica float64 o tych samych wymiarach co channel.
             Mniejsze wartości → tańsze (preferowane) osadzenie.
    """
    h, w = channel.shape
    LH, HL, HH = _haar_subbands(channel)  # H, V, D

    # Residuały Wienera dla każdego pasma
    r_H = _wiener_residual(LH)
    r_V = _wiener_residual(HL)
    r_D = _wiener_residual(HH)

    # Upsample do oryginalnego rozmiaru (nearest-neighbor)
    def _up(arr: NDArray) -> NDArray:
        return np.repeat(np.repeat(arr, 2, axis=0), 2, axis=1)[:h, :w]

    rho = 1.0 / (_up(r_H) + _up(r_V) + _up(r_D) + EPSILON)

    # Kara Sobel – piksele krawędziowe są bardziej widoczne dla oka
    if sobel_penalty > 0.0:
        sx = np.abs(np.diff(channel, axis=1, prepend=channel[:, :1]))
        sy = np.abs(np.diff(channel, axis=0, prepend=channel[:1, :]))
        sobel_mag = np.hypot(sx, sy)
        threshold = np.percentile(sobel_mag, 75)
        edge_mask = (sobel_mag > threshold).astype(np.float64)
        # Krawędzie: zwiększamy koszt (utrudniamy osadzenie)
        rho = rho * (1.0 + sobel_penalty * edge_mask)

    # Normalizacja do [0, 1] – przydatna przy wyborze pikseli
    rho_min, rho_max = rho.min(), rho.max()
    if rho_max > rho_min:
        rho = (rho - rho_min) / (rho_max - rho_min)

    return rho


def build_embedding_order(cost_maps: list[NDArray[np.float64]],
                          perm_key: bytes,
                          n_pixels: int,
                          alpha: float) -> NDArray[np.intp]:
    """
    Warstwa 4 – wyznaczanie pseudolosowej kolejności osadzania.

    WAŻNE: kolejność jest wyznaczana WYŁĄCZNIE na podstawie klucza (perm_key)
    i nie zależy od treści obrazu. Gwarantuje to deterministyczność przy
    ekstrakcji, gdzie obraz ma już zmodyfikowane LSB (co zmieniłoby cost map).

    Warstwa WOW (cost_maps) jest używana jako DODATKOWE PRZESUNIĘCIE przy
    wyborze startowych kandydatów, ale sama permutacja jest kluczowa.

    Args:
        cost_maps:  Lista map kosztów (nieużywane w obecnej implementacji –
                    zachowane dla kompatybilności API; przyszła optymalizacja
                    może je wykorzystać przez pre-embedded cost snapshot).
        perm_key:   Klucz HKDF (32 B) dla permutacji.
        n_pixels:   Całkowita liczba pikseli.
        alpha:      Współczynnik osadzania (0.0–1.0); ile pikseli użyć.

    Returns:
        Tablica indeksów pikseli do użycia (długość = alpha * n_pixels).
    """
    n_use = max(1, int(n_pixels * alpha))

    # Generujemy indeksy 0..n_pixels-1 i permutujemy kluczem
    # (Fisher-Yates – deterministyczny, niezależny od treści obrazu)
    rng = _seeded_rng(perm_key)
    all_idx = np.arange(n_pixels, dtype=np.intp)
    rng.shuffle(all_idx)

    return all_idx[:n_use]


def _seeded_rng(key: bytes) -> np.random.Generator:
    """Tworzy deterministyczny Generator numpy na podstawie klucza."""
    seed_int = int.from_bytes(key[:8], 'little')
    return np.random.default_rng(seed_int)
