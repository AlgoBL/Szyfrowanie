"""
crypto/steganography/__init__.py – Multi-Layer Adaptive Steganography (MLAS).

Public API
----------
embed_into_image(carrier_path, payload_bytes, password, output_path, alpha)
extract_from_image(steg_path, password) -> bytes
carrier_capacity(image_path, alpha) -> int   # max payload bytes
"""

from .steg_engine import embed_into_image, extract_from_image, carrier_capacity

__all__ = ['embed_into_image', 'extract_from_image', 'carrier_capacity']
