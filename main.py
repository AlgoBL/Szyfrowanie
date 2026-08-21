"""
main.py – ECC File Encryptor entry point.

Checks dependencies, then launches the GUI.
"""

from __future__ import annotations

import sys
from pathlib import Path

# ── Dependency check ───────────────────────────────────────────────────────────

def _check_deps() -> None:
    missing = []
    try:
        import cryptography
    except ImportError:
        missing.append('cryptography')
    try:
        import customtkinter
    except ImportError:
        missing.append('customtkinter')
    try:
        import argon2
    except ImportError:
        missing.append('argon2-cffi')

    if missing:
        print('=' * 60)
        print('Brakujące zależności:')
        for m in missing:
            print(f'  • {m}')
        print()
        print('Zainstaluj je poleceniem:')
        print(f'  pip install {" ".join(missing)}')
        print('Lub wszystkie naraz:')
        print('  pip install -r requirements.txt')
        print('=' * 60)
        sys.exit(1)


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    _check_deps()

    # Base directory = folder containing this script
    base_dir = Path(__file__).parent

    from gui.app import launch
    launch(base_dir)


if __name__ == '__main__':
    main()
