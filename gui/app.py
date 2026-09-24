"""
gui/app.py – Main application window.

Uses CustomTkinter for a modern dark-mode UI with tabbed navigation.
"""

from __future__ import annotations

import threading
from pathlib import Path

import customtkinter as ctk

from .key_panel     import KeyPanel
from .encrypt_panel import EncryptPanel
from .decrypt_panel import DecryptPanel
from .history_panel import HistoryPanel
from .steg_panel    import StegPanel
from crypto.key_manager import KeyManager
from utils.logger import OperationLogger

# ── App configuration ──────────────────────────────────────────────────────────
APP_TITLE   = 'ECC File Encryptor'
APP_VERSION = '1.0'
WIN_W, WIN_H = 1100, 720

ctk.set_appearance_mode('dark')
ctk.set_default_color_theme('blue')

# Colour palette
C_BG        = '#0f1117'
C_SIDEBAR   = '#161b22'
C_CARD      = '#1c2333'
C_ACCENT    = '#58a6ff'
C_ACCENT2   = '#3fb950'
C_WARN      = '#f78166'
C_TEXT      = '#e6edf3'
C_SUBTEXT   = '#8b949e'
C_BORDER    = '#30363d'


class App(ctk.CTk):
    def __init__(self, base_dir: Path):
        super().__init__()
        self.base_dir = base_dir
        self.keys_dir = base_dir / 'keys'
        self.log_dir  = base_dir

        self.key_manager = KeyManager(self.keys_dir)
        self.logger      = OperationLogger(self.log_dir)

        self._configure_window()
        self._build_ui()

    # ── Window setup ───────────────────────────────────────────────────────────

    def _configure_window(self) -> None:
        self.title(f'{APP_TITLE}  v{APP_VERSION}')
        self.geometry(f'{WIN_W}x{WIN_H}')
        self.minsize(900, 600)
        self.configure(fg_color=C_BG)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

    # ── UI Layout ──────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_sidebar()
        self._build_content_area()
        self._show_panel('encrypt')

    def _build_sidebar(self) -> None:
        self.sidebar = ctk.CTkFrame(
            self, width=220, fg_color=C_SIDEBAR,
            corner_radius=0, border_width=0,
        )
        self.sidebar.grid(row=0, column=0, sticky='nsew')
        self.sidebar.grid_rowconfigure(10, weight=1)
        self.sidebar.grid_propagate(False)

        # Logo / Title
        logo_frame = ctk.CTkFrame(self.sidebar, fg_color='transparent')
        logo_frame.grid(row=0, column=0, padx=20, pady=(24, 8), sticky='ew')

        ctk.CTkLabel(
            logo_frame,
            text='🔒',
            font=ctk.CTkFont(size=32),
        ).pack(side='left', padx=(0, 8))

        ctk.CTkLabel(
            logo_frame,
            text='ECC\nEncryptor',
            font=ctk.CTkFont(size=16, weight='bold'),
            text_color=C_TEXT,
            justify='left',
        ).pack(side='left')

        # Divider
        ctk.CTkFrame(self.sidebar, height=1, fg_color=C_BORDER).grid(
            row=1, column=0, sticky='ew', padx=12, pady=8)

        # Nav buttons
        self._nav_buttons: dict = {}
        nav_items = [
            ('encrypt',  '🔐  Szyfrowanie'),
            ('decrypt',  '🔓  Deszyfrowanie'),
            ('keys',     '🔑  Klucze'),
            ('history',  '📋  Historia'),
            ('steg',     '🕵️  Steganografia'),
        ]
        for row_idx, (key, label) in enumerate(nav_items, start=2):
            btn = ctk.CTkButton(
                self.sidebar,
                text=label,
                anchor='w',
                height=44,
                font=ctk.CTkFont(size=14),
                fg_color='transparent',
                hover_color=C_CARD,
                text_color=C_SUBTEXT,
                corner_radius=8,
                command=lambda k=key: self._show_panel(k),
            )
            btn.grid(row=row_idx, column=0, padx=10, pady=2, sticky='ew')
            self._nav_buttons[key] = btn

        # Version label at bottom
        ctk.CTkLabel(
            self.sidebar,
            text=f'v{APP_VERSION}  •  ECIES + AES-256-GCM',
            font=ctk.CTkFont(size=10),
            text_color=C_SUBTEXT,
        ).grid(row=11, column=0, padx=16, pady=16, sticky='sw')

    def _build_content_area(self) -> None:
        self.content = ctk.CTkFrame(self, fg_color=C_BG, corner_radius=0)
        self.content.grid(row=0, column=1, sticky='nsew')
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        self._panels: dict = {
            'encrypt': EncryptPanel(self.content, self.key_manager, self.logger, self._on_status),
            'decrypt': DecryptPanel(self.content, self.key_manager, self.logger, self._on_status),
            'keys':    KeyPanel(self.content, self.key_manager, self.logger, self._on_status),
            'history': HistoryPanel(self.content, self.logger),
            'steg':    StegPanel(self.content, self.logger, self._on_status),
        }
        for panel in self._panels.values():
            panel.grid(row=0, column=0, sticky='nsew')

    def _show_panel(self, name: str) -> None:
        # Update nav button styles
        for key, btn in self._nav_buttons.items():
            if key == name:
                btn.configure(fg_color=C_CARD, text_color=C_ACCENT)
            else:
                btn.configure(fg_color='transparent', text_color=C_SUBTEXT)

        # Raise the selected panel
        self._panels[name].tkraise()

        # Refresh panel if it has a refresh method
        panel = self._panels[name]
        if hasattr(panel, 'refresh'):
            panel.refresh()

    def _on_status(self, message: str, is_error: bool = False) -> None:
        """Called by child panels to show a status toast."""
        # Simple approach: update history panel and print to console
        print(f"[{'ERROR' if is_error else 'INFO'}] {message}")
        if 'history' in self._panels:
            self._panels['history'].refresh()


def launch(base_dir: Path) -> None:
    app = App(base_dir)
    app.mainloop()
