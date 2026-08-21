"""
gui/history_panel.py – Operation history / audit log panel.
"""

from __future__ import annotations

from typing import Callable
import tkinter.messagebox as mb

import customtkinter as ctk

from utils.logger import OperationLogger

C_BG     = '#0f1117'
C_CARD   = '#1c2333'
C_CARD2  = '#21262d'
C_ACCENT = '#58a6ff'
C_GREEN  = '#3fb950'
C_RED    = '#f78166'
C_ORANGE = '#d29922'
C_TEXT   = '#e6edf3'
C_SUB    = '#8b949e'
C_BORDER = '#30363d'

OP_ICONS = {
    'encrypt': ('🔐', C_ACCENT),
    'decrypt': ('🔓', C_GREEN),
    'keygen':  ('🔑', C_ORANGE),
    'delete_key': ('🗑', C_RED),
    'export_pem': ('↓', C_SUB),
    'import_pem': ('↑', C_SUB),
}


class HistoryPanel(ctk.CTkFrame):
    def __init__(self, parent, logger: OperationLogger):
        super().__init__(parent, fg_color=C_BG, corner_radius=0)
        self.logger = logger
        self._build()
        self.refresh()

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # ── Header ────────────────────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color=C_BG)
        header.grid(row=0, column=0, sticky='ew', padx=28, pady=(28, 12))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header, text='📋  Historia operacji',
            font=ctk.CTkFont(size=24, weight='bold'), text_color=C_TEXT,
        ).grid(row=0, column=0, sticky='w')

        ctk.CTkLabel(
            header,
            text='Kompletny log wszystkich operacji kryptograficznych',
            font=ctk.CTkFont(size=13), text_color=C_SUB,
        ).grid(row=1, column=0, sticky='w', pady=(4, 0))

        btn_frame = ctk.CTkFrame(header, fg_color='transparent')
        btn_frame.grid(row=0, column=1, rowspan=2, sticky='e')

        ctk.CTkButton(
            btn_frame, text='🔄  Odśwież', height=36, corner_radius=8,
            fg_color=C_CARD2, hover_color=C_BORDER,
            command=self.refresh,
        ).pack(side='left', padx=(0, 8))

        ctk.CTkButton(
            btn_frame, text='🗑  Wyczyść', height=36, corner_radius=8,
            fg_color='#3d1a1a', hover_color='#5c2222', text_color=C_RED,
            command=self._clear,
        ).pack(side='left')

        # ── Scrollable log list ───────────────────────────────────────────────
        self._list = ctk.CTkScrollableFrame(self, fg_color=C_CARD, corner_radius=12)
        self._list.grid(row=1, column=0, sticky='nsew', padx=28, pady=(0, 28))
        self._list.grid_columnconfigure(0, weight=1)

    def refresh(self) -> None:
        for w in self._list.winfo_children():
            w.destroy()

        entries = self.logger.read_recent(200)
        if not entries:
            ctk.CTkLabel(
                self._list,
                text='📭\n\nBrak historii operacji.',
                font=ctk.CTkFont(size=14),
                text_color=C_SUB, justify='center',
            ).pack(pady=40)
            return

        for entry in entries:
            self._entry_row(entry)

    def _entry_row(self, entry: dict) -> None:
        op = entry.get('op', '?')
        icon, color = OP_ICONS.get(op, ('•', C_SUB))

        ts = entry.get('ts', '')[:19].replace('T', '  ')

        row = ctk.CTkFrame(self._list, fg_color=C_CARD2, corner_radius=8)
        row.pack(fill='x', padx=8, pady=3)
        row.grid_columnconfigure(2, weight=1)

        # Icon badge
        badge = ctk.CTkLabel(
            row, text=icon, font=ctk.CTkFont(size=18),
            text_color=color, width=36,
        )
        badge.grid(row=0, column=0, padx=(12, 4), pady=10, rowspan=2)

        # Operation label
        ctk.CTkLabel(
            row, text=op.upper(),
            font=ctk.CTkFont(size=11, weight='bold'),
            text_color=color,
        ).grid(row=0, column=1, padx=4, pady=(10, 0), sticky='w')

        # Timestamp
        ctk.CTkLabel(
            row, text=ts,
            font=ctk.CTkFont(size=11),
            text_color=C_SUB,
        ).grid(row=0, column=2, padx=4, pady=(10, 0), sticky='e', columnspan=2)

        # Details
        details = self._format_details(op, entry)
        ctk.CTkLabel(
            row, text=details,
            font=ctk.CTkFont(size=11),
            text_color=C_TEXT,
            anchor='w', wraplength=700,
        ).grid(row=1, column=1, padx=4, pady=(0, 10), sticky='w', columnspan=3)

    def _format_details(self, op: str, e: dict) -> str:
        if op == 'encrypt':
            recs = ', '.join(e.get('recipients', []))
            signed = '✍️ podpisany' if e.get('signed') else ''
            paranoid = '🛡️ paranoidalny' if e.get('paranoid') else ''
            flags = '  '.join(filter(None, [signed, paranoid]))
            return f"{e.get('input', '')}  →  {e.get('output', '')}  [{recs}]  {flags}"
        elif op == 'decrypt':
            sig = '✅ podpis OK' if e.get('signature_verified') else ''
            return f"{e.get('input', '')}  →  {e.get('output', '')}  {sig}"
        elif op == 'keygen':
            paranoid = '🛡️ paranoidalny' if e.get('paranoid') else ''
            return f"'{e.get('key_name', '')}' {paranoid}"
        elif op == 'delete_key':
            return f"'{e.get('key_name', '')}'"
        elif op in ('export_pem', 'import_pem'):
            return f"'{e.get('key_name', '')}'  →  {e.get('path', '')}"
        return str(e)

    def _clear(self) -> None:
        if mb.askyesno('Wyczyść historię', 'Usunąć całą historię operacji?'):
            self.logger.clear()
            self.refresh()
