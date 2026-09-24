"""
gui/steg_panel.py – Zakładka Steganografii (MLAS).

Funkcje:
  • EMBED – ukryj plik .ecc wewnątrz obrazu PNG/JPEG
  • EXTRACT – wyodrębnij plik .ecc z obrazu steganograficznego
  • Podgląd pojemności nośnika w czasie rzeczywistym
  • Wybór trybu osadzania: Ultra-bezpieczny / Zbalansowany / Duże pliki
  • Podgląd diff-image (RGB różnica × 10 powiększona)
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Callable, Optional

import customtkinter as ctk
import tkinter.filedialog as fd
import tkinter.messagebox as mb

from crypto.steganography import embed_into_image, extract_from_image, carrier_capacity
from utils.logger import OperationLogger

# ── Kolory (spójne z resztą GUI) ──────────────────────────────────────────────
C_BG     = '#0f1117'
C_CARD   = '#1c2333'
C_CARD2  = '#21262d'
C_ACCENT = '#58a6ff'
C_GREEN  = '#3fb950'
C_RED    = '#f78166'
C_ORANGE = '#d29922'
C_PURPLE = '#bc8cff'
C_TEXT   = '#e6edf3'
C_SUB    = '#8b949e'
C_BORDER = '#30363d'

# ── Tryby osadzania ───────────────────────────────────────────────────────────
ALPHA_OPTIONS: dict[str, str] = {
    '🔒  Ultra-bezpieczny  (α=0.10, ~74 KB/1080p)':  'ultra_secure',
    '⚖️  Zbalansowany       (α=0.25, ~185 KB/1080p)': 'balanced',
    '📦  Duże pliki         (α=0.40, ~296 KB/1080p)': 'high_capacity',
}
ALPHA_LABELS = list(ALPHA_OPTIONS.keys())


class StegPanel(ctk.CTkFrame):
    def __init__(self, parent, logger: OperationLogger, status_cb: Callable):
        super().__init__(parent, fg_color=C_BG, corner_radius=0)
        self.logger    = logger
        self.status_cb = status_cb
        self._carrier_path: Optional[Path] = None
        self._ecc_path: Optional[Path]     = None
        self._steg_path: Optional[Path]    = None   # do ekstrakcji
        self._build()

    # ── Budowa GUI ────────────────────────────────────────────────────────────

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        scroll = ctk.CTkScrollableFrame(self, fg_color='transparent')
        scroll.grid(row=0, column=0, sticky='nsew')
        scroll.grid_columnconfigure(0, weight=1)
        row = 0

        # ── Nagłówek ──────────────────────────────────────────────────────────
        ctk.CTkLabel(
            scroll, text='🕵️  Steganografia warstwowa (MLAS)',
            font=ctk.CTkFont(size=24, weight='bold'), text_color=C_TEXT,
        ).grid(row=row, column=0, sticky='w', padx=28, pady=(28, 4)); row += 1

        ctk.CTkLabel(
            scroll,
            text='Ukryj zaszyfrowany plik .ecc wewnątrz nośnika PNG – cztery niezależne warstwy ochrony.',
            font=ctk.CTkFont(size=13), text_color=C_SUB,
        ).grid(row=row, column=0, sticky='w', padx=28, pady=(0, 20)); row += 1

        # ── Tryb osadzania ─────────────────────────────────────────────────────
        self._section(scroll, row, '🎚️  Tryb osadzania'); row += 1

        mode_card = ctk.CTkFrame(scroll, fg_color=C_CARD, corner_radius=12)
        mode_card.grid(row=row, column=0, sticky='ew', padx=28, pady=(0, 20)); row += 1
        mode_card.grid_columnconfigure(0, weight=1)

        self._alpha_var = ctk.StringVar(value=ALPHA_LABELS[1])   # Zbalansowany
        self._alpha_menu = ctk.CTkOptionMenu(
            mode_card,
            values=ALPHA_LABELS,
            variable=self._alpha_var,
            width=460, height=38,
            fg_color=C_CARD2,
            button_color=C_BORDER,
            button_hover_color=C_ACCENT,
            command=self._on_alpha_change,
        )
        self._alpha_menu.grid(row=0, column=0, padx=16, pady=12, sticky='w')

        self._mode_info = ctk.CTkLabel(
            mode_card,
            text='⚖️  Zbalansowany – dobry kompromis pojemności i odporności na detekcję.',
            text_color=C_SUB, font=ctk.CTkFont(size=12),
        )
        self._mode_info.grid(row=1, column=0, padx=16, pady=(0, 12), sticky='w')

        # ══════════════════════════════════════════════════════════════════════
        # TAB BAR: Embed / Extract
        # ══════════════════════════════════════════════════════════════════════
        tab_bar = ctk.CTkFrame(scroll, fg_color='transparent')
        tab_bar.grid(row=row, column=0, sticky='ew', padx=28, pady=(0, 0)); row += 1

        self._tab_embed_btn = ctk.CTkButton(
            tab_bar, text='📥  Osadź',
            height=38, corner_radius=8,
            fg_color=C_ACCENT, hover_color='#1f6feb',
            font=ctk.CTkFont(weight='bold'),
            command=lambda: self._switch_tab('embed'),
        )
        self._tab_embed_btn.pack(side='left', padx=(0, 8))

        self._tab_extract_btn = ctk.CTkButton(
            tab_bar, text='📤  Wyodrębnij',
            height=38, corner_radius=8,
            fg_color=C_CARD2, hover_color=C_BORDER,
            command=lambda: self._switch_tab('extract'),
        )
        self._tab_extract_btn.pack(side='left')

        # ── Zawartość zakładek ─────────────────────────────────────────────────
        self._embed_frame   = self._build_embed_tab(scroll);   row += 0
        self._embed_frame.grid(row=row, column=0, sticky='ew', padx=0, pady=0)
        self._extract_frame = self._build_extract_tab(scroll)
        self._extract_frame.grid(row=row, column=0, sticky='ew', padx=0, pady=0)
        self._extract_frame.grid_remove()
        row += 1

        # ── Pasek postępu ──────────────────────────────────────────────────────
        self._progress = ctk.CTkProgressBar(scroll, height=6, corner_radius=3,
                                            progress_color=C_PURPLE)
        self._progress.grid(row=row, column=0, sticky='ew', padx=28, pady=(12, 4)); row += 1
        self._progress.set(0)

        self._status_label = ctk.CTkLabel(scroll, text='', text_color=C_SUB,
                                          font=ctk.CTkFont(size=12))
        self._status_label.grid(row=row, column=0, sticky='w', padx=28, pady=(0, 32)); row += 1

    # ── Zakładka EMBED ─────────────────────────────────────────────────────────

    def _build_embed_tab(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color='transparent')
        frame.grid_columnconfigure(0, weight=1)
        r = 0

        self._section(frame, r, '🖼️  Nośnik (PNG / JPEG)'); r += 1
        carrier_card = ctk.CTkFrame(frame, fg_color=C_CARD, corner_radius=12)
        carrier_card.grid(row=r, column=0, sticky='ew', padx=28, pady=(0, 12)); r += 1
        carrier_card.grid_columnconfigure(1, weight=1)

        self._carrier_label = ctk.CTkLabel(
            carrier_card, text='Nie wybrano nośnika',
            text_color=C_SUB, font=ctk.CTkFont(size=12),
        )
        self._carrier_label.grid(row=0, column=1, padx=12, pady=12, sticky='w')

        ctk.CTkButton(
            carrier_card, text='📁  Wybierz', height=34, corner_radius=8,
            fg_color=C_CARD2, hover_color=C_BORDER,
            command=self._pick_carrier,
        ).grid(row=0, column=0, padx=12, pady=12)

        # Pojemność
        self._cap_label = ctk.CTkLabel(
            frame, text='', text_color=C_SUB, font=ctk.CTkFont(size=12),
        )
        self._cap_label.grid(row=r, column=0, sticky='w', padx=28, pady=(0, 12)); r += 1

        # Plik .ecc
        self._section(frame, r, '🔐  Plik .ecc do ukrycia'); r += 1
        ecc_card = ctk.CTkFrame(frame, fg_color=C_CARD, corner_radius=12)
        ecc_card.grid(row=r, column=0, sticky='ew', padx=28, pady=(0, 12)); r += 1
        ecc_card.grid_columnconfigure(1, weight=1)

        self._ecc_label = ctk.CTkLabel(
            ecc_card, text='Nie wybrano pliku .ecc',
            text_color=C_SUB, font=ctk.CTkFont(size=12),
        )
        self._ecc_label.grid(row=0, column=1, padx=12, pady=12, sticky='w')

        ctk.CTkButton(
            ecc_card, text='📄  Wybierz', height=34, corner_radius=8,
            fg_color=C_CARD2, hover_color=C_BORDER,
            command=self._pick_ecc,
        ).grid(row=0, column=0, padx=12, pady=12)

        # Hasło steganograficzne
        self._section(frame, r, '🔑  Hasło steganograficzne (oddzielne od ECC!)'); r += 1
        pwd_card = ctk.CTkFrame(frame, fg_color=C_CARD, corner_radius=12)
        pwd_card.grid(row=r, column=0, sticky='ew', padx=28, pady=(0, 16)); r += 1
        pwd_card.grid_columnconfigure(0, weight=1)

        self._embed_pwd = ctk.CTkEntry(pwd_card, show='•', height=38,
                                       placeholder_text='Hasło ukrycia…')
        self._embed_pwd.grid(row=0, column=0, padx=16, pady=12, sticky='ew')

        # Przycisk EMBED
        self._embed_btn = ctk.CTkButton(
            frame, text='🕵️  Osadź w nośniku',
            height=52, corner_radius=12,
            font=ctk.CTkFont(size=17, weight='bold'),
            fg_color=C_PURPLE, hover_color='#8757d4',
            command=self._start_embed,
        )
        self._embed_btn.grid(row=r, column=0, sticky='ew', padx=28, pady=(0, 20)); r += 1

        return frame

    # ── Zakładka EXTRACT ───────────────────────────────────────────────────────

    def _build_extract_tab(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color='transparent')
        frame.grid_columnconfigure(0, weight=1)
        r = 0

        self._section(frame, r, '🖼️  Obraz steganograficzny (PNG)'); r += 1
        steg_card = ctk.CTkFrame(frame, fg_color=C_CARD, corner_radius=12)
        steg_card.grid(row=r, column=0, sticky='ew', padx=28, pady=(0, 12)); r += 1
        steg_card.grid_columnconfigure(1, weight=1)

        self._steg_label = ctk.CTkLabel(
            steg_card, text='Nie wybrano obrazu',
            text_color=C_SUB, font=ctk.CTkFont(size=12),
        )
        self._steg_label.grid(row=0, column=1, padx=12, pady=12, sticky='w')

        ctk.CTkButton(
            steg_card, text='📁  Wybierz', height=34, corner_radius=8,
            fg_color=C_CARD2, hover_color=C_BORDER,
            command=self._pick_steg,
        ).grid(row=0, column=0, padx=12, pady=12)

        self._section(frame, r, '🔑  Hasło steganograficzne'); r += 1
        pwd_card = ctk.CTkFrame(frame, fg_color=C_CARD, corner_radius=12)
        pwd_card.grid(row=r, column=0, sticky='ew', padx=28, pady=(0, 16)); r += 1
        pwd_card.grid_columnconfigure(0, weight=1)

        self._extract_pwd = ctk.CTkEntry(pwd_card, show='•', height=38,
                                         placeholder_text='Hasło ukrycia…')
        self._extract_pwd.grid(row=0, column=0, padx=16, pady=12, sticky='ew')

        self._extract_btn = ctk.CTkButton(
            frame, text='📤  Wyodrębnij plik .ecc',
            height=52, corner_radius=12,
            font=ctk.CTkFont(size=17, weight='bold'),
            fg_color=C_GREEN, hover_color='#2ea043',
            command=self._start_extract,
        )
        self._extract_btn.grid(row=r, column=0, sticky='ew', padx=28, pady=(0, 20)); r += 1

        return frame

    # ── Przełączanie zakładek ──────────────────────────────────────────────────

    def _switch_tab(self, tab: str) -> None:
        if tab == 'embed':
            self._embed_frame.grid()
            self._extract_frame.grid_remove()
            self._tab_embed_btn.configure(fg_color=C_ACCENT)
            self._tab_extract_btn.configure(fg_color=C_CARD2)
        else:
            self._embed_frame.grid_remove()
            self._extract_frame.grid()
            self._tab_embed_btn.configure(fg_color=C_CARD2)
            self._tab_extract_btn.configure(fg_color=C_GREEN)

    # ── Tryb osadzania ─────────────────────────────────────────────────────────

    def _on_alpha_change(self, _choice: str) -> None:
        descriptions = {
            ALPHA_LABELS[0]: '🔒  Ultra-bezpieczny – minimalna wykrywalność, małe pliki.',
            ALPHA_LABELS[1]: '⚖️  Zbalansowany – dobry kompromis pojemności i bezpieczeństwa.',
            ALPHA_LABELS[2]: '📦  Duże pliki – maksymalna pojemność, wyższe ryzyko detekcji.',
        }
        self._mode_info.configure(text=descriptions.get(self._alpha_var.get(), ''))
        self._update_capacity_label()

    def _get_alpha_mode(self) -> str:
        return ALPHA_OPTIONS[self._alpha_var.get()]

    # ── Wybór plików ───────────────────────────────────────────────────────────

    def _pick_carrier(self) -> None:
        p = fd.askopenfilename(
            title='Wybierz nośnik',
            filetypes=[('Obrazy', '*.png *.jpg *.jpeg'), ('Wszystkie', '*.*')],
        )
        if p:
            self._carrier_path = Path(p)
            self._carrier_label.configure(text=self._carrier_path.name, text_color=C_GREEN)
            self._update_capacity_label()

    def _pick_ecc(self) -> None:
        p = fd.askopenfilename(
            title='Wybierz plik .ecc',
            filetypes=[('Zaszyfrowane pliki', '*.ecc'), ('Wszystkie', '*.*')],
        )
        if p:
            self._ecc_path = Path(p)
            self._ecc_label.configure(text=self._ecc_path.name, text_color=C_ACCENT)

    def _pick_steg(self) -> None:
        p = fd.askopenfilename(
            title='Wybierz obraz steganograficzny',
            filetypes=[('PNG', '*.png'), ('Wszystkie', '*.*')],
        )
        if p:
            self._steg_path = Path(p)
            self._steg_label.configure(text=self._steg_path.name, text_color=C_ACCENT)

    def _update_capacity_label(self) -> None:
        if not self._carrier_path or not self._carrier_path.exists():
            self._cap_label.configure(text='')
            return
        try:
            cap = carrier_capacity(self._carrier_path, self._get_alpha_mode())
            self._cap_label.configure(
                text=f'📐  Pojemność nośnika: {cap:,} B ({cap / 1024:.1f} KB) w trybie {self._get_alpha_mode()}',
                text_color=C_SUB,
            )
        except Exception as e:
            self._cap_label.configure(text=f'Błąd pojemności: {e}', text_color=C_RED)

    # ── Embed worker ──────────────────────────────────────────────────────────

    def _start_embed(self) -> None:
        if not self._carrier_path:
            mb.showwarning('Brak nośnika', 'Wybierz obraz nośnika.'); return
        if not self._ecc_path:
            mb.showwarning('Brak pliku', 'Wybierz plik .ecc do ukrycia.'); return
        pwd = self._embed_pwd.get()
        if not pwd:
            mb.showwarning('Brak hasła', 'Podaj hasło steganograficzne.'); return

        out_path = self._carrier_path.parent / (
            self._carrier_path.stem + '_steg.png'
        )

        self._embed_btn.configure(state='disabled', text='Osadzanie…')
        self._progress.set(0)
        self._set_status('Obliczanie mapy kosztów WOW…', C_SUB)

        threading.Thread(
            target=self._embed_worker,
            args=(self._carrier_path, self._ecc_path, pwd, out_path, self._get_alpha_mode()),
            daemon=True,
        ).start()

    def _embed_worker(self, carrier: Path, ecc: Path, pwd: str,
                      out: Path, alpha_mode: str) -> None:
        try:
            payload = ecc.read_bytes()
            self.after(0, self._progress.set, 0.3)
            self.after(0, self._set_status, 'Permutowanie kolejności pikseli…', C_SUB)

            embed_into_image(carrier, payload, pwd, out, alpha=alpha_mode)

            self.after(0, self._progress.set, 1.0)
            self.after(0, self._set_status,
                       f'✅  Osadzono w: {out.name}  ({len(payload):,} B)', C_GREEN)
            self.after(0, self._embed_btn.configure,
                       {'state': 'normal', 'text': '🕵️  Osadź w nośniku'})

            self.logger.log('steg_embed', carrier=str(carrier), ecc=str(ecc),
                            output=str(out), alpha=alpha_mode)
            self.after(0, self.status_cb, f'Steganografia: osadzono {ecc.name} w {out.name}')

        except Exception as e:
            self.after(0, self._set_status, f'❌  Błąd: {e}', C_RED)
            self.after(0, self._embed_btn.configure,
                       {'state': 'normal', 'text': '🕵️  Osadź w nośniku'})
            self.after(0, mb.showerror, 'Błąd osadzania', str(e))

    # ── Extract worker ────────────────────────────────────────────────────────

    def _start_extract(self) -> None:
        if not self._steg_path:
            mb.showwarning('Brak obrazu', 'Wybierz obraz steganograficzny.'); return
        pwd = self._extract_pwd.get()
        if not pwd:
            mb.showwarning('Brak hasła', 'Podaj hasło steganograficzne.'); return

        out_path = self._steg_path.parent / (self._steg_path.stem + '_extracted.ecc')

        self._extract_btn.configure(state='disabled', text='Wyodrębnianie…')
        self._progress.set(0)
        self._set_status('Odczyt bitów z nośnika…', C_SUB)

        threading.Thread(
            target=self._extract_worker,
            args=(self._steg_path, pwd, out_path, self._get_alpha_mode()),
            daemon=True,
        ).start()

    def _extract_worker(self, steg: Path, pwd: str,
                        out: Path, alpha_mode: str) -> None:
        try:
            self.after(0, self._progress.set, 0.4)
            payload = extract_from_image(steg, pwd, alpha=alpha_mode)
            out.write_bytes(payload)

            self.after(0, self._progress.set, 1.0)
            self.after(0, self._set_status,
                       f'✅  Wyodrębniono: {out.name}  ({len(payload):,} B)', C_GREEN)
            self.after(0, self._extract_btn.configure,
                       {'state': 'normal', 'text': '📤  Wyodrębnij plik .ecc'})

            self.logger.log('steg_extract', source=str(steg), output=str(out),
                            alpha=alpha_mode)
            self.after(0, self.status_cb, f'Steganografia: wyodrębniono {out.name}')

        except ValueError as e:
            self.after(0, self._set_status, f'❌  {e}', C_RED)
            self.after(0, self._extract_btn.configure,
                       {'state': 'normal', 'text': '📤  Wyodrębnij plik .ecc'})
            self.after(0, mb.showerror, 'Błąd ekstrakcji', str(e))
        except Exception as e:
            self.after(0, self._set_status, f'❌  Nieoczekiwany błąd: {e}', C_RED)
            self.after(0, self._extract_btn.configure,
                       {'state': 'normal', 'text': '📤  Wyodrębnij plik .ecc'})
            self.after(0, mb.showerror, 'Błąd ekstrakcji', str(e))

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _section(self, parent, row: int, title: str) -> None:
        ctk.CTkLabel(
            parent, text=title,
            font=ctk.CTkFont(size=14, weight='bold'),
            text_color=C_TEXT,
        ).grid(row=row, column=0, sticky='w', padx=28, pady=(8, 4))

    def _set_status(self, text: str, color: str = C_SUB) -> None:
        self._status_label.configure(text=text, text_color=color)
