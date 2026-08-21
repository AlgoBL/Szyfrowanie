"""
gui/decrypt_panel.py – File decryption panel.

Features:
  • Select one or more .ecc files
  • Choose decryption key (private)
  • Password prompt for private key
  • Ed25519 signature verification with visual result
  • Progress bar
  • Optional: securely delete .ecc file after decryption
"""

from __future__ import annotations

import threading
import hashlib
from pathlib import Path
from typing import Callable, List, Optional

import customtkinter as ctk
import tkinter.filedialog as fd
import tkinter.messagebox as mb

from crypto.key_manager import KeyManager
from crypto.ecc_core import decrypt_file
from utils.logger import OperationLogger
from utils.secure_delete import secure_delete

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


class DecryptPanel(ctk.CTkFrame):
    def __init__(self, parent, key_manager: KeyManager,
                 logger: OperationLogger, status_cb: Callable):
        super().__init__(parent, fg_color=C_BG, corner_radius=0)
        self.km = key_manager
        self.logger = logger
        self.status_cb = status_cb
        self._selected_paths: List[Path] = []
        self._build()

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        scroll = ctk.CTkScrollableFrame(self, fg_color='transparent')
        scroll.grid(row=0, column=0, sticky='nsew')
        scroll.grid_columnconfigure(0, weight=1)

        row = 0

        # ── Header ────────────────────────────────────────────────────────────
        ctk.CTkLabel(
            scroll, text='🔓  Deszyfrowanie plików',
            font=ctk.CTkFont(size=24, weight='bold'), text_color=C_TEXT,
        ).grid(row=row, column=0, sticky='w', padx=28, pady=(28, 4)); row += 1

        ctk.CTkLabel(
            scroll,
            text='Odszyfruj pliki .ecc przy użyciu swojego klucza prywatnego',
            font=ctk.CTkFont(size=13), text_color=C_SUB,
        ).grid(row=row, column=0, sticky='w', padx=28, pady=(0, 24)); row += 1

        # ── Drop zone ─────────────────────────────────────────────────────────
        drop = ctk.CTkFrame(scroll, fg_color=C_CARD, corner_radius=16,
                            border_width=2, border_color=C_BORDER)
        drop.grid(row=row, column=0, sticky='ew', padx=28, pady=(0, 12)); row += 1
        drop.grid_columnconfigure(0, weight=1)

        self._drop_label = ctk.CTkLabel(
            drop,
            text='🔒\n\nKliknij aby wybrać pliki .ecc',
            font=ctk.CTkFont(size=15), text_color=C_SUB, justify='center',
        )
        self._drop_label.pack(pady=32)
        drop.bind('<Button-1>', lambda e: self._pick_files())
        self._drop_label.bind('<Button-1>', lambda e: self._pick_files())

        ctk.CTkButton(
            scroll, text='📂  Wybierz pliki .ecc',
            height=38, corner_radius=8,
            fg_color=C_CARD2, hover_color=C_BORDER,
            command=self._pick_files,
        ).grid(row=row, column=0, sticky='w', padx=28, pady=(0, 24)); row += 1

        # ── Key selection ─────────────────────────────────────────────────────
        self._section(scroll, row, '🔑  Klucz prywatny (twój)'); row += 1

        key_card = ctk.CTkFrame(scroll, fg_color=C_CARD, corner_radius=12)
        key_card.grid(row=row, column=0, sticky='ew', padx=28, pady=(0, 24)); row += 1
        key_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(key_card, text='Klucz:', text_color=C_SUB,
                     font=ctk.CTkFont(size=13)).grid(
            row=0, column=0, padx=16, pady=16, sticky='w')

        self._key_menu = ctk.CTkOptionMenu(
            key_card, values=['(wybierz klucz)'],
            width=220, fg_color=C_CARD2,
        )
        self._key_menu.grid(row=0, column=1, padx=16, pady=16, sticky='w')

        ctk.CTkLabel(key_card, text='Hasło:', text_color=C_SUB,
                     font=ctk.CTkFont(size=13)).grid(
            row=1, column=0, padx=16, pady=(0, 16), sticky='w')

        self._pwd_entry = ctk.CTkEntry(key_card, show='•', height=38, width=220,
                                       placeholder_text='Hasło do klucza prywatnego')
        self._pwd_entry.grid(row=1, column=1, padx=16, pady=(0, 16), sticky='w')

        # ── Options ───────────────────────────────────────────────────────────
        self._section(scroll, row, '⚙️  Opcje'); row += 1

        opt_card = ctk.CTkFrame(scroll, fg_color=C_CARD, corner_radius=12)
        opt_card.grid(row=row, column=0, sticky='ew', padx=28, pady=(0, 24)); row += 1

        self._verify_sig_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            opt_card,
            text='✅  Weryfikuj podpis cyfrowy (Ed25519)',
            variable=self._verify_sig_var,
            text_color=C_TEXT,
        ).pack(anchor='w', padx=16, pady=(12, 4))

        self._shred_enc_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            opt_card,
            text='🔥  Bezpieczne usunięcie pliku .ecc po deszyfrowaniu',
            variable=self._shred_enc_var, text_color=C_RED,
        ).pack(anchor='w', padx=16, pady=(4, 12))

        # ── Output directory ──────────────────────────────────────────────────
        self._section(scroll, row, '📁  Folder docelowy'); row += 1

        out_card = ctk.CTkFrame(scroll, fg_color=C_CARD, corner_radius=12)
        out_card.grid(row=row, column=0, sticky='ew', padx=28, pady=(0, 24)); row += 1
        out_card.grid_columnconfigure(1, weight=1)

        self._out_dir_var = ctk.StringVar(value='(obok oryginału)')
        ctk.CTkLabel(out_card, text='Zapisz do:', text_color=C_SUB,
                     font=ctk.CTkFont(size=13)).grid(row=0, column=0, padx=16, pady=12)

        ctk.CTkEntry(out_card, textvariable=self._out_dir_var, height=36,
                     state='disabled').grid(row=0, column=1, padx=8, pady=12, sticky='ew')

        ctk.CTkButton(
            out_card, text='Zmień', width=80, height=36,
            fg_color=C_CARD2, hover_color=C_BORDER,
            command=self._pick_out_dir,
        ).grid(row=0, column=2, padx=16, pady=12)

        self._custom_out_dir: Optional[Path] = None

        # ── Progress ──────────────────────────────────────────────────────────
        self._progress = ctk.CTkProgressBar(scroll, height=6, corner_radius=3,
                                            progress_color=C_ACCENT)
        self._progress.grid(row=row, column=0, sticky='ew', padx=28, pady=(0, 4)); row += 1
        self._progress.set(0)

        self._status_label = ctk.CTkLabel(scroll, text='', text_color=C_SUB,
                                          font=ctk.CTkFont(size=12))
        self._status_label.grid(row=row, column=0, sticky='w', padx=28, pady=(0, 16)); row += 1

        # ── Decrypt button ────────────────────────────────────────────────────
        self._decrypt_btn = ctk.CTkButton(
            scroll, text='🔓  Deszyfruj',
            height=52, corner_radius=12,
            font=ctk.CTkFont(size=17, weight='bold'),
            fg_color='#2ea043', hover_color=C_GREEN,
            command=self._start_decrypt,
        )
        self._decrypt_btn.grid(row=row, column=0, sticky='ew', padx=28, pady=(0, 32)); row += 1

        self.refresh()

    def _section(self, parent, row, title: str) -> None:
        ctk.CTkLabel(
            parent, text=title,
            font=ctk.CTkFont(size=14, weight='bold'), text_color=C_TEXT,
        ).grid(row=row, column=0, sticky='w', padx=28, pady=(0, 6))

    def refresh(self) -> None:
        keys = [k for k in self.km.list_keys() if not self.km.is_recipient_only(k)]
        self._key_menu.configure(values=keys or ['(brak kluczy prywatnych)'])
        if keys:
            self._key_menu.set(keys[0])

    def _pick_files(self) -> None:
        paths = fd.askopenfilenames(
            title='Wybierz pliki .ecc',
            filetypes=[('Zaszyfrowane pliki ECC', '*.ecc'), ('All files', '*.*')],
        )
        if paths:
            self._selected_paths = [Path(p) for p in paths]
            names = [p.name for p in self._selected_paths[:3]]
            extra = len(self._selected_paths) - 3
            text = '🔓  ' + '\n'.join(names)
            if extra > 0:
                text += f'\n… i {extra} więcej'
            self._drop_label.configure(text=text, text_color=C_ACCENT)

    def _pick_out_dir(self) -> None:
        d = fd.askdirectory(title='Folder docelowy')
        if d:
            self._custom_out_dir = Path(d)
            self._out_dir_var.set(d)

    def _start_decrypt(self) -> None:
        if not self._selected_paths:
            mb.showwarning('Brak plików', 'Wybierz pliki .ecc do odszyfrowania.')
            return

        key_name = self._key_menu.get()
        if key_name in ('(wybierz klucz)', '(brak kluczy prywatnych)'):
            mb.showwarning('Brak klucza', 'Wybierz klucz prywatny.')
            return

        password = self._pwd_entry.get()
        try:
            priv_x25519 = self.km.load_x25519_private(key_name, password)
        except Exception as e:
            mb.showerror('Błąd hasła / klucza', str(e))
            return

        priv_p521: Optional[bytes] = None
        info = self.km.get_public_info(key_name)
        if info.get('paranoid'):
            try:
                priv_p521 = self.km.load_p521_private(key_name, password)
            except Exception as e:
                mb.showerror('Błąd klucza P-521', str(e))
                return

        self._decrypt_btn.configure(state='disabled', text='Deszyfrowanie…')
        self._progress.set(0)
        self._status_label.configure(text='Przygotowanie…', text_color=C_SUB)

        threading.Thread(
            target=self._decrypt_worker,
            args=(self._selected_paths, priv_x25519, priv_p521, key_name),
            daemon=True,
        ).start()

    def _decrypt_worker(self, paths, priv_x25519, priv_p521, key_name) -> None:
        total = len(paths)
        ok, errors, sig_results = 0, [], []

        for idx, path in enumerate(paths):
            self.after(0, self._status_label.configure,
                       {'text': f'Odszyfrowanie: {path.name} ({idx + 1}/{total})'})
            try:
                # Determine output path
                if self._custom_out_dir:
                    out_dir = self._custom_out_dir
                else:
                    out_dir = path.parent

                # Strip .ecc extension for output filename
                out_name = path.stem  # removes .ecc
                out_path = out_dir / out_name

                signer_pub = decrypt_file(
                    input_path=path,
                    output_path=out_path,
                    recipient_x25519_priv_key=priv_x25519,
                    paranoid_p521_priv_key=priv_p521,
                    verify_signature=self._verify_sig_var.get(),
                )

                sha = hashlib.sha256(out_path.read_bytes()).hexdigest()[:16]

                self.logger.log(
                    'decrypt',
                    input=str(path),
                    output=str(out_path),
                    key=key_name,
                    signature_verified=(signer_pub is not None),
                    signer_pub=signer_pub or '',
                    sha256_prefix=sha,
                )

                if signer_pub:
                    sig_results.append(f'✅ {path.name} – podpis OK\n   Sygnatariusz: {signer_pub[:16]}…')

                if self._shred_enc_var.get():
                    secure_delete(path)

                ok += 1
                self.after(0, self._progress.set, (idx + 1) / total)

            except Exception as e:
                errors.append(f'{path.name}: {e}')

        def finish():
            self._decrypt_btn.configure(state='normal', text='🔓  Deszyfruj')
            if errors:
                self._status_label.configure(
                    text=f'Błędy: {"; ".join(errors[:2])}', text_color=C_RED)
                mb.showerror('Błędy deszyfrowania', '\n'.join(errors))
            else:
                msg = f'✅  Odszyfrowano {ok} plik(ów).'
                if sig_results:
                    msg += f'  {len(sig_results)} z podpisem.'
                self._status_label.configure(text=msg, text_color=C_GREEN)
                self._progress.set(1)

                if sig_results:
                    mb.showinfo('Weryfikacja podpisów', '\n\n'.join(sig_results))

            self.status_cb(f'Deszyfrowanie: {ok} ok, {len(errors)} błędów.')

        self.after(0, finish)
