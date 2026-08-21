"""
gui/encrypt_panel.py – File / folder encryption panel.

Features:
  • Select single files or entire folders (auto-zipped)
  • Choose one or more recipient public keys
  • Optional: sign with own Ed25519 key
  • Optional: paranoid double-curve mode
  • Optional: securely delete originals after encryption
  • Progress bar for the operation
  • Drag-and-drop support (clicking the drop zone opens file dialog)
"""

from __future__ import annotations

import threading
import zipfile
import tempfile
import hashlib
from pathlib import Path
from typing import Callable, List, Optional

import customtkinter as ctk
import tkinter.filedialog as fd
import tkinter.messagebox as mb

from crypto.key_manager import KeyManager
from crypto.ecc_core import encrypt_file
from utils.logger import OperationLogger
from utils.secure_delete import secure_delete

C_BG      = '#0f1117'
C_CARD    = '#1c2333'
C_CARD2   = '#21262d'
C_ACCENT  = '#58a6ff'
C_GREEN   = '#3fb950'
C_RED     = '#f78166'
C_ORANGE  = '#d29922'
C_TEXT    = '#e6edf3'
C_SUB     = '#8b949e'
C_BORDER  = '#30363d'


class EncryptPanel(ctk.CTkFrame):
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
        scroll.grid(row=0, column=0, sticky='nsew', padx=0, pady=0)
        scroll.grid_columnconfigure(0, weight=1)

        row = 0

        # ── Header ────────────────────────────────────────────────────────────
        ctk.CTkLabel(
            scroll, text='🔐  Szyfrowanie plików',
            font=ctk.CTkFont(size=24, weight='bold'),
            text_color=C_TEXT,
        ).grid(row=row, column=0, sticky='w', padx=28, pady=(28, 4)); row += 1

        ctk.CTkLabel(
            scroll,
            text='Zaszyfruj dowolny plik lub folder algorytmem ECIES (X25519 + AES-256-GCM)',
            font=ctk.CTkFont(size=13), text_color=C_SUB,
        ).grid(row=row, column=0, sticky='w', padx=28, pady=(0, 24)); row += 1

        # ── Drop zone ─────────────────────────────────────────────────────────
        self.drop_frame = ctk.CTkFrame(
            scroll, fg_color=C_CARD, corner_radius=16,
            border_width=2, border_color=C_BORDER,
        )
        self.drop_frame.grid(row=row, column=0, sticky='ew', padx=28, pady=(0, 12))
        self.drop_frame.grid_columnconfigure(0, weight=1)
        row += 1

        self.drop_label = ctk.CTkLabel(
            self.drop_frame,
            text='📂\n\nKliknij aby wybrać pliki lub folder',
            font=ctk.CTkFont(size=15),
            text_color=C_SUB,
            justify='center',
        )
        self.drop_label.pack(pady=32)
        self.drop_frame.bind('<Button-1>', lambda e: self._pick_files())
        self.drop_label.bind('<Button-1>', lambda e: self._pick_files())

        # File / folder buttons
        btn_row = ctk.CTkFrame(scroll, fg_color='transparent')
        btn_row.grid(row=row, column=0, sticky='w', padx=28, pady=(0, 24)); row += 1

        ctk.CTkButton(
            btn_row, text='📄  Wybierz pliki',
            height=38, corner_radius=8,
            fg_color=C_CARD2, hover_color=C_BORDER,
            command=self._pick_files,
        ).pack(side='left', padx=(0, 8))

        ctk.CTkButton(
            btn_row, text='📁  Wybierz folder',
            height=38, corner_radius=8,
            fg_color=C_CARD2, hover_color=C_BORDER,
            command=self._pick_folder,
        ).pack(side='left')

        # ── Section: Recipients ───────────────────────────────────────────────
        self._section(scroll, row, '🔑  Odbiorcy (klucze publiczne)'); row += 1

        rec_frame = ctk.CTkFrame(scroll, fg_color=C_CARD, corner_radius=12)
        rec_frame.grid(row=row, column=0, sticky='ew', padx=28, pady=(0, 24)); row += 1
        rec_frame.grid_columnconfigure(0, weight=1)

        self._recipients_frame = rec_frame
        self._recipient_vars: dict = {}
        self._refresh_recipient_checkboxes()

        # ── Section: Signing ──────────────────────────────────────────────────
        self._section(scroll, row, '✍️  Podpis cyfrowy (opcjonalnie)'); row += 1

        sign_card = ctk.CTkFrame(scroll, fg_color=C_CARD, corner_radius=12)
        sign_card.grid(row=row, column=0, sticky='ew', padx=28, pady=(0, 24)); row += 1
        sign_card.grid_columnconfigure(1, weight=1)

        self._sign_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            sign_card, text='Podpisz plik Ed25519',
            variable=self._sign_var, text_color=C_TEXT,
            command=self._toggle_sign,
        ).grid(row=0, column=0, padx=16, pady=12, sticky='w')

        self._signer_label = ctk.CTkLabel(sign_card, text='Klucz podpisującego:',
                                          text_color=C_SUB, font=ctk.CTkFont(size=12))
        self._signer_label.grid(row=0, column=1, padx=8, sticky='e')

        self._signer_menu = ctk.CTkOptionMenu(
            sign_card, values=['(wybierz)'],
            width=180, fg_color=C_CARD2,
        )
        self._signer_menu.grid(row=0, column=2, padx=16, pady=12, sticky='e')
        self._signer_label.grid_remove()
        self._signer_menu.grid_remove()

        ctk.CTkLabel(sign_card, text='(wymaga hasła do klucza prywatnego)',
                     text_color=C_SUB, font=ctk.CTkFont(size=11)).grid(
            row=1, column=0, columnspan=3, padx=16, pady=(0, 12), sticky='w')

        # ── Section: Options ──────────────────────────────────────────────────
        self._section(scroll, row, '⚙️  Opcje'); row += 1

        opt_card = ctk.CTkFrame(scroll, fg_color=C_CARD, corner_radius=12)
        opt_card.grid(row=row, column=0, sticky='ew', padx=28, pady=(0, 24)); row += 1

        self._paranoid_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            opt_card,
            text='🛡️  Tryb paranoidalny – podwójna krzywa (X25519 + P-521)',
            variable=self._paranoid_var, text_color=C_ORANGE,
        ).pack(anchor='w', padx=16, pady=(12, 4))

        self._shred_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            opt_card,
            text='🔥  Bezpieczne usunięcie oryginału po zaszyfrowaniu',
            variable=self._shred_var, text_color=C_RED,
        ).pack(anchor='w', padx=16, pady=(4, 12))

        # ── Progress ──────────────────────────────────────────────────────────
        self._progress = ctk.CTkProgressBar(scroll, height=6, corner_radius=3,
                                            progress_color=C_GREEN)
        self._progress.grid(row=row, column=0, sticky='ew', padx=28, pady=(0, 4)); row += 1
        self._progress.set(0)
        self._progress_label = ctk.CTkLabel(scroll, text='', text_color=C_SUB,
                                             font=ctk.CTkFont(size=12))
        self._progress_label.grid(row=row, column=0, sticky='w', padx=28, pady=(0, 16)); row += 1

        # ── Encrypt button ────────────────────────────────────────────────────
        self._encrypt_btn = ctk.CTkButton(
            scroll, text='🔐  Szyfruj',
            height=52, corner_radius=12,
            font=ctk.CTkFont(size=17, weight='bold'),
            fg_color=C_ACCENT, hover_color='#1f6feb',
            command=self._start_encrypt,
        )
        self._encrypt_btn.grid(row=row, column=0, sticky='ew', padx=28, pady=(0, 32)); row += 1

    def _section(self, parent, row, title: str) -> None:
        ctk.CTkLabel(
            parent, text=title,
            font=ctk.CTkFont(size=14, weight='bold'),
            text_color=C_TEXT,
        ).grid(row=row, column=0, sticky='w', padx=28, pady=(0, 6))

    # ── Recipient checkboxes ───────────────────────────────────────────────────

    def _refresh_recipient_checkboxes(self) -> None:
        for w in self._recipients_frame.winfo_children():
            w.destroy()
        self._recipient_vars.clear()

        keys = self.km.list_keys()
        if not keys:
            ctk.CTkLabel(
                self._recipients_frame,
                text='Brak kluczy. Przejdź do zakładki Klucze i wygeneruj parę.',
                text_color=C_SUB, font=ctk.CTkFont(size=12),
            ).pack(padx=16, pady=16)
            return

        for name in sorted(keys):
            var = ctk.BooleanVar(value=False)
            self._recipient_vars[name] = var
            ctk.CTkCheckBox(
                self._recipients_frame,
                text=f'🔑  {name}',
                variable=var, text_color=C_TEXT,
            ).pack(anchor='w', padx=16, pady=4)

        # Padding
        ctk.CTkFrame(self._recipients_frame, height=8, fg_color='transparent').pack()

    def refresh(self) -> None:
        self._refresh_recipient_checkboxes()
        # Update signer menu
        keys = [k for k in self.km.list_keys() if not self.km.is_recipient_only(k)]
        self._signer_menu.configure(values=keys or ['(brak kluczy)'])

    # ── File selection ─────────────────────────────────────────────────────────

    def _pick_files(self) -> None:
        paths = fd.askopenfilenames(title='Wybierz pliki do zaszyfrowania')
        if paths:
            self._selected_paths = [Path(p) for p in paths]
            self._update_drop_label()

    def _pick_folder(self) -> None:
        folder = fd.askdirectory(title='Wybierz folder do zaszyfrowania')
        if folder:
            self._selected_paths = [Path(folder)]
            self._update_drop_label()

    def _update_drop_label(self) -> None:
        if not self._selected_paths:
            self.drop_label.configure(
                text='📂\n\nKliknij aby wybrać pliki lub folder', text_color=C_SUB)
            return
        names = [p.name for p in self._selected_paths[:3]]
        extra = len(self._selected_paths) - 3
        text = '✅  ' + '\n'.join(names)
        if extra > 0:
            text += f'\n… i {extra} więcej'
        self.drop_label.configure(text=text, text_color=C_GREEN)

    # ── Sign toggle ────────────────────────────────────────────────────────────

    def _toggle_sign(self) -> None:
        if self._sign_var.get():
            self._signer_label.grid()
            self._signer_menu.grid()
        else:
            self._signer_label.grid_remove()
            self._signer_menu.grid_remove()

    # ── Encryption worker ──────────────────────────────────────────────────────

    def _start_encrypt(self) -> None:
        if not self._selected_paths:
            mb.showwarning('Brak plików', 'Wybierz pliki lub folder do zaszyfrowania.')
            return

        selected_recipients = [n for n, v in self._recipient_vars.items() if v.get()]
        if not selected_recipients:
            mb.showwarning('Brak odbiorców', 'Wybierz co najmniej jednego odbiorcę.')
            return

        paranoid = self._paranoid_var.get()

        # Check paranoid keys
        if paranoid:
            for name in selected_recipients:
                info = self.km.get_public_info(name)
                if not info.get('p521_pub'):
                    mb.showerror('Tryb paranoidalny',
                                 f"Klucz '{name}' nie ma składowej P-521.\n"
                                 "Wygeneruj klucz z trybem paranoidalnym.")
                    return

        # Build recipient public key lists
        rec_x25519 = [self.km.load_x25519_public(n) for n in selected_recipients]
        rec_p521 = None
        if paranoid:
            rec_p521 = [self.km.load_p521_public(n) for n in selected_recipients]

        # Signing
        sign_priv: Optional[bytes] = None
        sign_name: Optional[str] = None
        if self._sign_var.get():
            sign_name = self._signer_menu.get()
            if sign_name in ('(wybierz)', '(brak kluczy)', ''):
                mb.showwarning('Brak klucza', 'Wybierz klucz do podpisania.')
                return
            pwd = self._ask_password(f"Hasło dla klucza '{sign_name}':")
            if pwd is None:
                return
            try:
                sign_priv = self.km.load_ed25519_private(sign_name, pwd)
            except Exception as e:
                mb.showerror('Błąd hasła', str(e))
                return

        self._encrypt_btn.configure(state='disabled', text='Szyfrowanie…')
        self._progress.set(0)
        self._progress_label.configure(text='Przygotowanie…')

        threading.Thread(
            target=self._encrypt_worker,
            args=(self._selected_paths, rec_x25519, sign_priv, paranoid, rec_p521,
                  selected_recipients, sign_name),
            daemon=True,
        ).start()

    def _encrypt_worker(self, paths, rec_x25519, sign_priv, paranoid, rec_p521,
                        rec_names, sign_name) -> None:
        encrypted_count = 0
        errors = []
        total = len(paths)

        for idx, path in enumerate(paths):
            try:
                self.after(0, self._progress_label.configure,
                           {'text': f'Szyfrowanie: {path.name} ({idx + 1}/{total})'})

                # Folder → zip first
                tmp_zip = None
                actual_path = path
                if path.is_dir():
                    tmp_zip = Path(tempfile.mktemp(suffix='.zip'))
                    with zipfile.ZipFile(tmp_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
                        for f in path.rglob('*'):
                            if f.is_file():
                                zf.write(f, f.relative_to(path.parent))
                    actual_path = tmp_zip

                output_path = actual_path.parent / (actual_path.name + '.ecc')

                encrypt_file(
                    input_path=actual_path,
                    output_path=output_path,
                    recipient_x25519_pub_keys=rec_x25519,
                    signing_ed25519_priv_key=sign_priv,
                    paranoid=paranoid,
                    recipient_p521_pub_keys=rec_p521,
                )

                # SHA-256 of output for logging
                sha = hashlib.sha256(output_path.read_bytes()).hexdigest()[:16]

                self.logger.log(
                    'encrypt',
                    input=str(path),
                    output=str(output_path),
                    recipients=rec_names,
                    signed=(sign_name is not None),
                    paranoid=paranoid,
                    sha256_prefix=sha,
                )

                # Shred original
                if self._shred_var.get():
                    if actual_path != path:
                        secure_delete(tmp_zip)  # delete temp zip
                    else:
                        secure_delete(path)
                elif tmp_zip and tmp_zip.exists():
                    tmp_zip.unlink()  # just clean up temp

                encrypted_count += 1
                self.after(0, self._progress.set, (idx + 1) / total)

            except Exception as e:
                errors.append(f'{path.name}: {e}')

        def finish():
            self._encrypt_btn.configure(state='normal', text='🔐  Szyfruj')
            if errors:
                self._progress_label.configure(
                    text=f'Ukończono z błędami: {", ".join(errors[:2])}',
                    text_color=C_RED,
                )
                mb.showerror('Błędy szyfrowania', '\n'.join(errors))
            else:
                self._progress_label.configure(
                    text=f'✅  Zaszyfrowano {encrypted_count} plik(ów).',
                    text_color=C_GREEN,
                )
                self._progress.set(1)
            self.status_cb(f'Szyfrowanie: {encrypted_count} ok, {len(errors)} błędów.')

        self.after(0, finish)

    # ── Password dialog ────────────────────────────────────────────────────────

    def _ask_password(self, prompt: str) -> Optional[str]:
        result = [None]
        dlg = ctk.CTkToplevel(self)
        dlg.title('Hasło klucza')
        dlg.geometry('360x180')
        dlg.grab_set()
        dlg.configure(fg_color=C_CARD)
        dlg.resizable(False, False)

        ctk.CTkLabel(dlg, text=prompt, text_color=C_TEXT).pack(pady=(24, 8))
        entry = ctk.CTkEntry(dlg, show='•', height=38, width=280)
        entry.pack()
        entry.focus()

        def confirm(event=None):
            result[0] = entry.get()
            dlg.destroy()

        entry.bind('<Return>', confirm)
        ctk.CTkButton(dlg, text='OK', fg_color=C_ACCENT,
                      command=confirm, height=38).pack(pady=16)
        dlg.wait_window()
        return result[0]
