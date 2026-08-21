"""
gui/key_panel.py – Key management panel.

Features:
  • List all key pairs
  • Generate new key pair (X25519 + Ed25519, optional P-521 paranoid mode)
  • View public key details
  • Export public key as PEM
  • Import foreign public key (PEM)
  • Delete key pair
"""

from __future__ import annotations

import threading
import tkinter as tk
import tkinter.messagebox as mb
import tkinter.filedialog as fd
from pathlib import Path
from typing import Callable, Optional

import customtkinter as ctk

from crypto.key_manager import KeyManager
from utils.logger import OperationLogger

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


class KeyPanel(ctk.CTkFrame):
    def __init__(self, parent, key_manager: KeyManager,
                 logger: OperationLogger, status_cb: Callable):
        super().__init__(parent, fg_color=C_BG, corner_radius=0)
        self.km = key_manager
        self.logger = logger
        self.status_cb = status_cb
        self._selected_key: Optional[str] = None
        self._build()

    def _build(self) -> None:
        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # ── Left list pane ────────────────────────────────────────────────────
        left = ctk.CTkFrame(self, fg_color=C_CARD, corner_radius=0, width=260)
        left.grid(row=0, column=0, sticky='nsew')
        left.grid_rowconfigure(2, weight=1)
        left.grid_propagate(False)

        ctk.CTkLabel(
            left, text='Klucze', font=ctk.CTkFont(size=16, weight='bold'),
            text_color=C_TEXT,
        ).grid(row=0, column=0, padx=16, pady=(20, 4), sticky='w')

        ctk.CTkLabel(
            left, text='Zarządzaj parami kluczy ECC',
            font=ctk.CTkFont(size=11), text_color=C_SUB,
        ).grid(row=1, column=0, padx=16, pady=(0, 12), sticky='w')

        # Key list using a scrollable frame
        self.key_list_frame = ctk.CTkScrollableFrame(
            left, fg_color='transparent', corner_radius=0,
        )
        self.key_list_frame.grid(row=2, column=0, sticky='nsew', padx=8, pady=0)
        self.key_list_frame.grid_columnconfigure(0, weight=1)

        # Bottom buttons
        btn_frame = ctk.CTkFrame(left, fg_color='transparent')
        btn_frame.grid(row=3, column=0, sticky='ew', padx=10, pady=12)
        btn_frame.grid_columnconfigure(0, weight=1)
        btn_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(
            btn_frame, text='+ Nowy', height=36, corner_radius=8,
            fg_color=C_ACCENT, hover_color='#1f6feb',
            font=ctk.CTkFont(size=13, weight='bold'),
            command=self._open_generate_dialog,
        ).grid(row=0, column=0, padx=(0, 4), sticky='ew')

        ctk.CTkButton(
            btn_frame, text='↑ Import', height=36, corner_radius=8,
            fg_color=C_CARD2, hover_color=C_BORDER,
            font=ctk.CTkFont(size=13),
            command=self._import_pem,
        ).grid(row=0, column=1, padx=(4, 0), sticky='ew')

        # ── Right detail pane ─────────────────────────────────────────────────
        self.detail = ctk.CTkFrame(self, fg_color=C_BG, corner_radius=0)
        self.detail.grid(row=0, column=1, sticky='nsew', padx=0, pady=0)
        self.detail.grid_rowconfigure(0, weight=1)
        self.detail.grid_columnconfigure(0, weight=1)

        self._detail_placeholder()
        self.refresh()

    def _detail_placeholder(self) -> None:
        for w in self.detail.winfo_children():
            w.destroy()
        ctk.CTkLabel(
            self.detail,
            text='🔑\n\nWybierz klucz z listy\nlub wygeneruj nowy',
            font=ctk.CTkFont(size=15),
            text_color=C_SUB,
            justify='center',
        ).place(relx=0.5, rely=0.45, anchor='center')

    # ── Key list ───────────────────────────────────────────────────────────────

    def refresh(self) -> None:
        for w in self.key_list_frame.winfo_children():
            w.destroy()

        keys = self.km.list_keys()
        if not keys:
            ctk.CTkLabel(
                self.key_list_frame,
                text='Brak kluczy.\nKliknij + Nowy.',
                text_color=C_SUB, font=ctk.CTkFont(size=12),
                justify='center',
            ).pack(pady=20)
            return

        for name in sorted(keys):
            is_rec_only = self.km.is_recipient_only(name)
            icon = '🌐' if is_rec_only else '🔑'
            card = ctk.CTkButton(
                self.key_list_frame,
                text=f'{icon}  {name}',
                anchor='w',
                height=40,
                corner_radius=8,
                fg_color=C_CARD2 if name == self._selected_key else 'transparent',
                hover_color=C_CARD2,
                text_color=C_ACCENT if name == self._selected_key else C_TEXT,
                font=ctk.CTkFont(size=13),
                command=lambda n=name: self._select_key(n),
            )
            card.pack(fill='x', padx=4, pady=2)

    def _select_key(self, name: str) -> None:
        self._selected_key = name
        self.refresh()
        self._show_key_detail(name)

    def _show_key_detail(self, name: str) -> None:
        for w in self.detail.winfo_children():
            w.destroy()

        try:
            info = self.km.get_public_info(name)
        except Exception as e:
            ctk.CTkLabel(self.detail, text=f'Błąd: {e}', text_color=C_RED).pack(pady=20)
            return

        # Scroll container
        scroll = ctk.CTkScrollableFrame(self.detail, fg_color='transparent')
        scroll.pack(fill='both', expand=True, padx=20, pady=20)
        scroll.grid_columnconfigure(0, weight=1)

        # Title
        row = 0
        ctk.CTkLabel(
            scroll,
            text=f'🔑  {info["name"]}',
            font=ctk.CTkFont(size=22, weight='bold'),
            text_color=C_TEXT,
        ).grid(row=row, column=0, sticky='w', pady=(0, 4)); row += 1

        badges = []
        if info['paranoid']:
            badges.append(('🛡️ Paranoidalny (X25519+P-521)', C_ORANGE))
        if self.km.is_recipient_only(name):
            badges.append(('🌐 Tylko odbiorca (publiczny)', C_ACCENT))
        else:
            badges.append(('🔐 Pełna para (prywatny+publiczny)', C_GREEN))

        _badge_bg = {
            C_ORANGE: '#3d2f0d',
            C_ACCENT:  '#0d2040',
            C_GREEN:   '#0d2e18',
            C_RED:     '#3d1a1a',
        }
        badge_frame = ctk.CTkFrame(scroll, fg_color='transparent')
        badge_frame.grid(row=row, column=0, sticky='w', pady=(0, 16)); row += 1
        for txt, col in badges:
            bg = _badge_bg.get(col, C_CARD2)
            ctk.CTkLabel(
                badge_frame, text=txt,
                fg_color=bg, text_color=col,
                corner_radius=6,
                font=ctk.CTkFont(size=11),
                padx=8, pady=3,
            ).pack(side='left', padx=(0, 6))

        ctk.CTkLabel(
            scroll, text=f'Utworzono: {info["created"][:19].replace("T", "  ")}',
            font=ctk.CTkFont(size=11), text_color=C_SUB,
        ).grid(row=row, column=0, sticky='w', pady=(0, 20)); row += 1

        # Key fields
        fields = [
            ('X25519 – Klucz publiczny (szyfrowanie)', info['x25519_pub']),
            ('Ed25519 – Klucz publiczny (podpis)', info['ed25519_pub']),
        ]
        if info['p521_pub']:
            fields.append(('P-521 – Klucz publiczny (paranoidalny)', info['p521_pub']))

        for label, value in fields:
            if not value:
                continue
            self._key_field(scroll, row, label, value)
            row += 1

        # Action buttons
        btn_row = ctk.CTkFrame(scroll, fg_color='transparent')
        btn_row.grid(row=row, column=0, sticky='w', pady=(20, 0))

        if not self.km.is_recipient_only(name):
            ctk.CTkButton(
                btn_row, text='↓ Eksportuj PEM',
                height=36, corner_radius=8,
                fg_color=C_ACCENT, hover_color='#1f6feb',
                command=lambda: self._export_pem(name),
            ).pack(side='left', padx=(0, 8))

        ctk.CTkButton(
            btn_row, text='🗑 Usuń',
            height=36, corner_radius=8,
            fg_color='#3d1a1a', hover_color='#5c2222',
            text_color=C_RED,
            command=lambda: self._delete_key(name),
        ).pack(side='left')

    def _key_field(self, parent, row, label: str, value: str) -> None:
        ctk.CTkLabel(
            parent, text=label,
            font=ctk.CTkFont(size=11, weight='bold'),
            text_color=C_SUB,
        ).grid(row=row * 2, column=0, sticky='w', pady=(8, 2))

        frame = ctk.CTkFrame(parent, fg_color=C_CARD2, corner_radius=8)
        frame.grid(row=row * 2 + 1, column=0, sticky='ew', pady=(0, 4))
        frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            frame,
            text=value[:32] + '…' + value[-16:] if len(value) > 64 else value,
            font=ctk.CTkFont(family='Consolas', size=11),
            text_color=C_GREEN,
            wraplength=500,
            justify='left',
        ).grid(row=0, column=0, padx=12, pady=8, sticky='w')

        ctk.CTkButton(
            frame, text='📋', width=32, height=28,
            fg_color='transparent', hover_color=C_BORDER,
            command=lambda v=value: self._copy_to_clipboard(v),
        ).grid(row=0, column=1, padx=4)

    def _copy_to_clipboard(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)

    # ── Generate dialog ────────────────────────────────────────────────────────

    def _open_generate_dialog(self) -> None:
        dlg = ctk.CTkToplevel(self)
        dlg.title('Generuj nową parę kluczy')
        dlg.geometry('500x560')
        dlg.minsize(460, 500)
        dlg.grab_set()
        dlg.configure(fg_color=C_CARD)
        dlg.resizable(True, True)

        ctk.CTkLabel(
            dlg, text='Nowa para kluczy ECC',
            font=ctk.CTkFont(size=18, weight='bold'),
            text_color=C_TEXT,
        ).pack(pady=(20, 2))
        ctk.CTkLabel(
            dlg, text='X25519 + Ed25519 (+ opcjonalnie P-521)',
            font=ctk.CTkFont(size=12), text_color=C_SUB,
        ).pack(pady=(0, 12))

        form = ctk.CTkFrame(dlg, fg_color='transparent')
        form.pack(fill='x', padx=30)

        ctk.CTkLabel(form, text='Nazwa klucza:', text_color=C_TEXT, anchor='w').pack(fill='x')
        name_entry = ctk.CTkEntry(form, placeholder_text='np. moje_klucze', height=38)
        name_entry.pack(fill='x', pady=(4, 12))

        ctk.CTkLabel(form, text='Hasło ochrony klucza prywatnego:', text_color=C_TEXT, anchor='w').pack(fill='x')
        pass_entry = ctk.CTkEntry(form, placeholder_text='Silne hasło…', show='•', height=38)
        pass_entry.pack(fill='x', pady=(4, 4))

        ctk.CTkLabel(form, text='Potwierdź hasło:', text_color=C_TEXT, anchor='w').pack(fill='x')
        pass2_entry = ctk.CTkEntry(form, placeholder_text='Powtórz hasło…', show='•', height=38)
        pass2_entry.pack(fill='x', pady=(4, 12))

        paranoid_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            form,
            text='🛡️  Tryb paranoidalny (X25519 + P-521)',
            variable=paranoid_var,
            text_color=C_ORANGE,
        ).pack(anchor='w', pady=(0, 8))

        status_lbl = ctk.CTkLabel(dlg, text='', text_color=C_RED, font=ctk.CTkFont(size=12))
        status_lbl.pack(pady=(6, 0))

        def do_generate():
            name = name_entry.get().strip()
            pwd  = pass_entry.get()
            pwd2 = pass2_entry.get()
            if not name:
                status_lbl.configure(text='Podaj nazwę klucza.')
                return
            if pwd != pwd2:
                status_lbl.configure(text='Hasła nie są identyczne.')
                return
            if len(pwd) < 6:
                status_lbl.configure(text='Hasło musi mieć min. 6 znaków.')
                return

            btn_gen.configure(state='disabled', text='Generowanie…')
            status_lbl.configure(text='')

            def worker():
                try:
                    self.km.generate(name, pwd, paranoid=paranoid_var.get())
                    self.logger.log('keygen', key_name=name, paranoid=paranoid_var.get())
                    dlg.after(0, lambda: (dlg.destroy(), self.refresh(), self.status_cb(f"Klucz '{name}' wygenerowany.")))
                except FileExistsError:
                    dlg.after(0, lambda: (btn_gen.configure(state='normal', text='Generuj'),
                                          status_lbl.configure(text=f"Klucz '{name}' już istnieje.")))
                except Exception as e:
                    dlg.after(0, lambda: (btn_gen.configure(state='normal', text='Generuj'),
                                          status_lbl.configure(text=str(e))))

            threading.Thread(target=worker, daemon=True).start()

        btn_gen = ctk.CTkButton(
            dlg, text='Generuj', height=42,
            font=ctk.CTkFont(size=14, weight='bold'),
            fg_color=C_ACCENT, hover_color='#1f6feb',
            command=do_generate,
        )
        btn_gen.pack(pady=16, padx=30, fill='x')

    # ── Export PEM ─────────────────────────────────────────────────────────────

    def _export_pem(self, name: str) -> None:
        pem = self.km.export_public_pem(name)
        path = fd.asksaveasfilename(
            defaultextension='.pem',
            filetypes=[('PEM files', '*.pem'), ('All files', '*.*')],
            initialfile=f'{name}_public.pem',
        )
        if path:
            Path(path).write_text(pem, encoding='utf-8')
            self.logger.log('export_pem', key_name=name, path=path)
            self.status_cb(f"Wyeksportowano '{name}' → {path}")

    # ── Import PEM ─────────────────────────────────────────────────────────────

    def _import_pem(self) -> None:
        path = fd.askopenfilename(
            filetypes=[('PEM files', '*.pem'), ('All files', '*.*')],
        )
        if not path:
            return

        pem_text = Path(path).read_text(encoding='utf-8')
        name = Path(path).stem

        dlg = ctk.CTkToplevel(self)
        dlg.title('Import klucza publicznego')
        dlg.geometry('380x220')
        dlg.grab_set()
        dlg.configure(fg_color=C_CARD)

        ctk.CTkLabel(dlg, text='Nazwa dla importowanego klucza:',
                     text_color=C_TEXT).pack(pady=(24, 8))
        name_entry = ctk.CTkEntry(dlg, placeholder_text=name, height=38)
        name_entry.insert(0, name)
        name_entry.pack(padx=30, fill='x')

        status_lbl = ctk.CTkLabel(dlg, text='', text_color=C_RED)
        status_lbl.pack(pady=8)

        def do_import():
            n = name_entry.get().strip() or name
            try:
                self.km.import_public_key_from_pem(n, pem_text)
                self.logger.log('import_pem', key_name=n, path=path)
                dlg.destroy()
                self.refresh()
                self.status_cb(f"Zaimportowano '{n}'.")
            except Exception as e:
                status_lbl.configure(text=str(e))

        ctk.CTkButton(dlg, text='Importuj', height=40,
                      fg_color=C_ACCENT, command=do_import).pack(pady=12, padx=30, fill='x')

    # ── Delete key ─────────────────────────────────────────────────────────────

    def _delete_key(self, name: str) -> None:
        if mb.askyesno('Usuń klucz', f"Napewno usunąć klucz '{name}'?\nTej operacji nie można cofnąć!"):
            self.km.delete(name)
            self.logger.log('delete_key', key_name=name)
            self._selected_key = None
            self._detail_placeholder()
            self.refresh()
            self.status_cb(f"Klucz '{name}' usunięty.")
