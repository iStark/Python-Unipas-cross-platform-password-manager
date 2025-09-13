#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Universal cross-platform password manager with a 6-digit PIN, encrypted storage, and a simple GUI.

Features
- On first run: prompts to create a 6-digit PIN and initializes encrypted storage.
- On subsequent runs: requires the correct 6-digit PIN to unlock.
- AES-GCM encryption with a key derived via scrypt (from the PIN + random salt).
- SQLite database stores ONLY ciphertext (per-record JSON blob) + nonce. No plaintext fields on disk.
- Tkinter GUI with a table view and an add form:
  Columns: ID / Название сайта / Login / Email / Телефон / Password / Description
- Buttons: Добавить, Показать/Скрыть пароль, Копировать пароль, Копировать email,
           Копировать название сайта, Редактировать, Удалить запись, Обновить.

Dependencies
    pip install cryptography

Optional one-file build (Windows/macOS/Linux):
    pip install pyinstaller
    pyinstaller -F -w password_manager.py
"""
from __future__ import annotations
import base64
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

# --- Crypto (cryptography) ---
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend

# --- GUI (tkinter) ---
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

APP_NAME = "UniPass"
def _app_dir() -> Path:
    # Папка, где лежит exe (или .py, если не собрано)
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

DB_PATH = _app_dir() / "unipass.db"
SCHEMA_VERSION = 1

# Scrypt parameters (balanced for desktop; adjust if desired)
SCRYPT_N = 2**15  # CPU/memory cost (32768)
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32  # AES-256 key
NONCE_LEN = 12  # AES-GCM recommended nonce length

PIN_REGEX = re.compile(r"^\d{6}$")


# -----------------------------
# Utilities
# -----------------------------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


@dataclass
class KDFParams:
    salt: bytes
    n: int = SCRYPT_N
    r: int = SCRYPT_R
    p: int = SCRYPT_P

    def to_meta(self) -> Dict[str, str]:
        return {
            "salt": b64e(self.salt),
            "n": str(self.n),
            "r": str(self.r),
            "p": str(self.p),
        }

    @staticmethod
    def from_meta(meta: Dict[str, str]) -> "KDFParams":
        return KDFParams(
            salt=b64d(meta["salt"]),
            n=int(meta.get("n", SCRYPT_N)),
            r=int(meta.get("r", SCRYPT_R)),
            p=int(meta.get("p", SCRYPT_P)),
        )


class CryptoManager:
    def __init__(self, kdf_params: KDFParams):
        self.kdf_params = kdf_params
        self._key: Optional[bytes] = None

    def derive_key(self, pin: str) -> bytes:
        kdf = Scrypt(
            salt=self.kdf_params.salt,
            length=KEY_LEN,
            n=self.kdf_params.n,
            r=self.kdf_params.r,
            p=self.kdf_params.p,
            backend=default_backend(),
        )
        key = kdf.derive(pin.encode("utf-8"))
        self._key = key
        return key

    @property
    def key(self) -> bytes:
        if self._key is None:
            raise RuntimeError("Key is not derived yet")
        return self._key

    def encrypt_json(self, obj: Dict[str, Any]) -> tuple[bytes, bytes]:
        aes = AESGCM(self.key)
        nonce = os.urandom(NONCE_LEN)
        plaintext = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        ct = aes.encrypt(nonce, plaintext, associated_data=None)
        return nonce, ct

    def decrypt_json(self, nonce: bytes, ct: bytes) -> Dict[str, Any]:
        aes = AESGCM(self.key)
        pt = aes.decrypt(nonce, ct, associated_data=None)
        return json.loads(pt.decode("utf-8"))


class Store:
    """Encrypted SQLite store. Only ciphertext is stored for entries."""

    def __init__(self, path: Path):
        self.path = path
        self.conn: sqlite3.Connection = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        self._ensure_tables()

    def _ensure_tables(self):
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nonce TEXT NOT NULL,
                data  TEXT NOT NULL
            );
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_info (
                version INTEGER NOT NULL
            );
            """
        )
        # Initialize schema_info if empty
        cur.execute("SELECT COUNT(*) as c FROM schema_info")
        if cur.fetchone()["c"] == 0:
            cur.execute("INSERT INTO schema_info(version) VALUES (?)", (SCHEMA_VERSION,))
        self.conn.commit()

    # --- Meta helpers ---
    def set_meta(self, key: str, value: str):
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        self.conn.commit()

    def get_meta(self, key: str) -> Optional[str]:
        cur = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,))
        row = cur.fetchone()
        return row["value"] if row else None

    def all_meta(self) -> Dict[str, str]:
        cur = self.conn.execute("SELECT key, value FROM meta")
        return {row["key"]: row["value"] for row in cur.fetchall()}

    # --- Entry CRUD ---
    def add_entry_blob(self, nonce_b64: str, data_b64: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO entries(nonce, data) VALUES(?, ?)", (nonce_b64, data_b64)
        )
        self.conn.commit()
        return int(cur.lastrowid)

    def update_entry_blob(self, entry_id: int, nonce_b64: str, data_b64: str) -> None:
        self.conn.execute(
            "UPDATE entries SET nonce=?, data=? WHERE id=?", (nonce_b64, data_b64, entry_id)
        )
        self.conn.commit()

    def list_entries(self) -> list[sqlite3.Row]:
        cur = self.conn.execute("SELECT id, nonce, data FROM entries ORDER BY id DESC")
        return cur.fetchall()

    def get_entry(self, entry_id: int) -> Optional[sqlite3.Row]:
        cur = self.conn.execute("SELECT id, nonce, data FROM entries WHERE id=?", (entry_id,))
        return cur.fetchone()

    def delete_entry(self, entry_id: int):
        self.conn.execute("DELETE FROM entries WHERE id=?", (entry_id,))
        self.conn.commit()


# -----------------------------
# PIN dialogs
# -----------------------------
class PinDialog(simpledialog.Dialog):
    def __init__(self, parent, title: str, prompt: str, confirm: bool = False):
        self.prompt = prompt
        self.confirm = confirm
        self.pin_var = tk.StringVar()
        self.pin2_var = tk.StringVar()
        super().__init__(parent, title)

    def body(self, master):
        ttk.Label(master, text=self.prompt).grid(row=0, column=0, columnspan=2, pady=(0, 6))
        ttk.Label(master, text="PIN (6 цифр):").grid(row=1, column=0, sticky="e")
        e1 = ttk.Entry(master, textvariable=self.pin_var, show="•", width=20)
        e1.grid(row=1, column=1, pady=2)
        e1.focus_set()
        if self.confirm:
            ttk.Label(master, text="Повторите PIN:").grid(row=2, column=0, sticky="e")
            ttk.Entry(master, textvariable=self.pin2_var, show="•", width=20).grid(row=2, column=1, pady=2)
        return e1

    def validate(self):
        pin = self.pin_var.get().strip()
        if not PIN_REGEX.match(pin):
            messagebox.showerror(APP_NAME, "PIN должен состоять из 6 цифр")
            return False
        if self.confirm and pin != self.pin2_var.get().strip():
            messagebox.showerror(APP_NAME, "PIN не совпадает")
            return False
        return True

    def apply(self):
        self.result = self.pin_var.get().strip()


# -----------------------------
# Edit dialog
# -----------------------------
class EditDialog(simpledialog.Dialog):
    """Modal dialog to edit entry fields."""

    def __init__(self, parent, title: str, data: Dict[str, Any]):
        self.data_in = data
        self.result_data: Optional[Dict[str, Any]] = None
        # vars
        self.var_site = tk.StringVar(value=data.get("site", ""))
        self.var_login = tk.StringVar(value=data.get("login", ""))
        self.var_email = tk.StringVar(value=data.get("email", ""))
        self.var_phone = tk.StringVar(value=data.get("phone", ""))
        self.var_pass = tk.StringVar(value=data.get("password", ""))
        self.var_desc = tk.StringVar(value=data.get("description", ""))
        super().__init__(parent, title)

    def body(self, master):
        master.columnconfigure(1, weight=1)
        master.columnconfigure(3, weight=1)

        ttk.Label(master, text="Название сайта:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        ttk.Entry(master, textvariable=self.var_site, width=28).grid(row=0, column=1, sticky="we", padx=4, pady=4)

        ttk.Label(master, text="Login:").grid(row=0, column=2, sticky="e", padx=4, pady=4)
        ttk.Entry(master, textvariable=self.var_login, width=24).grid(row=0, column=3, sticky="we", padx=4, pady=4)

        ttk.Label(master, text="Email:").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        ttk.Entry(master, textvariable=self.var_email, width=28).grid(row=1, column=1, sticky="we", padx=4, pady=4)

        ttk.Label(master, text="Телефон:").grid(row=1, column=2, sticky="e", padx=4, pady=4)
        ttk.Entry(master, textvariable=self.var_phone, width=24).grid(row=1, column=3, sticky="we", padx=4, pady=4)

        ttk.Label(master, text="Password:").grid(row=2, column=0, sticky="e", padx=4, pady=4)
        ttk.Entry(master, textvariable=self.var_pass, width=28, show="•").grid(row=2, column=1, sticky="we", padx=4, pady=4)

        ttk.Label(master, text="Description:").grid(row=2, column=2, sticky="e", padx=4, pady=4)
        ttk.Entry(master, textvariable=self.var_desc, width=24).grid(row=2, column=3, sticky="we", padx=4, pady=4)

        # enable clipboard support in dialog entries (inherits from parent class bindings)
        return None

    def validate(self):
        if not self.var_site.get().strip():
            messagebox.showerror(APP_NAME, "Введите название сайта")
            return False
        return True

    def apply(self):
        self.result_data = {
            "site": self.var_site.get().strip(),
            "login": self.var_login.get().strip(),
            "email": self.var_email.get().strip(),
            "phone": self.var_phone.get().strip(),
            "password": self.var_pass.get(),
            "description": self.var_desc.get().strip(),
        }


# -----------------------------
# Main Application
# -----------------------------
class PasswordManagerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1120x580")
        self.minsize(950, 540)
        self.style = ttk.Style(self)
        if sys.platform == "darwin":
            self.style.theme_use("clam")

        self.store = Store(DB_PATH)
        self.crypto: Optional[CryptoManager] = None
        self._unlocked = False

        # Unlock flow
        self.unlock_or_init()
        if not self._unlocked:
            self.destroy()
            return

        # UI
        self._build_ui()
        self.refresh_table()

    # --- Unlock / Initialize ---
    def unlock_or_init(self):
        meta = self.store.all_meta()
        salt_b64 = meta.get("kdf_salt")
        if not salt_b64:
            # First run -> create PIN & initialize meta
            dlg = PinDialog(self, APP_NAME, "Создайте 6-значный PIN для шифрования", confirm=True)
            pin = dlg.result
            if not pin:
                return
            salt = os.urandom(16)
            kdf_params = KDFParams(salt=salt)
            crypto = CryptoManager(kdf_params)
            crypto.derive_key(pin)
            # Store kdf params
            self.store.set_meta("kdf_salt", b64e(salt))
            self.store.set_meta("kdf_n", str(kdf_params.n))
            self.store.set_meta("kdf_r", str(kdf_params.r))
            self.store.set_meta("kdf_p", str(kdf_params.p))
            # Verifier
            verifier_plain = {"ok": True}
            v_nonce, v_ct = crypto.encrypt_json(verifier_plain)
            self.store.set_meta("verifier_nonce", b64e(v_nonce))
            self.store.set_meta("verifier_ct", b64e(v_ct))
            self.crypto = crypto
            self._unlocked = True
            return

        # Existing db -> ask PIN and verify
        try:
            kdf_params = KDFParams(
                salt=b64d(self.store.get_meta("kdf_salt")),
                n=int(self.store.get_meta("kdf_n") or SCRYPT_N),
                r=int(self.store.get_meta("kdf_r") or SCRYPT_R),
                p=int(self.store.get_meta("kdf_p") or SCRYPT_P),
            )
        except Exception:
            messagebox.showerror(APP_NAME, "Поврежденные метаданные KDF")
            return

        attempts = 0
        while attempts < 3:
            dlg = PinDialog(self, APP_NAME, "Введите 6-значный PIN")
            pin = dlg.result
            if not pin:
                return
            crypto = CryptoManager(kdf_params)
            try:
                crypto.derive_key(pin)
                v_nonce = b64d(self.store.get_meta("verifier_nonce") or "")
                v_ct = b64d(self.store.get_meta("verifier_ct") or "")
                obj = crypto.decrypt_json(v_nonce, v_ct)
                if obj.get("ok") is True:
                    self.crypto = crypto
                    self._unlocked = True
                    return
            except Exception:
                pass
            attempts += 1
            messagebox.showerror(APP_NAME, f"Неверный PIN (попытка {attempts}/3)")
        messagebox.showwarning(APP_NAME, "Слишком много неудачных попыток. Выход.")

    # --- UI Building ---
    def _build_ui(self):
        # Top controls
        top = ttk.Frame(self)
        top.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)

        self.btn_refresh = ttk.Button(top, text="Обновить", command=self.refresh_table)
        self.btn_refresh.pack(side=tk.LEFT)

        self.btn_reveal = ttk.Button(top, text="Показать/Скрыть пароль", command=self.toggle_reveal_selected)
        self.btn_reveal.pack(side=tk.LEFT, padx=(6, 0))

        self.btn_copy_pwd = ttk.Button(top, text="Копировать пароль", command=self.copy_password_selected)
        self.btn_copy_pwd.pack(side=tk.LEFT, padx=(6, 0))

        self.btn_copy_email = ttk.Button(top, text="Копировать email", command=self.copy_email_selected)
        self.btn_copy_email.pack(side=tk.LEFT, padx=(6, 0))

        self.btn_copy_site = ttk.Button(top, text="Копировать название сайта", command=self.copy_site_selected)
        self.btn_copy_site.pack(side=tk.LEFT, padx=(6, 0))

        self.btn_edit = ttk.Button(top, text="Редактировать", command=self.edit_selected)
        self.btn_edit.pack(side=tk.LEFT, padx=(6, 0))

        self.btn_delete = ttk.Button(top, text="Удалить запись", command=self.delete_selected)
        self.btn_delete.pack(side=tk.LEFT, padx=(6, 0))

        # Table
        columns = ("id", "site", "login", "email", "phone", "password", "desc")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=12)
        self.tree.heading("id", text="ID")
        self.tree.heading("site", text="Название сайта")
        self.tree.heading("login", text="Login")
        self.tree.heading("email", text="Email")
        self.tree.heading("phone", text="Телефон")
        self.tree.heading("password", text="Password")
        self.tree.heading("desc", text="Description")

        self.tree.column("id", width=60, anchor=tk.CENTER)
        self.tree.column("site", width=200)
        self.tree.column("login", width=160)
        self.tree.column("email", width=200)
        self.tree.column("phone", width=140)
        self.tree.column("password", width=140, anchor=tk.CENTER)
        self.tree.column("desc", width=260)

        self.tree.pack(fill=tk.BOTH, expand=True, padx=8)

        # Add form
        form = ttk.LabelFrame(self, text="Добавить запись")
        form.pack(side=tk.BOTTOM, fill=tk.X, padx=8, pady=8)

        # Row 0
        ttk.Label(form, text="Название сайта:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        ttk.Label(form, text="Login:").grid(row=0, column=2, sticky="e", padx=4, pady=4)
        ttk.Label(form, text="Email:").grid(row=0, column=4, sticky="e", padx=4, pady=4)

        # Row 1
        ttk.Label(form, text="Телефон:").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        ttk.Label(form, text="Password:").grid(row=1, column=2, sticky="e", padx=4, pady=4)
        ttk.Label(form, text="Description:").grid(row=1, column=4, sticky="e", padx=4, pady=4)

        self.var_site = tk.StringVar()
        self.var_login = tk.StringVar()
        self.var_email = tk.StringVar()
        self.var_phone = tk.StringVar()
        self.var_pass = tk.StringVar()
        self.var_desc = tk.StringVar()

        # Inputs
        ttk.Entry(form, textvariable=self.var_site, width=28).grid(row=0, column=1, sticky="we", padx=4, pady=4)
        ttk.Entry(form, textvariable=self.var_login, width=22).grid(row=0, column=3, sticky="we", padx=4, pady=4)
        ttk.Entry(form, textvariable=self.var_email, width=28).grid(row=0, column=5, sticky="we", padx=4, pady=4)

        ttk.Entry(form, textvariable=self.var_phone, width=22).grid(row=1, column=1, sticky="we", padx=4, pady=4)
        ttk.Entry(form, textvariable=self.var_pass, width=22, show="•").grid(row=1, column=3, sticky="we", padx=4, pady=4)
        ttk.Entry(form, textvariable=self.var_desc, width=28).grid(row=1, column=5, sticky="we", padx=4, pady=4)

        self.btn_add = ttk.Button(form, text="Добавить", command=self.add_entry)
        self.btn_add.grid(row=0, column=6, rowspan=2, padx=6)

        # Column weights
        for c in (1, 3, 5):
            form.grid_columnconfigure(c, weight=1)

        # Bindings
        self.tree.bind("<Double-1>", self.on_double_click)

        # In-memory reveal state: entry_id -> bool
        self._revealed: dict[int, bool] = {}

        # Clipboard support (Windows-safe)
        self._install_clipboard_support()

    # --- Clipboard helpers (fix Ctrl+V etc.) ---
    def _install_clipboard_support(self):
        # Class bindings for all Entry/ttk.Entry
        for cls in ("TEntry", "Entry"):
            self.bind_class(cls, "<Control-v>", lambda e: e.widget.event_generate("<<Paste>>"))
            self.bind_class(cls, "<Control-Shift-V>", lambda e: e.widget.event_generate("<<Paste>>"))
            self.bind_class(cls, "<Control-c>", lambda e: e.widget.event_generate("<<Copy>>"))
            self.bind_class(cls, "<Control-x>", lambda e: e.widget.event_generate("<<Cut>>"))
            self.bind_class(cls, "<Control-a>", lambda e: (e.widget.selection_range(0, "end"), "break"))
            self.bind_class(cls, "<Button-3>", self._show_entry_menu)

        self._entry_menu = tk.Menu(self, tearoff=0)
        self._entry_menu.add_command(label="Копировать", command=lambda: self.focus_get().event_generate("<<Copy>>"))
        self._entry_menu.add_command(label="Вставить", command=lambda: self.focus_get().event_generate("<<Paste>>"))
        self._entry_menu.add_command(label="Вырезать", command=lambda: self.focus_get().event_generate("<<Cut>>"))
        self._entry_menu.add_separator()
        self._entry_menu.add_command(label="Выделить всё", command=self._select_all_current)

    def _show_entry_menu(self, event):
        widget = event.widget
        widget.focus_set()
        try:
            self._entry_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._entry_menu.grab_release()

    def _select_all_current(self):
        w = self.focus_get()
        try:
            w.selection_range(0, "end")
        except Exception:
            pass

    # --- Data operations ---
    def refresh_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        if not self.crypto:
            return
        rows = self.store.list_entries()
        for r in rows:
            try:
                data = self.crypto.decrypt_json(b64d(r["nonce"]), b64d(r["data"]))
                entry_id = int(r["id"])
                shown_pw = data.get("password") if self._revealed.get(entry_id) else "••••••••"
                self.tree.insert(
                    "",
                    tk.END,
                    iid=str(entry_id),
                    values=(
                        entry_id,
                        data.get("site", ""),
                        data.get("login", ""),
                        data.get("email", ""),
                        data.get("phone", ""),
                        shown_pw,
                        data.get("description", ""),
                    ),
                )
            except Exception:
                # Skip corrupted rows silently
                continue

    def add_entry(self):
        site = self.var_site.get().strip()
        login = self.var_login.get().strip()
        email = self.var_email.get().strip()
        phone = self.var_phone.get().strip()
        password = self.var_pass.get()
        desc = self.var_desc.get().strip()
        if not site:
            messagebox.showerror(APP_NAME, "Введите название сайта")
            return
        if not self.crypto:
            return
        payload = {
            "site": site,
            "login": login,
            "email": email,
            "phone": phone,
            "password": password,
            "description": desc,
        }
        nonce, ct = self.crypto.encrypt_json(payload)
        new_id = self.store.add_entry_blob(b64e(nonce), b64e(ct))
        # Clear inputs
        self.var_site.set("")
        self.var_login.set("")
        self.var_email.set("")
        self.var_phone.set("")
        self.var_pass.set("")
        self.var_desc.set("")
        # Make the new one hidden by default
        self._revealed[new_id] = False
        self.refresh_table()

    def get_selected_entry_id(self) -> Optional[int]:
        sel = self.tree.selection()
        if not sel:
            return None
        try:
            return int(sel[0])
        except Exception:
            return None

    def _copy_field_from_selected(self, field: str, success_msg: str):
        entry_id = self.get_selected_entry_id()
        if entry_id is None:
            messagebox.showinfo(APP_NAME, "Выберите запись в таблице")
            return
        row = self.store.get_entry(entry_id)
        if not row:
            return
        try:
            data = self.crypto.decrypt_json(b64d(row["nonce"]), b64d(row["data"]))
            value = data.get(field, "")
            self.clipboard_clear()
            self.clipboard_append(value)
            self.update()
            messagebox.showinfo(APP_NAME, success_msg)
        except Exception:
            messagebox.showerror(APP_NAME, "Не удалось расшифровать запись")

    def toggle_reveal_selected(self):
        entry_id = self.get_selected_entry_id()
        if entry_id is None:
            messagebox.showinfo(APP_NAME, "Выберите запись в таблице")
            return
        self._revealed[entry_id] = not self._revealed.get(entry_id, False)
        self.refresh_table()

    def copy_password_selected(self):
        self._copy_field_from_selected("password", "Пароль скопирован в буфер обмена")

    def copy_email_selected(self):
        self._copy_field_from_selected("email", "Email скопирован в буфер обмена")

    def copy_site_selected(self):
        self._copy_field_from_selected("site", "Название сайта скопировано в буфер обмена")

    def edit_selected(self):
        entry_id = self.get_selected_entry_id()
        if entry_id is None:
            messagebox.showinfo(APP_NAME, "Выберите запись в таблице")
            return
        row = self.store.get_entry(entry_id)
        if not row:
            return
        try:
            data = self.crypto.decrypt_json(b64d(row["nonce"]), b64d(row["data"]))
        except Exception:
            messagebox.showerror(APP_NAME, "Не удалось расшифровать запись")
            return

        dlg = EditDialog(self, f"Редактировать запись ID {entry_id}", data)
        if dlg.result_data is None:
            return  # canceled

        # Re-encrypt updated payload and update DB
        try:
            nonce, ct = self.crypto.encrypt_json(dlg.result_data)
            self.store.update_entry_blob(entry_id, b64e(nonce), b64e(ct))
            # keep current reveal state as-is
            self.refresh_table()
            messagebox.showinfo(APP_NAME, "Запись обновлена")
        except Exception:
            messagebox.showerror(APP_NAME, "Не удалось обновить запись")

    def delete_selected(self):
        entry_id = self.get_selected_entry_id()
        if entry_id is None:
            messagebox.showinfo(APP_NAME, "Выберите запись в таблице")
            return
        if not messagebox.askyesno(APP_NAME, f"Удалить запись ID {entry_id}?"):
            return
        self.store.delete_entry(entry_id)
        self._revealed.pop(entry_id, None)
        self.refresh_table()

    def on_double_click(self, event):
        # Toggle reveal on double click row
        self.toggle_reveal_selected()


def main():
    app = PasswordManagerApp()
    # app.mainloop() should only run if unlock successful
    if app._unlocked:
        app.mainloop()


if __name__ == "__main__":
    main()
