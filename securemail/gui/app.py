"""Tkinter desktop GUI for SecureMail.

Run from the project root:
    python -m securemail.gui.app
"""

from __future__ import annotations

import contextlib
import datetime as dt
import os
import queue
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import tkinter as tk
from tkinter import messagebox, ttk

from cryptography import x509

from securemail import client_core


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DOMAIN = "mail.local"


COLORS = {
    "bg": "#F7F8FA",
    "surface": "#FFFFFF",
    "surface_2": "#EEF2F7",
    "text": "#17202A",
    "muted": "#697386",
    "border": "#D8DEE8",
    "primary": "#2563EB",
    "success": "#15803D",
    "warning": "#B45309",
    "danger": "#B91C1C",
    "info": "#0E7490",
    "gray": "#64748B",
}


SERVICE_PORTS = {
    "CA": 9000,
    "KDS": 9001,
    "TICKET": 9002,
    "SMTP": 2525,
    "POP3": 1100,
}


SERVICE_RUNNERS = {
    "CA": {
        "command": [sys.executable, "-m", "securemail.main_ca", "serve"],
        "ports": (9000,),
    },
    "KDS": {
        "command": [sys.executable, "-m", "securemail.main_kds"],
        "ports": (9001,),
    },
    "TICKET": {
        "command": [sys.executable, "-m", "securemail.main_ticket"],
        "ports": (9002,),
    },
    "MAIL": {
        "command": [sys.executable, "-m", "securemail.main_mail_server"],
        "ports": (2525, 1100),
    },
}


SCENARIO_META = {
    "1": ("Normal encrypted + signed email", "S/MIME, SMTP/POP3, verify signature"),
    "2": ("MITM / Public-key substitution", "Fake cert bi reject khi verify chain"),
    "3": ("Replay Attack", "Authenticator reuse bi replay cache chan"),
    "4": ("Revoked Certificate", "CRL/OCSP tu choi cert da revoke"),
    "5": ("Spoofed Sender", "SPF/DMARC phat hien gia mao sender"),
    "6": ("Reusable Ticket", "Mot ST dung nhieu lan voi authenticator moi"),
    "7": ("Key Recovery", "Shamir 2-of-3 khoi phuc private key"),
    "8": ("HKDF Subsession Key", "Dan xuat subkey theo context rieng"),
}


@dataclass
class AppState:
    ctx: dict[str, Any] | None = None
    inbox: list[dict[str, Any]] = field(default_factory=list)
    sent: list[dict[str, Any]] = field(default_factory=list)
    selected_message: dict[str, Any] | None = None
    current_folder: str = "inbox"
    services: dict[str, bool] = field(default_factory=dict)
    scenario_status: dict[str, str] = field(default_factory=dict)

    @property
    def email(self) -> str | None:
        return self.ctx.get("email") if self.ctx else None

    @property
    def role(self) -> str | None:
        return self.ctx.get("role", "user") if self.ctx else None


class SecureMailApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecureMail Desktop")
        self.geometry("1320x840")
        self.minsize(1100, 720)
        self.configure(bg=COLORS["bg"])

        self.state_data = AppState()
        self.tasks: queue.Queue[tuple[str, str, Any, Any, str | None]] = queue.Queue()
        self._main_widgets: list[tk.Widget] = []
        self._right_widgets: list[tk.Widget] = []
        self._service_labels: dict[str, tk.Label] = {}
        self._service_toggle_buttons: list[ttk.Button] = []
        self._service_processes: dict[str, subprocess.Popen] = {}
        self._nav_buttons: dict[str, ttk.Button] = {}

        self._configure_styles()
        self._build_shell()
        self._load_saved_session()
        self.refresh_services()
        self.after(150, self._drain_task_queue)

    # ------------------------------------------------------------------
    # Shell and shared widgets
    # ------------------------------------------------------------------
    def _configure_styles(self):
        style = ttk.Style(self)
        with contextlib.suppress(tk.TclError):
            style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 10), background=COLORS["bg"], foreground=COLORS["text"])
        style.configure("TFrame", background=COLORS["bg"])
        style.configure("Surface.TFrame", background=COLORS["surface"], relief="solid", borderwidth=1)
        style.configure("Nav.TFrame", background=COLORS["surface"])
        style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["text"])
        style.configure("Muted.TLabel", foreground=COLORS["muted"], background=COLORS["bg"])
        style.configure("Surface.TLabel", background=COLORS["surface"], foreground=COLORS["text"])
        style.configure("Title.TLabel", font=("Segoe UI Semibold", 18), background=COLORS["bg"])
        style.configure("Section.TLabel", font=("Segoe UI Semibold", 12), background=COLORS["surface"])
        style.configure("TButton", padding=(12, 8))
        style.configure("Primary.TButton", padding=(14, 9))
        style.map("Primary.TButton", foreground=[("active", "#FFFFFF"), ("!disabled", "#FFFFFF")],
                  background=[("active", "#1D4ED8"), ("!disabled", COLORS["primary"])])
        style.configure("Nav.TButton", anchor="w", padding=(12, 10), background=COLORS["surface"])
        style.configure("Treeview", rowheight=30, fieldbackground=COLORS["surface"], background=COLORS["surface"])
        style.configure("Treeview.Heading", font=("Segoe UI Semibold", 10), padding=(6, 6))
        style.configure("Horizontal.TSeparator", background=COLORS["border"])

    def _build_shell(self):
        header = tk.Frame(self, bg=COLORS["surface"], highlightbackground=COLORS["border"], highlightthickness=1)
        header.pack(side="top", fill="x")

        left_header = tk.Frame(header, bg=COLORS["surface"])
        left_header.pack(side="left", padx=18, pady=12)
        tk.Label(left_header, text="SecureMail", font=("Segoe UI Semibold", 18),
                 bg=COLORS["surface"], fg=COLORS["text"]).pack(anchor="w")
        tk.Label(left_header, text="Encrypted mail client, monitoring dashboard, scenario lab",
                 bg=COLORS["surface"], fg=COLORS["muted"]).pack(anchor="w")

        status_header = tk.Frame(header, bg=COLORS["surface"])
        status_header.pack(side="right", padx=18, pady=10)
        self.user_pill = self._pill(status_header, "Not logged in", "gray")
        self.user_pill.pack(side="left", padx=4)
        self.tgt_pill = self._pill(status_header, "NO TGT", "gray")
        self.tgt_pill.pack(side="left", padx=4)
        for service in SERVICE_PORTS:
            pill = self._pill(status_header, f"{service} ?", "gray")
            pill.pack(side="left", padx=3)
            self._service_labels[service] = pill

        body = tk.Frame(self, bg=COLORS["bg"])
        body.pack(side="top", fill="both", expand=True)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self.nav_shell = tk.Frame(
            body,
            bg=COLORS["surface"],
            width=205,
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        self.nav_shell.grid(row=0, column=0, sticky="ns")
        self.nav_shell.grid_propagate(False)
        self.nav_canvas = tk.Canvas(self.nav_shell, bg=COLORS["surface"], highlightthickness=0, borderwidth=0)
        self.nav_scrollbar = ttk.Scrollbar(self.nav_shell, orient="vertical", command=self.nav_canvas.yview)
        self.nav_canvas.configure(yscrollcommand=self.nav_scrollbar.set)
        self.nav_canvas.pack(side="left", fill="both", expand=True)
        self.nav_scrollbar.pack(side="right", fill="y")
        self.nav = tk.Frame(self.nav_canvas, bg=COLORS["surface"])
        self._nav_window = self.nav_canvas.create_window((0, 0), window=self.nav, anchor="nw")
        self.nav.bind("<Configure>", self._sync_nav_scrollregion)
        self.nav_canvas.bind("<Configure>", self._sync_nav_width)
        self.nav_canvas.bind("<Enter>", self._bind_nav_mousewheel)
        self.nav_canvas.bind("<Leave>", self._unbind_nav_mousewheel)
        self.nav.bind("<Enter>", self._bind_nav_mousewheel)
        self.nav.bind("<Leave>", self._unbind_nav_mousewheel)
        self._build_nav()

        self.main = tk.Frame(body, bg=COLORS["bg"])
        self.main.grid(row=0, column=1, sticky="nsew", padx=14, pady=14)
        self.main.grid_columnconfigure(0, weight=1)
        self.main.grid_rowconfigure(1, weight=1)

        self.right = tk.Frame(body, bg=COLORS["surface"], width=310,
                              highlightbackground=COLORS["border"], highlightthickness=1)
        self.right.grid(row=0, column=2, sticky="ns")
        self.right.grid_propagate(False)
        self.operation_log = self._build_right_panel("Security Flow")

    def _sync_nav_scrollregion(self, _event: tk.Event | None = None):
        self.nav_canvas.configure(scrollregion=self.nav_canvas.bbox("all"))

    def _sync_nav_width(self, event: tk.Event):
        self.nav_canvas.itemconfigure(self._nav_window, width=event.width)

    def _bind_nav_mousewheel(self, _event: tk.Event):
        self.nav_canvas.bind_all("<MouseWheel>", self._on_nav_mousewheel)

    def _unbind_nav_mousewheel(self, _event: tk.Event):
        self.nav_canvas.unbind_all("<MouseWheel>")

    def _on_nav_mousewheel(self, event: tk.Event):
        self.nav_canvas.yview_scroll(int(-event.delta / 120), "units")

    def _build_nav(self):
        parent = self.nav
        self._nav_buttons.clear()
        active_service_buttons: list[ttk.Button] = []
        for btn in self._service_toggle_buttons:
            try:
                if btn.winfo_exists() and btn.master is not parent:
                    active_service_buttons.append(btn)
            except tk.TclError:
                pass
        self._service_toggle_buttons = active_service_buttons
        for child in parent.winfo_children():
            child.destroy()

        def section(text: str):
            tk.Label(parent, text=text.upper(), bg=COLORS["surface"], fg=COLORS["muted"],
                     font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=18, pady=(18, 6))

        def nav_button(key: str, text: str, command: Callable[[], None]):
            btn = ttk.Button(parent, text=text, style="Nav.TButton", command=command)
            btn.pack(fill="x", padx=12, pady=3)
            self._nav_buttons[key] = btn

        role = self.state_data.role

        if not role:
            section("Account")
            nav_button("login", "Login / Register", self.show_login)
            return

        section("User App")
        nav_button("inbox", "Inbox", self.show_inbox)
        nav_button("sent", "Sent", self.show_sent)
        nav_button("compose", "Compose", self.show_compose)
        nav_button("security", "Security / Recovery", self.show_security)

        if role == "admin":
            section("Monitoring")
            nav_button("monitor", "Dashboard", self.show_monitor)

            section("Domain Security")
            nav_button("dkim", "DKIM Domains", self.show_dkim_domains)

            section("Scenario Lab")
            nav_button("scenario", "Scenarios", self.show_scenarios)

            ttk.Separator(parent).pack(fill="x", padx=12, pady=18)
            self._add_service_toggle_button(parent).pack(fill="x", padx=12, pady=3)
            ttk.Button(parent, text="Refresh services", command=self.refresh_services).pack(fill="x", padx=12, pady=3)

        ttk.Separator(parent).pack(fill="x", padx=12, pady=18)
        ttk.Button(parent, text="Logout", command=self.logout).pack(fill="x", padx=12, pady=3)

    def _add_service_toggle_button(self, parent: tk.Widget) -> ttk.Button:
        btn = ttk.Button(parent, text="Start all services", style="Primary.TButton",
                         command=self.toggle_all_services)
        self._service_toggle_buttons.append(btn)
        self._update_service_toggle_buttons()
        return btn

    def _build_right_panel(self, title: str) -> tk.Text:
        self._clear_right()
        tk.Label(self.right, text=title, bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 13)).pack(anchor="w", padx=16, pady=(16, 4))
        tk.Label(self.right, text="Trang thai thao tac va bang chung bao mat",
                 bg=COLORS["surface"], fg=COLORS["muted"], wraplength=265, justify="left").pack(anchor="w", padx=16)
        text = tk.Text(self.right, height=18, wrap="word", borderwidth=0, bg="#F8FAFC",
                       fg=COLORS["text"], padx=10, pady=10, font=("Consolas", 9))
        text.pack(fill="both", expand=True, padx=16, pady=16)
        text.configure(state="disabled")
        self._right_widgets.append(text)
        return text

    def _clear_main(self):
        for child in self.main.winfo_children():
            child.destroy()
        self.main.grid_rowconfigure(1, weight=1)
        self.main.grid_rowconfigure(2, weight=1)

    def _clear_right(self):
        for child in self.right.winfo_children():
            child.destroy()
        self._right_widgets.clear()

    def _page_title(self, title: str, subtitle: str = ""):
        top = tk.Frame(self.main, bg=COLORS["bg"])
        top.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        tk.Label(top, text=title, bg=COLORS["bg"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 20)).pack(anchor="w")
        if subtitle:
            tk.Label(top, text=subtitle, bg=COLORS["bg"], fg=COLORS["muted"],
                     wraplength=780, justify="left").pack(anchor="w", pady=(2, 0))

    def _surface(self, parent: tk.Widget | None = None) -> tk.Frame:
        parent = parent or self.main
        return tk.Frame(parent, bg=COLORS["surface"], highlightbackground=COLORS["border"], highlightthickness=1)

    def _field(self, parent: tk.Widget, label: str, show: str | None = None) -> ttk.Entry:
        tk.Label(parent, text=label, bg=COLORS["surface"], fg=COLORS["muted"]).pack(anchor="w", pady=(10, 3))
        entry = ttk.Entry(parent, show=show)
        entry.pack(fill="x", ipady=5)
        return entry

    def _pill(self, parent: tk.Widget, text: str, tone: str) -> tk.Label:
        bg = COLORS.get(tone, COLORS["gray"])
        return tk.Label(parent, text=text, bg=bg, fg="#FFFFFF", padx=9, pady=4,
                        font=("Segoe UI Semibold", 8))

    def _set_pill(self, label: tk.Label, text: str, tone: str):
        label.configure(text=text, bg=COLORS.get(tone, COLORS["gray"]))

    def _append_log(self, line: str):
        ts = dt.datetime.now().strftime("%H:%M:%S")
        self.operation_log.configure(state="normal")
        self.operation_log.insert("end", f"[{ts}] {line}\n")
        self.operation_log.see("end")
        self.operation_log.configure(state="disabled")

    def _set_header_user(self):
        email = self.state_data.email or "Not logged in"
        role = self.state_data.role
        label = f"{email} ({role})" if role else email
        self._set_pill(self.user_pill, label, "info" if self.state_data.email else "gray")
        self._set_pill(self.tgt_pill, "TGT ACTIVE" if self.state_data.ctx else "NO TGT",
                       "success" if self.state_data.ctx else "gray")
        if hasattr(self, "nav"):
            self._build_nav()

    def _require_login(self) -> bool:
        if self.state_data.ctx:
            return True
        messagebox.showwarning("SecureMail", "Ban can login truoc.")
        self._set_header_user()
        self.show_login()
        return False

    def _require_admin(self) -> bool:
        if self.state_data.role == "admin":
            return True
        messagebox.showwarning("SecureMail", "Man hinh nay chi danh cho admin.")
        return False

    # ------------------------------------------------------------------
    # Background tasks
    # ------------------------------------------------------------------
    def _run_task(self, label: str, fn: Callable[[], Any], on_success: Callable[[Any], None] | None = None):
        self._append_log(f"{label} ...")

        def worker():
            try:
                result = fn()
                self.tasks.put(("ok", label, result, on_success, None))
            except Exception as exc:
                self.tasks.put(("err", label, exc, None, traceback.format_exc()))

        threading.Thread(target=worker, daemon=True).start()

    def _drain_task_queue(self):
        try:
            while True:
                try:
                    status, label, payload, callback, tb = self.tasks.get_nowait()
                except queue.Empty:
                    break
                if status == "ok":
                    self._append_log(f"{label}: DONE")
                    if callback:
                        try:
                            callback(payload)
                        except Exception as exc:
                            detail = traceback.format_exc()
                            self._append_log(f"{label}: CALLBACK FAILED - {friendly_error(exc)}")
                            self._show_error(friendly_error(exc), detail)
                else:
                    message = friendly_error(payload)
                    self._append_log(f"{label}: FAILED - {message}")
                    if label in {"Start all services", "Stop all services"}:
                        self._set_service_controls_busy(False)
                        self.refresh_services()
                    self._show_error(message, tb or "")
        finally:
            with contextlib.suppress(tk.TclError):
                self.after(150, self._drain_task_queue)

    def _show_error(self, message: str, detail: str = ""):
        if detail:
            self._append_log("Technical detail is available in terminal traceback output.")
            print(detail)
        messagebox.showerror("SecureMail", message)

    # ------------------------------------------------------------------
    # Session
    # ------------------------------------------------------------------
    def _load_saved_session(self):
        ctx = client_core.load_session()
        if ctx:
            self.state_data.ctx = ctx
            self._append_log(f"Loaded saved session for {ctx['email']}")
        self._set_header_user()
        if self.state_data.ctx:
            self.show_inbox()
        else:
            self.show_login()

    def logout(self):
        self.state_data.ctx = None
        self.state_data.inbox.clear()
        self.state_data.sent.clear()
        self.state_data.selected_message = None
        self.state_data.current_folder = "inbox"
        client_core.clear_session()
        self._set_header_user()
        self._append_log("Logged out and cleared saved session")
        self.show_login()

    # ------------------------------------------------------------------
    # Login / Register
    # ------------------------------------------------------------------
    def show_login(self):
        self._clear_main()
        self.operation_log = self._build_right_panel("Authentication Flow")
        self._page_title("Login / Register", "Dang nhap Kerberos-lite hoac tao identity PKI moi.")

        wrapper = tk.Frame(self.main, bg=COLORS["bg"])
        wrapper.grid(row=1, column=0, sticky="nsew")
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_columnconfigure(1, weight=1)

        login_card = self._surface(wrapper)
        login_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        login_card.grid_columnconfigure(0, weight=1)
        login_inner = tk.Frame(login_card, bg=COLORS["surface"])
        login_inner.pack(fill="both", expand=True, padx=18, pady=18)
        tk.Label(login_inner, text="Login", bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 14)).pack(anchor="w")
        email_entry = self._field(login_inner, "Email")
        email_entry.insert(0, "alice@mail.local")
        password_entry = self._field(login_inner, "Password", show="*")
        remember = tk.BooleanVar(value=True)
        ttk.Checkbutton(login_inner, text="Remember session", variable=remember).pack(anchor="w", pady=10)
        ttk.Button(login_inner, text="Login", style="Primary.TButton",
                   command=lambda: self._login(email_entry.get().strip(), password_entry.get(), remember.get())).pack(anchor="w")

        register_card = self._surface(wrapper)
        register_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        register_inner = tk.Frame(register_card, bg=COLORS["surface"])
        register_inner.pack(fill="both", expand=True, padx=18, pady=18)
        tk.Label(register_inner, text="Register Account", bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 14)).pack(anchor="w")
        name_entry = self._field(register_inner, "Display name")
        reg_email_entry = self._field(register_inner, "Email")
        reg_email_entry.insert(0, "carol@mail.local")
        reg_password_entry = self._field(register_inner, "Password", show="*")
        reg_confirm_entry = self._field(register_inner, "Confirm password", show="*")
        ttk.Button(register_inner, text="Generate keypair + Register", style="Primary.TButton",
                   command=lambda: self._register_account(
                       reg_email_entry.get().strip(),
                       reg_password_entry.get(),
                       reg_confirm_entry.get(),
                       name_entry.get().strip(),
                   )).pack(anchor="w", pady=14)

        self._append_log("1. Doc private key local / tao keypair khi register")
        self._append_log("2. AS-REQ/AS-REP de lay TGT khi login")
        self._append_log("3. Session san sang cho SMTP/POP3 service ticket")

    def _login(self, email: str, password: str, remember: bool):
        if not email or not password:
            messagebox.showwarning("SecureMail", "Nhap email va password.")
            return

        def action():
            ctx = client_core.login(email, password)
            if remember:
                client_core.save_session(ctx)
            return ctx

        def done(ctx: dict[str, Any]):
            self.state_data.ctx = ctx
            self._set_header_user()
            self._append_log(f"TGT length={len(ctx['tgt'])}; current user={ctx['email']}")
            self.show_inbox()

        self._run_task("Login", action, done)

    def _register_account(self, email: str, password: str, confirm_password: str, display_name: str):
        if not email or not password:
            messagebox.showwarning("SecureMail", "Nhap email va password de register.")
            return
        if password != confirm_password:
            messagebox.showwarning("SecureMail", "Password va confirm password khong khop.")
            return

        def action():
            return client_core.public_register(email, password, display_name)

        def done(result: dict[str, Any]):
            self._append_log(f"Registered {email}; serial={result.get('serial')}")
            messagebox.showinfo("SecureMail", f"Registered {email}\nSerial: {result.get('serial')}")

        self._run_task("Register identity", action, done)

    # ------------------------------------------------------------------
    # Mailbox
    # ------------------------------------------------------------------
    def show_inbox(self):
        if not self._require_login():
            return
        self._show_mailbox("inbox")

    def show_sent(self):
        if not self._require_login():
            return
        self._show_mailbox("sent")

    def _show_mailbox(self, folder: str):
        self._clear_main()
        self.operation_log = self._build_right_panel("Message Security")
        title = "Inbox" if folder == "inbox" else "Sent"
        subtitle = "Fetch POP3, decrypt S/MIME, verify signature va policy labels."
        self._page_title(title, subtitle)
        self.state_data.current_folder = folder

        toolbar = tk.Frame(self.main, bg=COLORS["bg"])
        toolbar.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        search_var = tk.StringVar()
        ttk.Entry(toolbar, textvariable=search_var).pack(side="left", fill="x", expand=True, ipady=5)
        filter_var = tk.StringVar(value="All")
        ttk.Combobox(toolbar, textvariable=filter_var,
                     values=("All", "Secure", "Warning", "Dangerous", "Signed", "Failed", "Quarantine"),
                     state="readonly", width=16).pack(side="left", padx=8)
        ttk.Button(toolbar, text="Refresh", style="Primary.TButton",
                   command=lambda: self.refresh_mailbox(folder, tree, search_var.get(), filter_var.get())).pack(side="left")

        table_frame = self._surface()
        table_frame.grid(row=2, column=0, sticky="nsew")
        table_frame.grid_rowconfigure(0, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        columns = ("id", "status", "from_to", "subject", "date", "spf", "dkim", "dmarc")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        headings = {
            "id": "ID", "status": "Status", "from_to": "From" if folder == "inbox" else "To",
            "subject": "Subject", "date": "Date", "spf": "SPF", "dkim": "DKIM", "dmarc": "DMARC",
        }
        widths = {"id": 55, "status": 105, "from_to": 190, "subject": 320, "date": 190, "spf": 70, "dkim": 70, "dmarc": 90}
        for col in columns:
            tree.heading(col, text=headings[col])
            tree.column(col, width=widths[col], anchor="w")
        tree.tag_configure("SECURE", foreground=COLORS["success"])
        tree.tag_configure("WARNING", foreground=COLORS["warning"])
        tree.tag_configure("DANGEROUS", foreground=COLORS["danger"])
        tree.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        scroll.grid(row=0, column=1, sticky="ns", pady=10)
        tree.configure(yscrollcommand=scroll.set)
        tree.bind("<<TreeviewSelect>>", lambda _evt: self._on_mail_select(tree))

        search_var.trace_add("write", lambda *_: self._populate_mail_tree(tree, folder, search_var.get(), filter_var.get()))
        filter_var.trace_add("write", lambda *_: self._populate_mail_tree(tree, folder, search_var.get(), filter_var.get()))
        self._populate_mail_tree(tree, folder, "", "All")

        if self.state_data.ctx:
            self.refresh_mailbox(folder, tree, "", "All")
        else:
            self._append_log("Login truoc khi fetch mailbox.")

    def refresh_mailbox(self, folder: str, tree: ttk.Treeview, search: str, filter_name: str):
        if not self.state_data.ctx:
            messagebox.showwarning("SecureMail", "Ban can login truoc.")
            return
        ctx = self.state_data.ctx
        request_email = self.state_data.email

        def action():
            if self.state_data.email != request_email:
                return None
            try:
                if folder == "inbox":
                    return client_core.fetch_inbox(ctx)
                return client_core.fetch_sent(ctx)
            except Exception:
                if self.state_data.email != request_email:
                    return None
                raise

        def done(messages: list[dict[str, Any]] | None):
            if messages is None or self.state_data.email != request_email:
                self._append_log(f"Ignored stale {folder} refresh for {request_email}")
                return
            if folder == "inbox":
                self.state_data.inbox = messages
            else:
                self.state_data.sent = messages
            try:
                exists = bool(tree.winfo_exists())
            except tk.TclError:
                exists = False
            if not exists:
                self._append_log(f"Loaded {len(messages)} {folder} message(s); view closed")
                return
            self._populate_mail_tree(tree, folder, search, filter_name)
            self._append_log(f"Loaded {len(messages)} {folder} message(s)")

        self._run_task(f"Refresh {folder}", action, done)

    def _populate_mail_tree(self, tree: ttk.Treeview, folder: str, search: str, filter_name: str):
        messages = self.state_data.inbox if folder == "inbox" else self.state_data.sent
        query = search.lower().strip()
        tree.delete(*tree.get_children())
        for msg in messages:
            label, _reason = client_core.classify_security(msg)
            if not self._mail_matches_filter(msg, label, filter_name):
                continue
            haystack = " ".join(str(msg.get(k, "")) for k in ("sender", "to", "subject", "date", "body")).lower()
            if query and query not in haystack:
                continue
            from_to = msg.get("sender") if folder == "inbox" else (msg.get("to") or msg.get("recipient"))
            tree.insert("", "end", iid=str(msg["id"]), values=(
                msg.get("id", ""),
                label,
                from_to or "",
                msg.get("subject", ""),
                msg.get("date", ""),
                msg.get("spf_result", ""),
                msg.get("dkim_result", ""),
                msg.get("dmarc_action", ""),
            ), tags=(label,))

    def _mail_matches_filter(self, msg: dict[str, Any], label: str, filter_name: str) -> bool:
        if filter_name == "All":
            return True
        if filter_name in ("Secure", "Warning", "Dangerous"):
            return label == filter_name.upper()
        if filter_name == "Signed":
            return msg.get("signature_valid") is True
        if filter_name == "Failed":
            return bool(msg.get("error")) or msg.get("signature_valid") is False
        if filter_name == "Quarantine":
            return msg.get("dmarc_action") == "quarantine"
        return True

    def _on_mail_select(self, tree: ttk.Treeview):
        selected = tree.selection()
        if not selected:
            return
        msg_id = int(selected[0])
        messages = self.state_data.inbox if self.state_data.current_folder == "inbox" else self.state_data.sent
        msg = next((m for m in messages if int(m.get("id", -1)) == msg_id), None)
        if msg:
            self.state_data.selected_message = msg
            self._render_message_detail(msg)

    def _render_message_detail(self, msg: dict[str, Any]):
        self.operation_log = self._build_right_panel("Message Security")
        label, reason = client_core.classify_security(msg)
        self._append_log(f"Message #{msg.get('id')} classified as {label}")
        self._append_log(f"Reason: {reason}")
        self._append_log(f"Signature: {'VALID' if msg.get('signature_valid') else 'INVALID'}")
        self._append_log(f"SPF={msg.get('spf_result')} DKIM={msg.get('dkim_result')} DMARC={msg.get('dmarc_action')}")

        detail = tk.Toplevel(self)
        detail.title(f"Message #{msg.get('id')} - {label}")
        detail.geometry("760x620")
        detail.configure(bg=COLORS["bg"])
        top = tk.Frame(detail, bg=COLORS["surface"], highlightbackground=COLORS["border"], highlightthickness=1)
        top.pack(fill="x", padx=12, pady=12)
        for line in (
            f"From: {msg.get('sender', '')}",
            f"To: {msg.get('to') or msg.get('recipient', '')}",
            f"Subject: {msg.get('subject', '')}",
            f"Date: {msg.get('date', '')}",
            f"Security: {label} - {reason}",
            f"SPF: {msg.get('spf_result', '')} | DKIM: {msg.get('dkim_result', '')} | DMARC: {msg.get('dmarc_action', '')}",
        ):
            tk.Label(top, text=line, bg=COLORS["surface"], fg=COLORS["text"], anchor="w",
                     wraplength=700, justify="left").pack(fill="x", padx=12, pady=2)
        body = tk.Text(detail, wrap="word", bg=COLORS["surface"], fg=COLORS["text"], padx=12, pady=12)
        body.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        body.insert("1.0", msg.get("error") or msg.get("body", ""))
        body.configure(state="disabled")

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------
    def show_compose(self):
        if not self._require_login():
            return
        self._clear_main()
        self.operation_log = self._build_right_panel("Send Security Flow")
        self._page_title("Compose", "Gui email ma hoa dau-cuoi va ky so RSA-PSS.")

        card = self._surface()
        card.grid(row=1, column=0, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(4, weight=1)
        inner = tk.Frame(card, bg=COLORS["surface"])
        inner.grid(row=0, column=0, sticky="nsew", padx=18, pady=18)
        inner.grid_columnconfigure(0, weight=1)
        inner.grid_rowconfigure(6, weight=1)

        to_entry = self._field(inner, "To")
        to_entry.insert(0, "bob@mail.local")
        subject_entry = self._field(inner, "Subject")
        subject_entry.insert(0, "SecureMail test")
        tk.Label(inner, text="Body", bg=COLORS["surface"], fg=COLORS["muted"]).pack(anchor="w")
        body = tk.Text(inner, height=16, wrap="word", bg="#F8FAFC", fg=COLORS["text"], padx=10, pady=10,
                       font=("Segoe UI", 10))
        body.pack(fill="both", expand=True, pady=(3, 12))
        body.insert("1.0", "Xin chao, day la email duoc ma hoa va ky so boi SecureMail.")
        actions = tk.Frame(inner, bg=COLORS["surface"])
        actions.pack(fill="x")
        ttk.Button(actions, text="Preview recipient cert",
                   command=lambda: self._preview_cert(to_entry.get().strip())).pack(side="left")
        ttk.Button(actions, text="Send secure mail", style="Primary.TButton",
                   command=lambda: self._send_mail(
                       to_entry.get().strip(),
                       subject_entry.get().strip(),
                       body.get("1.0", "end-1c"),
                   )).pack(side="left", padx=8)

        for step in (
            "1. Lay CA root cert va CRL tu KDS",
            "2. Bulk lookup certificate nguoi nhan",
            "3. Verify chain + OCSP",
            "4. Sign body bang private key nguoi gui",
            "5. Encrypt body bang CEK, wrap CEK bang RSA-OAEP",
            "6. Lay Service Ticket va SMTP STARTTLS-lite",
            "7. Mail Server ky DKIM theo domain, kiem tra SPF/DKIM/DMARC va luu encrypted envelope",
        ):
            self._append_log(step)

    def _preview_cert(self, email: str):
        if not email:
            messagebox.showwarning("SecureMail", "Nhap email nguoi nhan.")
            return

        def action():
            from securemail.kds import kds_client
            pem = kds_client.get_cert(email)
            if not pem:
                raise RuntimeError(f"no cert for {email}")
            cert = x509.load_pem_x509_certificate(pem)
            return cert

        def done(cert):
            self._append_log(f"Cert subject: {cert.subject.rfc4514_string()}")
            self._append_log(f"Serial: {hex(cert.serial_number)}")
            self._append_log(f"Valid until: {cert.not_valid_after_utc}")

        self._run_task("Preview recipient cert", action, done)

    def _send_mail(self, to_text: str, subject: str, body: str):
        if not self.state_data.ctx:
            messagebox.showwarning("SecureMail", "Ban can login truoc khi gui mail.")
            return
        recipients = [part.strip() for part in to_text.split(",") if part.strip()]
        if not recipients or not subject or not body.strip():
            messagebox.showwarning("SecureMail", "Nhap To, Subject va Body.")
            return

        def action():
            return client_core.send_secure_email(
                self.state_data.ctx,
                recipients,
                subject,
                body,
            )

        def done(result: dict[str, Any]):
            self._append_log(f"Envelope={result.get('envelope_len')} bytes; sender_copy={result.get('sender_copy_len')} bytes")
            for rcpt, resp in result.get("results", []):
                self._append_log(f"{rcpt}: ok={resp.get('ok')} dmarc={resp.get('dmarc_action')} id={resp.get('message_id')}")
            messagebox.showinfo("SecureMail", "Email da gui thanh cong.")

        self._run_task("Send secure mail", action, done)

    # ------------------------------------------------------------------
    # Security / Recovery
    # ------------------------------------------------------------------
    def show_security(self):
        if not self._require_login():
            return
        self._clear_main()
        self.operation_log = self._build_right_panel("Identity Security")
        self._page_title("Security / Certificates", "Kiem tra cert/key local va khoi phuc private key bang Shamir shares.")

        grid = tk.Frame(self.main, bg=COLORS["bg"])
        grid.grid(row=1, column=0, sticky="nsew")
        grid.grid_columnconfigure(0, weight=1)
        grid.grid_columnconfigure(1, weight=1)

        cert_card = self._surface(grid)
        cert_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        cert_inner = tk.Frame(cert_card, bg=COLORS["surface"])
        cert_inner.pack(fill="both", expand=True, padx=18, pady=18)
        tk.Label(cert_inner, text="Local Identity", bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 14)).pack(anchor="w")
        email_var = tk.StringVar(value=self.state_data.email or "alice@mail.local")
        self._field_with_var(cert_inner, "Email", email_var)
        ttk.Button(cert_inner, text="Inspect local cert/key", style="Primary.TButton",
                   command=lambda: self._inspect_identity(email_var.get().strip())).pack(anchor="w", pady=12)

        recovery_card = self._surface(grid)
        recovery_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        recovery_inner = tk.Frame(recovery_card, bg=COLORS["surface"])
        recovery_inner.pack(fill="both", expand=True, padx=18, pady=18)
        tk.Label(recovery_inner, text="Key Recovery", bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 14)).pack(anchor="w")
        rec_email_var = tk.StringVar(value=self.state_data.email or "bob@mail.local")
        self._field_with_var(recovery_inner, "Email", rec_email_var)
        tk.Label(recovery_inner, text="Shares", bg=COLORS["surface"], fg=COLORS["muted"]).pack(anchor="w", pady=(10, 3))
        share_frame = tk.Frame(recovery_inner, bg=COLORS["surface"])
        share_frame.pack(anchor="w")
        s1 = tk.BooleanVar(value=True)
        s2 = tk.BooleanVar(value=True)
        s3 = tk.BooleanVar(value=False)
        for text, var in (("1", s1), ("2", s2), ("3", s3)):
            ttk.Checkbutton(share_frame, text=text, variable=var).pack(side="left", padx=(0, 12))
        ttk.Button(recovery_inner, text="Recover private key", style="Primary.TButton",
                   command=lambda: self._recover_key(rec_email_var.get().strip(), [v for v, b in ((1, s1), (2, s2), (3, s3)) if b.get()])).pack(anchor="w", pady=12)

        self._inspect_identity(email_var.get().strip(), silent=True)

    def _field_with_var(self, parent: tk.Widget, label: str, var: tk.StringVar) -> ttk.Entry:
        tk.Label(parent, text=label, bg=COLORS["surface"], fg=COLORS["muted"]).pack(anchor="w", pady=(10, 3))
        entry = ttk.Entry(parent, textvariable=var)
        entry.pack(fill="x", ipady=5)
        return entry

    def _inspect_identity(self, email: str, silent: bool = False):
        if not email:
            return
        safe = email.replace("@", "_at_")
        key_path = PROJECT_ROOT / "data" / "users" / f"{safe}.key.pem"
        cert_path = PROJECT_ROOT / "data" / "users" / f"{safe}.cert.pem"
        salt_path = PROJECT_ROOT / "data" / "users" / f"{safe}.salt.bin"
        self._append_log(f"Key file: {'FOUND' if key_path.exists() else 'MISSING'} - {key_path}")
        self._append_log(f"Cert file: {'FOUND' if cert_path.exists() else 'MISSING'} - {cert_path}")
        self._append_log(f"Salt file: {'FOUND' if salt_path.exists() else 'MISSING'} - {salt_path}")
        if cert_path.exists():
            try:
                cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
                self._append_log(f"Subject: {cert.subject.rfc4514_string()}")
                self._append_log(f"Issuer: {cert.issuer.rfc4514_string()}")
                self._append_log(f"Serial: {hex(cert.serial_number)}")
                self._append_log(f"Valid: {cert.not_valid_before_utc} -> {cert.not_valid_after_utc}")
            except Exception as exc:
                self._append_log(f"Cannot parse cert: {exc}")
        if not silent:
            messagebox.showinfo("SecureMail", "Identity inspection da ghi vao panel ben phai.")

    def _recover_key(self, email: str, shares: list[int]):
        if len(shares) != 2:
            messagebox.showwarning("SecureMail", "Chon dung 2 share trong 3 share.")
            return

        def action():
            return client_core.recover_user_key(email, shares)

        def done(recovered: bytes):
            self._append_log(f"Recovered {len(recovered)} bytes for {email} using shares {shares}")
            messagebox.showinfo("SecureMail", f"Recovered private key for {email}.")

        self._run_task("Recover key", action, done)

    # ------------------------------------------------------------------
    # Service lifecycle
    # ------------------------------------------------------------------
    def toggle_all_services(self):
        all_running = bool(self.state_data.services) and all(self.state_data.services.values())
        if all_running:
            self.stop_all_services()
        else:
            self.start_all_services()

    def start_all_services(self):
        self._set_service_controls_busy(True)

        def action():
            started: list[str] = []
            skipped: list[str] = []
            env = os.environ.copy()
            env.setdefault("PYTHONIOENCODING", "utf-8")
            for name, config in SERVICE_RUNNERS.items():
                ports = config["ports"]
                if all(is_port_open(port) for port in ports):
                    skipped.append(name)
                    continue
                proc = self._launch_service(config["command"], env)
                self._service_processes[name] = proc
                started.append(name)
                self._wait_for_ports(name, ports, proc)
            return started, skipped

        def done(result: tuple[list[str], list[str]]):
            started, skipped = result
            if started:
                self._append_log(f"Started services: {', '.join(started)}")
            if skipped:
                self._append_log(f"Already running: {', '.join(skipped)}")
            self._set_service_controls_busy(False)
            self.refresh_services()

        self._run_task("Start all services", action, done)

    def stop_all_services(self):
        self._set_service_controls_busy(True)

        def action():
            stopped: set[str] = set()
            for name, proc in list(self._service_processes.items()):
                if proc.poll() is None:
                    terminate_process_tree(proc.pid)
                    stopped.add(name)
                self._service_processes.pop(name, None)

            pids = find_service_pids()
            for pid in pids:
                terminate_process_tree(pid)
            time.sleep(0.8)
            return sorted(stopped), sorted(pids)

        def done(result: tuple[list[str], list[int]]):
            stopped, pids = result
            if stopped:
                self._append_log(f"Stopped GUI-managed services: {', '.join(stopped)}")
            if pids:
                self._append_log(f"Stopped service port owners: {', '.join(str(pid) for pid in pids)}")
            if not stopped and not pids:
                self._append_log("No running SecureMail service ports found.")
            self._set_service_controls_busy(False)
            self.refresh_services()

        self._run_task("Stop all services", action, done)

    def _launch_service(self, command: list[str], env: dict[str, str]) -> subprocess.Popen:
        kwargs: dict[str, Any] = {
            "cwd": PROJECT_ROOT,
            "env": env,
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            kwargs["startupinfo"] = startupinfo
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
        else:
            kwargs["start_new_session"] = True
        return subprocess.Popen(command, **kwargs)

    def _wait_for_ports(self, name: str, ports: tuple[int, ...], proc: subprocess.Popen):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"{name} exited immediately with code {proc.returncode}")
            if all(is_port_open(port) for port in ports):
                return
            time.sleep(0.25)
        ports_text = ", ".join(str(port) for port in ports)
        raise RuntimeError(f"{name} did not open port(s) {ports_text}")

    def _set_service_controls_busy(self, busy: bool):
        state = "disabled" if busy else "normal"
        for btn in list(self._service_toggle_buttons):
            try:
                if btn.winfo_exists():
                    btn.configure(state=state)
            except tk.TclError:
                self._service_toggle_buttons.remove(btn)

    def _update_service_toggle_buttons(self):
        all_running = bool(self.state_data.services) and all(self.state_data.services.values())
        text = "Stop all services" if all_running else "Start all services"
        for btn in list(self._service_toggle_buttons):
            try:
                if btn.winfo_exists():
                    btn.configure(text=text)
                else:
                    self._service_toggle_buttons.remove(btn)
            except tk.TclError:
                self._service_toggle_buttons.remove(btn)

    # ------------------------------------------------------------------
    # DKIM Domain Management
    # ------------------------------------------------------------------
    def show_dkim_domains(self):
        if not self._require_admin():
            return
        self._clear_main()
        self.operation_log = self._build_right_panel("DKIM Domain Registry")
        self._page_title("DKIM Domains", "Dang ky domain MTA vao KDS de Mail Server ky va verify DKIM.")

        card = self._surface()
        card.grid(row=1, column=0, sticky="ew")
        card.grid_columnconfigure(0, weight=1)
        inner = tk.Frame(card, bg=COLORS["surface"])
        inner.grid(row=0, column=0, sticky="ew", padx=18, pady=18)
        inner.grid_columnconfigure(0, weight=1)

        tk.Label(inner, text="Domain", bg=COLORS["surface"], fg=COLORS["muted"]).grid(row=0, column=0, sticky="w")
        domain_var = tk.StringVar(value=DOMAIN)
        ttk.Entry(inner, textvariable=domain_var).grid(row=1, column=0, sticky="ew", ipady=5, pady=(3, 12))
        ttk.Button(
            inner,
            text="Register in KDS",
            style="Primary.TButton",
            command=lambda: self._register_dkim_domain(domain_var.get().strip()),
        ).grid(row=2, column=0, sticky="w")

        info = self._surface()
        info.grid(row=2, column=0, sticky="ew", pady=(12, 0))
        info_inner = tk.Frame(info, bg=COLORS["surface"])
        info_inner.pack(fill="x", padx=18, pady=14)
        for label, value in (
            ("KDS identity", "_dkim.<domain>"),
            ("Local MTA key", "data/server/mta_<domain>_key.pem"),
            ("Private key passphrase", "mta-domain-key"),
        ):
            row = tk.Frame(info_inner, bg=COLORS["surface"])
            row.pack(fill="x", pady=2)
            tk.Label(row, text=label, width=22, anchor="w", bg=COLORS["surface"], fg=COLORS["muted"]).pack(side="left")
            tk.Label(row, text=value, anchor="w", bg=COLORS["surface"], fg=COLORS["text"]).pack(side="left", fill="x")

        self._append_log("Nhap domain ma SecureMail kiem soat duoc key MTA.")
        self._append_log("Register se tao key local, xin CA ky cert va publish _dkim.<domain> vao KDS.")

    # ------------------------------------------------------------------
    # Monitor
    # ------------------------------------------------------------------
    def show_monitor(self):
        if not self._require_admin():
            return
        self._clear_main()
        self.operation_log = self._build_right_panel("Monitor Detail")
        self._page_title("Monitoring Dashboard", "Service status, metrics, audit event stream va alert bao mat.")

        top = tk.Frame(self.main, bg=COLORS["bg"])
        top.grid(row=1, column=0, sticky="ew")
        self.monitor_service_values: dict[str, tk.Label] = {}
        for i, name in enumerate(SERVICE_PORTS):
            card, value_label = self._metric_card(top, name, "Checking", "gray")
            self.monitor_service_values[name] = value_label
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 8, 0), pady=(0, 10))
            top.grid_columnconfigure(i, weight=1)
        actions = tk.Frame(top, bg=COLORS["bg"])
        actions.grid(row=0, column=len(SERVICE_PORTS), padx=8, sticky="ns")
        self._add_service_toggle_button(actions).pack(fill="x", pady=(0, 6))
        ttk.Button(actions, text="Refresh dashboard", style="Primary.TButton",
                   command=self._refresh_monitor_data).pack(fill="x")

        lower = tk.Frame(self.main, bg=COLORS["bg"])
        lower.grid(row=2, column=0, sticky="nsew")
        lower.grid_columnconfigure(0, weight=1)
        lower.grid_columnconfigure(1, weight=1)
        lower.grid_rowconfigure(0, weight=1)

        logs_card = self._surface(lower)
        logs_card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        logs_card.grid_columnconfigure(0, weight=1)
        logs_card.grid_rowconfigure(1, weight=1)
        tk.Label(logs_card, text="Event Stream", bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 13)).grid(row=0, column=0, sticky="w", padx=12, pady=10)
        self.logs_tree = ttk.Treeview(logs_card, columns=("time", "service", "event", "details"), show="headings")
        for col, width in (("time", 145), ("service", 70), ("event", 145), ("details", 320)):
            self.logs_tree.heading(col, text=col.title())
            self.logs_tree.column(col, width=width, anchor="w")
        self.logs_tree.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.logs_tree.bind("<<TreeviewSelect>>", lambda _evt: self._show_selected_log())

        alerts_card = self._surface(lower)
        alerts_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        alerts_card.grid_columnconfigure(0, weight=1)
        alerts_card.grid_rowconfigure(1, weight=1)
        tk.Label(alerts_card, text="Alerts / Metrics", bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 13)).grid(row=0, column=0, sticky="w", padx=12, pady=10)
        self.alert_text = tk.Text(alerts_card, wrap="word", bg="#F8FAFC", fg=COLORS["text"], padx=10, pady=10,
                                  borderwidth=0, font=("Consolas", 9))
        self.alert_text.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._refresh_monitor_data()

    def _metric_card(self, parent: tk.Widget, title: str, value: str, tone: str) -> tuple[tk.Frame, tk.Label]:
        card = tk.Frame(parent, bg=COLORS["surface"], highlightbackground=COLORS["border"], highlightthickness=1)
        tk.Label(card, text=title, bg=COLORS["surface"], fg=COLORS["muted"],
                 font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=12, pady=(10, 1))
        value_label = tk.Label(card, text=value, bg=COLORS["surface"], fg=COLORS.get(tone, COLORS["text"]),
                               font=("Segoe UI Semibold", 15))
        value_label.pack(anchor="w", padx=12, pady=(0, 10))
        return card, value_label

    def refresh_services(self):
        def action():
            return {name: is_port_open(port) for name, port in SERVICE_PORTS.items()}

        def done(statuses: dict[str, bool]):
            self.state_data.services = statuses
            for name, ok in statuses.items():
                self._set_pill(self._service_labels[name], f"{name} {'ON' if ok else 'OFF'}",
                               "success" if ok else "danger")
                if hasattr(self, "monitor_service_values") and name in self.monitor_service_values:
                    self.monitor_service_values[name].configure(
                        text="ON" if ok else "OFF",
                        fg=COLORS["success"] if ok else COLORS["danger"],
                    )
            self._update_service_toggle_buttons()

        self._run_task("Check services", action, done)

    def _refresh_monitor_data(self):
        self.refresh_services()

        def action():
            return {
                "logs": read_audit_logs(limit=250),
                "metrics": read_metrics(),
            }

        def done(data: dict[str, Any]):
            self._populate_logs(data["logs"])
            self._populate_alerts(data["logs"], data["metrics"])

        self._run_task("Load monitoring data", action, done)

    def _register_dkim_domain(self, domain: str):
        if not self._require_admin():
            return
        if not domain:
            messagebox.showwarning("SecureMail", "Nhap domain can dang ky DKIM.")
            return

        def action():
            return client_core.register_dkim_domain(domain)

        def done(result: dict[str, Any]):
            state = "created" if result.get("created") else "already registered"
            self._append_log(
                f"DKIM domain {result['domain']} {state}; identity={result['identity']} serial={result['serial']}"
            )
            self._append_log(f"MTA key: {result['key_path']}")
            messagebox.showinfo("SecureMail", f"DKIM domain {result['domain']} {state} in KDS.")
            try:
                if hasattr(self, "logs_tree") and self.logs_tree.winfo_exists():
                    self._refresh_monitor_data()
            except tk.TclError:
                pass

        self._run_task("Register DKIM domain", action, done)

    def _populate_logs(self, logs: list[dict[str, Any]]):
        if not hasattr(self, "logs_tree"):
            return
        self.logs_tree.delete(*self.logs_tree.get_children())
        for idx, log in enumerate(logs):
            self.logs_tree.insert("", "end", iid=str(idx), values=(
                format_ts(log.get("ts")),
                log.get("service", ""),
                log.get("event", ""),
                log.get("details", ""),
            ))
        self._monitor_logs_cache = logs

    def _populate_alerts(self, logs: list[dict[str, Any]], metrics: dict[str, Any]):
        if not hasattr(self, "alert_text"):
            return
        self.alert_text.configure(state="normal")
        self.alert_text.delete("1.0", "end")
        self.alert_text.insert("end", "METRICS\n")
        if metrics.get("error"):
            self.alert_text.insert("end", f"  SQL Server: {metrics['error']}\n\n")
        else:
            for key, value in metrics.items():
                self.alert_text.insert("end", f"  {key}: {value}\n")
            self.alert_text.insert("end", "\n")
        self.alert_text.insert("end", "ALERTS\n")
        alerts = infer_alerts(logs)
        if not alerts:
            self.alert_text.insert("end", "  No alert events found in recent logs.\n")
        for alert in alerts[:30]:
            self.alert_text.insert("end", f"  [{alert['service']}] {alert['title']}\n")
            self.alert_text.insert("end", f"      {alert['details']}\n")
        self.alert_text.configure(state="disabled")

    def _show_selected_log(self):
        selected = self.logs_tree.selection()
        if not selected:
            return
        idx = int(selected[0])
        logs = getattr(self, "_monitor_logs_cache", [])
        if idx >= len(logs):
            return
        log = logs[idx]
        self.operation_log = self._build_right_panel("Selected Event")
        self._append_log(f"Time: {format_ts(log.get('ts'))}")
        self._append_log(f"Service: {log.get('service')}")
        self._append_log(f"Event: {log.get('event')}")
        self._append_log(f"Details: {log.get('details')}")

    # ------------------------------------------------------------------
    # Scenario Lab
    # ------------------------------------------------------------------
    def show_scenarios(self):
        if not self._require_admin():
            return
        self._clear_main()
        self.operation_log = self._build_right_panel("Scenario Evidence")
        self._page_title("Scenario Lab", "Chay bootstrap va 8 kich ban bao mat tu run_demo.py.")

        shell = tk.Frame(self.main, bg=COLORS["bg"])
        shell.grid(row=1, column=0, sticky="nsew")
        shell.grid_columnconfigure(0, weight=0)
        shell.grid_columnconfigure(1, weight=1)
        shell.grid_rowconfigure(0, weight=1)

        list_card = self._surface(shell)
        list_card.grid(row=0, column=0, sticky="ns", padx=(0, 10))
        list_inner = tk.Frame(list_card, bg=COLORS["surface"])
        list_inner.pack(fill="both", expand=True, padx=12, pady=12)
        ttk.Button(list_inner, text="Bootstrap", style="Primary.TButton",
                   command=lambda: self._run_scenario_cmd("bootstrap")).pack(fill="x", pady=(0, 6))
        ttk.Button(list_inner, text="Run all", command=lambda: self._run_scenario_cmd("all")).pack(fill="x", pady=(0, 12))
        self.scenario_rows: dict[str, tk.Label] = {}
        for number, (name, mechanism) in SCENARIO_META.items():
            row = tk.Frame(list_inner, bg=COLORS["surface"], highlightbackground=COLORS["border"], highlightthickness=1)
            row.pack(fill="x", pady=4)
            tk.Label(row, text=f"{number}. {name}", bg=COLORS["surface"], fg=COLORS["text"],
                     font=("Segoe UI Semibold", 9), wraplength=255, justify="left").pack(anchor="w", padx=8, pady=(8, 1))
            tk.Label(row, text=mechanism, bg=COLORS["surface"], fg=COLORS["muted"],
                     wraplength=255, justify="left").pack(anchor="w", padx=8)
            bottom = tk.Frame(row, bg=COLORS["surface"])
            bottom.pack(fill="x", padx=8, pady=8)
            status = self._pill(bottom, self.state_data.scenario_status.get(number, "READY"), "gray")
            status.pack(side="left")
            self.scenario_rows[number] = status
            ttk.Button(bottom, text="Run", command=lambda n=number: self._run_scenario_cmd(n)).pack(side="right")

        console_card = self._surface(shell)
        console_card.grid(row=0, column=1, sticky="nsew")
        console_card.grid_columnconfigure(0, weight=1)
        console_card.grid_rowconfigure(1, weight=1)
        tk.Label(console_card, text="Console Output", bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 13)).grid(row=0, column=0, sticky="w", padx=12, pady=10)
        self.scenario_console = tk.Text(console_card, wrap="word", bg="#0F172A", fg="#E2E8F0",
                                        insertbackground="#E2E8F0", padx=10, pady=10,
                                        font=("Consolas", 9), borderwidth=0)
        self.scenario_console.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _run_scenario_cmd(self, cmd: str):
        if hasattr(self, "scenario_console"):
            self.scenario_console.configure(state="normal")
            self.scenario_console.delete("1.0", "end")
            self.scenario_console.insert("end", f"$ python -m securemail.run_demo {cmd}\n\n")
            self.scenario_console.configure(state="disabled")
        if cmd in getattr(self, "scenario_rows", {}):
            self._set_pill(self.scenario_rows[cmd], "RUNNING", "info")

        def action():
            env = os.environ.copy()
            env.setdefault("PYTHONIOENCODING", "utf-8")
            proc = subprocess.run(
                [sys.executable, "-m", "securemail.run_demo", cmd],
                cwd=PROJECT_ROOT,
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                timeout=600,
            )
            return proc.returncode, proc.stdout

        def done(result: tuple[int, str]):
            code, output = result
            if hasattr(self, "scenario_console"):
                self.scenario_console.configure(state="normal")
                self.scenario_console.insert("end", output)
                self.scenario_console.configure(state="disabled")
            passed = code == 0 and ("[FAIL]" not in output)
            status_text = "PASS" if passed else "CHECK"
            if cmd in getattr(self, "scenario_rows", {}):
                self._set_pill(self.scenario_rows[cmd], status_text, "success" if passed else "warning")
                self.state_data.scenario_status[cmd] = status_text
            self._append_log(f"Scenario {cmd} exit_code={code}; status={status_text}")
            self._append_log(explain_scenario(cmd, output))

        self._run_task(f"Run scenario {cmd}", action, done)


def friendly_error(exc: BaseException) -> str:
    text = str(exc)
    lower = text.lower()
    if isinstance(exc, FileNotFoundError):
        return "Local certificate/private key not found. Please register or bootstrap first."
    if "connection refused" in lower or "winerror 10061" in lower:
        if "9000" in text:
            return "CA Service is offline. Start: python -m securemail.main_ca serve"
        if "9001" in text:
            return "KDS is offline. Start: python -m securemail.main_kds"
        if "9002" in text:
            return "Ticket Service is offline. Start: python -m securemail.main_ticket"
        if "2525" in text:
            return "SMTP service is offline. Start: python -m securemail.main_mail_server"
        if "1100" in text:
            return "POP3 service is offline. Start: python -m securemail.main_mail_server"
        return "A local SecureMail service is offline. Check CA/KDS/Ticket/Mail Server."
    if "no cert" in lower:
        return "Recipient has no certificate in KDS."
    if "revoked" in lower or "ocsp=revoked" in lower:
        return "Certificate has been revoked."
    if "decrypt" in lower:
        return "Login/decryption failed. Check password or recovered private key."
    if "login failed" in lower:
        return "Login failed. Check email/password and Ticket Service."
    if "pymssql" in lower or "sql" in lower:
        return f"SQL Server unavailable: {text}"
    return text or exc.__class__.__name__


def is_port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.65):
            return True
    except OSError:
        return False


def find_service_pids() -> set[int]:
    pids: set[int] = set()
    for port in SERVICE_PORTS.values():
        pids.update(find_pids_by_port(port))
    current_pid = os.getpid()
    return {pid for pid in pids if pid != current_pid}


def find_pids_by_port(port: int) -> set[int]:
    if os.name == "nt":
        return find_pids_by_port_windows(port)
    return find_pids_by_port_posix(port)


def find_pids_by_port_windows(port: int) -> set[int]:
    try:
        output = subprocess.check_output(
            ["netstat", "-ano", "-p", "tcp"],
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except Exception:
        return set()

    pids: set[int] = set()
    suffix = f":{port}"
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] != "TCP":
            continue
        local_addr, state, pid_text = parts[1], parts[3], parts[4]
        if state.upper() != "LISTENING" or not local_addr.endswith(suffix):
            continue
        with contextlib.suppress(ValueError):
            pids.add(int(pid_text))
    return pids


def find_pids_by_port_posix(port: int) -> set[int]:
    try:
        output = subprocess.check_output(
            ["lsof", "-ti", f"tcp:{port}", "-sTCP:LISTEN"],
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except Exception:
        return set()
    pids: set[int] = set()
    for line in output.splitlines():
        with contextlib.suppress(ValueError):
            pids.add(int(line.strip()))
    return pids


def terminate_process_tree(pid: int):
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pid, signal.SIGTERM)
    time.sleep(0.5)
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pid, signal.SIGKILL)


def format_ts(value: Any) -> str:
    if isinstance(value, dt.datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    return str(value)[:19].replace("T", " ")


def read_audit_logs(limit: int = 200) -> list[dict[str, Any]]:
    tables = [
        ("ca.audit_log", "CA"),
        ("ticket.audit_log", "TICKET"),
        ("kds.audit_log", "KDS"),
        ("mail.server_log", "MAIL"),
    ]
    logs: list[dict[str, Any]] = []
    try:
        from securemail.db_conn import get_conn
        conn = get_conn()
        cursor = conn.cursor()
        for table, service in tables:
            cursor.execute(f"SELECT TOP ({limit}) ts, event, details FROM {table} ORDER BY ts DESC")
            for row in cursor.fetchall():
                logs.append({"ts": row[0], "service": service, "event": row[1], "details": row[2] or ""})
        conn.close()
    except Exception as exc:
        return [{"ts": dt.datetime.now(), "service": "MONITOR", "event": "log_read_failed", "details": friendly_error(exc)}]
    logs.sort(key=lambda item: str(item["ts"]), reverse=True)
    return logs[:limit]


def read_metrics() -> dict[str, Any]:
    queries = {
        "total_mails": "SELECT COUNT(*) FROM mail.mailbox",
        "dmarc_quarantine": "SELECT COUNT(*) FROM mail.mailbox WHERE dmarc_action='quarantine'",
        "revoked_certs": "SELECT COUNT(*) FROM ca.issued WHERE status='revoked'",
        "active_principals": "SELECT COUNT(*) FROM ticket.principals",
        "revoked_tgts": "SELECT COUNT(*) FROM ticket.revoked_tgts",
    }
    out: dict[str, Any] = {}
    try:
        from securemail.db_conn import get_conn
        conn = get_conn()
        cursor = conn.cursor()
        for key, sql in queries.items():
            cursor.execute(sql)
            out[key] = cursor.fetchone()[0]
        conn.close()
    except Exception as exc:
        out["error"] = friendly_error(exc)
    return out


def infer_alerts(logs: list[dict[str, Any]]) -> list[dict[str, str]]:
    patterns = (
        ("replay", "Replay Attack Blocked"),
        ("revoked", "Revoked Certificate"),
        ("spoof", "Spoofed Sender"),
        ("quarantine", "DMARC Quarantine"),
        ("reject", "DMARC Reject"),
        ("invalid", "Invalid Crypto/Policy"),
        ("failed", "Operation Failed"),
    )
    alerts = []
    for log in logs:
        hay = f"{log.get('event', '')} {log.get('details', '')}".lower()
        for needle, title in patterns:
            if needle in hay:
                alerts.append({
                    "service": str(log.get("service", "")),
                    "title": title,
                    "details": str(log.get("details", ""))[:220],
                })
                break
    return alerts


def explain_scenario(cmd: str, output: str) -> str:
    if cmd == "bootstrap":
        return "Bootstrap tao identity server, user demo, SPF/DMARC va CRL ban dau."
    if cmd == "all":
        return "Run all gom toan bo happy path va attack scenarios; xem console de lay bang chung PASS/FAIL."
    name, mechanism = SCENARIO_META.get(cmd, ("Scenario", ""))
    if "PASS" in output:
        return f"{name}: PASS - {mechanism}."
    if "FAIL" in output:
        return f"{name}: can inspect output - co dau hieu FAIL."
    return f"{name}: hoan tat subprocess, can xem console output de ket luan."


def main():
    os.chdir(PROJECT_ROOT)
    app = SecureMailApp()
    app.mainloop()


if __name__ == "__main__":
    main()
