"""Tkinter desktop GUI for SecureMail.

Run from the project root:
    python -m securemail.gui.app
"""

from __future__ import annotations

import contextlib
import datetime as dt
import argparse
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
import tkinter.font as tkfont
from tkinter import messagebox, ttk

from cryptography import x509

from securemail import client_core


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DOMAIN = "mail.local"
APP_MODES = {"client", "monitor", "all"}


COLORS = {
    "bg": "#0E1117",
    "auth_bg": "#0B1020",
    "nav": "#111318",
    "header": "#0A0C10",
    "surface": "#181B22",
    "surface_2": "#20242D",
    "surface_3": "#2A303B",
    "text": "#F4F7FB",
    "muted": "#A4ADBA",
    "subtle": "#707A89",
    "border": "#343A46",
    "primary": "#5B7CFA",
    "primary_2": "#A855F7",
    "success": "#22C55E",
    "warning": "#F59E0B",
    "danger": "#F43F5E",
    "info": "#38BDF8",
    "gray": "#64748B",
    "input": "#10141C",
    "table": "#121720",
    "table_alt": "#181E29",
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
    "1": ("Normal Encrypted & Signed Email", "S/MIME end-to-end, SMTP/POP3, verify signature"),
    "2": ("MITM / Public-Key Substitution", "Fake cert bị reject khi verify chain CA"),
    "3": ("Replay Attack", "Authenticator reuse bị replay cache chặn"),
    "4": ("Revoked Certificate", "CRL/OCSP từ chối cert đã revoke"),
    "5": ("Spoofed Sender", "SPF/DMARC phát hiện giả mạo sender"),
    "6": ("Reusable Ticket", "Một ST dùng nhiều lần với authenticator mới"),
    "7": ("Key Recovery", "Shamir 2-of-3 khôi phục private key"),
    "8": ("HKDF Subsession Key", "Dẫn xuất subkey theo context riêng"),
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


def _parent_bg(parent: tk.Widget | None, fallback: str = COLORS["bg"]) -> str:
    if parent is None:
        return fallback
    try:
        return str(parent.cget("bg"))
    except tk.TclError:
        return fallback


def _draw_round_rect(canvas: tk.Canvas, x1: int, y1: int, x2: int, y2: int, radius: int, **kwargs: Any) -> int:
    radius = max(0, min(radius, (x2 - x1) // 2, (y2 - y1) // 2))
    points = (
        x1 + radius, y1,
        x2 - radius, y1,
        x2, y1,
        x2, y1 + radius,
        x2, y2 - radius,
        x2, y2,
        x2 - radius, y2,
        x1 + radius, y2,
        x1, y2,
        x1, y2 - radius,
        x1, y1 + radius,
        x1, y1,
    )
    return canvas.create_polygon(points, smooth=True, splinesteps=16, **kwargs)


class RoundedFrame(tk.Frame):
    def __init__(
        self,
        parent: tk.Widget,
        fill: str = COLORS["surface"],
        border: str = COLORS["border"],
        radius: int = 12,
        **kwargs: Any,
    ):
        super().__init__(parent, bg=_parent_bg(parent), highlightthickness=0, borderwidth=0, **kwargs)
        self._rounded_fill = fill
        self._rounded_border = border
        self._rounded_radius = radius
        self._rounded_canvas = tk.Canvas(self, bg=self["bg"], highlightthickness=0, borderwidth=0)
        self._rounded_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.bind("<Configure>", self._redraw_rounding)

    def _redraw_rounding(self, _event: tk.Event | None = None):
        width = max(self.winfo_width(), 1)
        height = max(self.winfo_height(), 1)
        self._rounded_canvas.delete("all")
        _draw_round_rect(
            self._rounded_canvas,
            1,
            1,
            width - 2,
            height - 2,
            self._rounded_radius,
            fill=self._rounded_fill,
            outline=self._rounded_border,
            width=1,
        )


class RoundedPill(tk.Canvas):
    def __init__(self, parent: tk.Widget, text: str, tone: str, padx: int = 10, pady: int = 4):
        super().__init__(parent, bg=_parent_bg(parent, COLORS["surface"]), highlightthickness=0, borderwidth=0)
        self._text = text
        self._tone = tone
        self._padx = padx
        self._pady = pady
        self._font = tkfont.Font(family="Segoe UI Semibold", size=8)
        self._draw()

    def set(self, text: str, tone: str):
        self._text = text
        self._tone = tone
        self._draw()

    def _draw(self):
        fill = COLORS.get(self._tone, COLORS["gray"])
        width = self._font.measure(self._text) + (self._padx * 2)
        height = self._font.metrics("linespace") + (self._pady * 2)
        self.configure(width=width, height=height)
        self.delete("all")
        _draw_round_rect(self, 0, 0, width, height, min(11, height // 2), fill=fill, outline=fill)
        self.create_text(width // 2, height // 2, text=self._text, fill="#FFFFFF", font=self._font)


class RoundedButton(tk.Canvas):
    def __init__(self, parent: tk.Widget, text: str, command: Callable[[], None], tone: str = "primary"):
        super().__init__(parent, bg=_parent_bg(parent, COLORS["surface"]), highlightthickness=0, borderwidth=0, height=43, cursor="hand2")
        self._text = text
        self._command = command
        self._tone = tone
        self._normal = COLORS["primary"] if tone == "primary" else COLORS["surface_2"]
        self._hover = "#4768EE" if tone == "primary" else COLORS["surface_3"]
        self._fill = self._normal
        self._fg = "#FFFFFF" if tone == "primary" else COLORS["text"]
        self._font = tkfont.Font(family="Segoe UI Semibold", size=10)
        self.bind("<Configure>", self._draw)
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)
        self.bind("<Button-1>", self._invoke)

    def _draw(self, _event: tk.Event | None = None):
        width = max(self.winfo_width(), self._font.measure(self._text) + 32)
        height = max(self.winfo_height(), 43)
        self.delete("all")
        _draw_round_rect(self, 0, 0, width, height, 12, fill=self._fill, outline=self._fill)
        self.create_text(width // 2, height // 2, text=self._text, fill=self._fg, font=self._font)

    def _enter(self, _event: tk.Event):
        self._fill = self._hover
        self._draw()

    def _leave(self, _event: tk.Event):
        self._fill = self._normal
        self._draw()

    def _invoke(self, _event: tk.Event | None = None):
        self._command()


class SecureMailApp(tk.Tk):
    def __init__(self, mode: str = "client"):
        super().__init__()
        self.mode = mode if mode in APP_MODES else "client"
        self.title(self._window_title())
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
        self._nav_buttons: dict[str, tk.Widget] = {}
        self._active_nav_key = "login"
        self._mail_stat_labels: dict[str, tk.Label] = {}
        self._detail_panel_visible = False
        self._client_auth_view = "login"
        self._auth_error_message = ""
        self._auth_error_label: tk.Label | None = None
        self._send_in_progress = False
        self._compose_send_button: ttk.Button | None = None
        self._compose_status_label: tk.Label | None = None
        self.operation_log: tk.Text | None = None
        self._log_history: list[str] = []

        self._configure_styles()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
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
        style.configure("Surface.TFrame", background=COLORS["surface"], relief="flat", borderwidth=0)
        style.configure("Nav.TFrame", background=COLORS["nav"])
        style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["text"])
        style.configure("Muted.TLabel", foreground=COLORS["muted"], background=COLORS["bg"])
        style.configure("Surface.TLabel", background=COLORS["surface"], foreground=COLORS["text"])
        style.configure("Title.TLabel", font=("Segoe UI Semibold", 20), background=COLORS["bg"], foreground=COLORS["text"])
        style.configure("Section.TLabel", font=("Segoe UI Semibold", 12), background=COLORS["surface"])
        style.configure(
            "TEntry",
            padding=(12, 8),
            fieldbackground=COLORS["input"],
            background=COLORS["input"],
            foreground=COLORS["text"],
            bordercolor=COLORS["border"],
            lightcolor=COLORS["border"],
            darkcolor=COLORS["border"],
            insertcolor=COLORS["text"],
            relief="flat",
        )
        style.map("TEntry",
                  bordercolor=[("focus", COLORS["primary"])],
                  lightcolor=[("focus", COLORS["primary"])],
                  darkcolor=[("focus", COLORS["primary"])])
        style.configure(
            "TCombobox",
            padding=(10, 8),
            fieldbackground=COLORS["input"],
            background=COLORS["surface_2"],
            foreground=COLORS["text"],
            bordercolor=COLORS["border"],
            arrowcolor=COLORS["primary"],
            relief="flat",
        )
        style.map("TCombobox", fieldbackground=[("readonly", COLORS["input"])], foreground=[("readonly", COLORS["text"])])
        style.configure("TCheckbutton", background=COLORS["surface"], foreground=COLORS["text"], padding=(2, 4))
        style.configure("TButton", padding=(14, 9), background=COLORS["surface_2"], foreground=COLORS["text"], borderwidth=0, relief="flat")
        style.map("TButton", background=[("active", COLORS["surface_3"]), ("disabled", COLORS["surface_2"])], relief=[("active", "flat")])
        style.configure("Primary.TButton", padding=(16, 10), background=COLORS["primary"], foreground="#FFFFFF", borderwidth=0, relief="flat")
        style.map("Primary.TButton", foreground=[("active", "#FFFFFF"), ("!disabled", "#FFFFFF")],
                  background=[("active", "#4A6CF7"), ("disabled", COLORS["surface_3"]), ("!disabled", COLORS["primary"])],
                  relief=[("active", "flat")])
        style.configure("Secondary.TButton", padding=(14, 9), background=COLORS["surface_2"], foreground=COLORS["text"], borderwidth=0, relief="flat")
        style.configure("Danger.TButton", padding=(14, 9), background=COLORS["danger"], foreground="#FFFFFF", borderwidth=0, relief="flat")
        style.configure("Nav.TButton", anchor="w", padding=(14, 12), background=COLORS["nav"], foreground=COLORS["muted"], borderwidth=0, relief="flat")
        style.map("Nav.TButton", background=[("active", COLORS["surface_2"])], foreground=[("active", COLORS["text"])], relief=[("active", "flat")])
        style.configure(
            "Treeview",
            rowheight=36,
            fieldbackground=COLORS["table"],
            background=COLORS["table"],
            foreground=COLORS["text"],
            bordercolor=COLORS["table"],
            lightcolor=COLORS["table"],
            darkcolor=COLORS["table"],
            relief="flat",
        )
        style.map("Treeview", background=[("selected", COLORS["primary"])], foreground=[("selected", "#FFFFFF")])
        style.configure(
            "Treeview.Heading",
            font=("Segoe UI Semibold", 10),
            padding=(10, 10),
            background=COLORS["surface_2"],
            foreground=COLORS["muted"],
            bordercolor=COLORS["surface_2"],
            lightcolor=COLORS["surface_2"],
            darkcolor=COLORS["surface_2"],
            relief="flat",
        )
        style.configure("Horizontal.TSeparator", background=COLORS["border"])

    def _window_title(self) -> str:
        titles = {
            "client": "SecureMail Client",
            "monitor": "SecureMail Monitor",
            "all": "SecureMail Desktop",
        }
        return titles.get(self.mode, "SecureMail Client")

    def _shell_subtitle(self) -> str:
        subtitles = {
            "client": "Encrypted mailbox",
            "monitor": "Admin monitor for services, audit logs, warnings, metrics and scenario evidence",
            "all": "Encrypted mail client, monitoring dashboard, scenario lab",
        }
        return subtitles.get(self.mode, subtitles["client"])

    def _build_shell(self):
        header = tk.Frame(self, bg=COLORS["header"], highlightbackground=COLORS["border"], highlightthickness=1)
        self.header = header
        header.pack(side="top", fill="x")

        left_header = tk.Frame(header, bg=COLORS["header"])
        left_header.pack(side="left", padx=18, pady=12)
        tk.Label(left_header, text="SecureMail", font=("Segoe UI Semibold", 19),
                 bg=COLORS["header"], fg=COLORS["text"]).pack(anchor="w")
        tk.Label(left_header, text=self._shell_subtitle(),
                 bg=COLORS["header"], fg=COLORS["muted"]).pack(anchor="w")

        status_header = tk.Frame(header, bg=COLORS["header"])
        status_header.pack(side="right", padx=18, pady=10)
        self.user_pill = self._pill(status_header, "Not logged in", "gray")
        self.user_pill.pack(side="left", padx=4)
        self.tgt_pill = self._pill(status_header, "NO TGT", "gray")
        self.tgt_pill.pack(side="left", padx=4)
        if self.mode != "client":
            for service in SERVICE_PORTS:
                pill = self._pill(status_header, f"{service} ?", "gray")
                pill.pack(side="left", padx=3)
                self._service_labels[service] = pill

        body = tk.Frame(self, bg=COLORS["bg"])
        self.body = body
        body.pack(side="top", fill="both", expand=True)
        body.grid_columnconfigure(0, weight=0)
        body.grid_columnconfigure(1, weight=1)
        body.grid_columnconfigure(2, weight=0)
        body.grid_rowconfigure(0, weight=1)

        self.nav_shell = tk.Frame(
            body,
            bg=COLORS["nav"],
            width=230 if self.mode == "client" else 245,
            highlightbackground=COLORS["border"],
            highlightthickness=1,
        )
        self.nav_shell.grid(row=0, column=0, sticky="ns")
        self.nav_shell.grid_propagate(False)
        self.nav_canvas = tk.Canvas(self.nav_shell, bg=COLORS["nav"], highlightthickness=0, borderwidth=0)
        self.nav_canvas.pack(fill="both", expand=True)
        self.nav = tk.Frame(self.nav_canvas, bg=COLORS["nav"])
        self._nav_window = self.nav_canvas.create_window((0, 0), window=self.nav, anchor="nw")
        self.nav.bind("<Configure>", self._sync_nav_scrollregion)
        self.nav_canvas.bind("<Configure>", self._sync_nav_width)
        self.nav_canvas.bind("<Enter>", self._bind_nav_mousewheel)
        self.nav_canvas.bind("<Leave>", self._unbind_nav_mousewheel)
        self.nav.bind("<Enter>", self._bind_nav_mousewheel)
        self.nav.bind("<Leave>", self._unbind_nav_mousewheel)
        self._build_nav()

        self.main = tk.Frame(body, bg=COLORS["bg"])
        self.main.grid(row=0, column=1, sticky="nsew", padx=18, pady=18)
        self.main.grid_columnconfigure(0, weight=1)
        self.main.grid_rowconfigure(1, weight=1)

        self.right: tk.Frame | None = None
        if self.mode != "client":
            self.right = tk.Frame(body, bg=COLORS["surface"], width=260,
                                  highlightbackground=COLORS["border"], highlightthickness=1)
            self.right.grid_propagate(False)

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

        brand = tk.Frame(parent, bg=COLORS["nav"])
        brand.pack(fill="x", padx=16, pady=(20, 18))
        logo = tk.Label(
            brand,
            text="SM",
            bg=COLORS["primary"],
            fg="#FFFFFF",
            width=4,
            height=2,
            font=("Segoe UI Semibold", 10),
        )
        logo.pack(anchor="w")
        mode_title = "SecureMail Client" if self.mode == "client" else ("SecureMail Monitor" if self.mode == "monitor" else "SecureMail")
        tk.Label(brand, text=mode_title, bg=COLORS["nav"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 13)).pack(anchor="w", pady=(10, 2))
        tk.Label(brand, text=self.state_data.email or "Not signed in", bg=COLORS["nav"], fg=COLORS["muted"],
                 font=("Segoe UI", 9)).pack(anchor="w")

        def section(text: str):
            tk.Label(parent, text=text.upper(), bg=COLORS["nav"], fg=COLORS["subtle"],
                     font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=18, pady=(18, 6))

        def nav_button(key: str, text: str, command: Callable[[], None]):
            active = key == self._active_nav_key
            bg = COLORS["surface_2"] if active else COLORS["nav"]
            fg = COLORS["text"] if active else COLORS["muted"]
            row = tk.Frame(parent, bg=bg, cursor="hand2")
            row.pack(fill="x", padx=12, pady=3)
            accent = tk.Frame(row, bg=COLORS["primary"] if active else bg, width=4)
            accent.pack(side="left", fill="y")
            label = tk.Label(row, text=text, bg=bg, fg=fg, anchor="w",
                             font=("Segoe UI Semibold" if active else "Segoe UI", 10), padx=12, pady=11)
            label.pack(side="left", fill="x", expand=True)

            def on_enter(_event: tk.Event):
                if key != self._active_nav_key:
                    row.configure(bg=COLORS["surface"])
                    accent.configure(bg=COLORS["surface"])
                    label.configure(bg=COLORS["surface"], fg=COLORS["text"])

            def on_leave(_event: tk.Event):
                if key != self._active_nav_key:
                    row.configure(bg=COLORS["nav"])
                    accent.configure(bg=COLORS["nav"])
                    label.configure(bg=COLORS["nav"], fg=COLORS["muted"])

            def invoke(_event: tk.Event | None = None):
                self._active_nav_key = key
                command()

            for widget in (row, accent, label):
                widget.bind("<Button-1>", invoke)
                widget.bind("<Enter>", on_enter)
                widget.bind("<Leave>", on_leave)
            self._nav_buttons[key] = row

        role = self.state_data.role

        if self.mode == "monitor":
            section("Services")
            self._add_service_toggle_button(parent).pack(fill="x", padx=12, pady=3)
            ttk.Button(parent, text="Refresh services", command=self.refresh_services).pack(fill="x", padx=12, pady=3)
            ttk.Separator(parent).pack(fill="x", padx=12, pady=18)

            section("Account")
            if not role:
                nav_button("login", "Monitor Login", self.show_login)
                return
            if role != "admin":
                nav_button("access", "Monitor Access", self.show_monitor_access_denied)
                ttk.Separator(parent).pack(fill="x", padx=12, pady=18)
                ttk.Button(parent, text="Logout", command=self.logout).pack(fill="x", padx=12, pady=3)
                return

            section("Monitoring")
            nav_button("monitor", "Dashboard", self.show_monitor)

            section("Administration")
            nav_button("accounts", "Accounts", self.show_accounts)
            nav_button("dkim", "DKIM Domains", self.show_dkim_domains)

            section("Scenario Lab")
            nav_button("scenario", "Scenarios", self.show_scenarios)

            ttk.Separator(parent).pack(fill="x", padx=12, pady=18)
            ttk.Button(parent, text="Logout", command=self.logout).pack(fill="x", padx=12, pady=3)
            return

        if self.mode == "client":
            section("Account")
            if not role:
                nav_button("login", "Login / Register", self.show_login)
                return

            ttk.Button(parent, text="Compose", style="Primary.TButton",
                       command=self.show_compose).pack(fill="x", padx=12, pady=(8, 12))
            section("User App")
            nav_button("inbox", "Inbox", lambda: self._nav_to_folder('inbox'))
            nav_button("sent", "Sent", lambda: self._nav_to_folder('sent'))
            nav_button("security", "Security / Recovery", self.show_security)

            ttk.Separator(parent).pack(fill="x", padx=12, pady=18)
            ttk.Button(parent, text="Logout", command=self.logout).pack(fill="x", padx=12, pady=3)
            return

        section("Services")
        self._add_service_toggle_button(parent).pack(fill="x", padx=12, pady=3)
        ttk.Button(parent, text="Refresh services", command=self.refresh_services).pack(fill="x", padx=12, pady=3)

        if not role:
            ttk.Separator(parent).pack(fill="x", padx=12, pady=18)
            section("Account")
            nav_button("login", "Login / Register", self.show_login)
            return

        ttk.Separator(parent).pack(fill="x", padx=12, pady=18)
        section("User App")
        nav_button("inbox", "Inbox", self.show_inbox)
        nav_button("sent", "Sent", self.show_sent)
        nav_button("compose", "Compose", self.show_compose)
        nav_button("security", "Security / Recovery", self.show_security)

        if role == "admin":
            section("Monitoring")
            nav_button("monitor", "Dashboard", self.show_monitor)

            section("Administration")
            nav_button("accounts", "Accounts", self.show_accounts)
            nav_button("dkim", "DKIM Domains", self.show_dkim_domains)

            section("Scenario Lab")
            nav_button("scenario", "Scenarios", self.show_scenarios)

        ttk.Separator(parent).pack(fill="x", padx=12, pady=18)
        ttk.Button(parent, text="Logout", command=self.logout).pack(fill="x", padx=12, pady=3)

    def _set_client_chrome(self, visible: bool):
        if self.mode != "client":
            return
        if visible:
            if not self.header.winfo_ismapped():
                self.header.pack(side="top", fill="x", before=self.body)
            if not self.nav_shell.winfo_ismapped():
                self.nav_shell.grid(row=0, column=0, sticky="ns")
            self.main.grid_configure(row=0, column=1, columnspan=1, sticky="nsew", padx=18, pady=18)
            self.body.grid_columnconfigure(0, weight=0)
            self.body.grid_columnconfigure(1, weight=1)
            self.body.grid_columnconfigure(2, weight=0)
            return
        if self.header.winfo_ismapped():
            self.header.pack_forget()
        if self.nav_shell.winfo_ismapped():
            self.nav_shell.grid_remove()
        self.main.grid_configure(row=0, column=0, columnspan=3, sticky="nsew", padx=0, pady=0)
        self.body.grid_columnconfigure(0, weight=1)
        self.body.grid_columnconfigure(1, weight=0)
        self.body.grid_columnconfigure(2, weight=0)

    def _set_active_nav(self, key: str):
        self._active_nav_key = key
        if hasattr(self, "nav"):
            self._build_nav()

    def _add_service_toggle_button(self, parent: tk.Widget) -> ttk.Button:
        btn = ttk.Button(parent, text="Start all services", style="Primary.TButton",
                         command=self.toggle_all_services)
        self._service_toggle_buttons.append(btn)
        self._update_service_toggle_buttons()
        return btn

    def _build_right_panel(self, title: str) -> tk.Text | None:
        if self.mode == "client" or self.right is None:
            return None
        if not self._detail_panel_visible:
            return None
        self._clear_right()
        head = tk.Frame(self.right, bg=COLORS["surface"])
        head.pack(fill="x", padx=14, pady=(14, 4))
        tk.Label(head, text=title, bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 13)).pack(side="left", anchor="w")
        ttk.Button(head, text="Hide", command=self._hide_detail_panel).pack(side="right")
        tk.Label(self.right, text="Operation detail, audit evidence and selected event context",
                 bg=COLORS["surface"], fg=COLORS["muted"], wraplength=220, justify="left").pack(anchor="w", padx=14)
        text = tk.Text(self.right, height=18, wrap="word", borderwidth=0, bg=COLORS["input"],
                       fg=COLORS["text"], insertbackground=COLORS["text"], padx=10, pady=10, font=("Consolas", 9))
        text.pack(fill="both", expand=True, padx=14, pady=14)
        text.configure(state="disabled")
        self._right_widgets.append(text)
        return text

    def _show_detail_panel(self):
        if self.mode == "client" or self.right is None:
            return
        if not self._detail_panel_visible:
            self._detail_panel_visible = True
            self.right.grid(row=0, column=2, sticky="ns")

    def _hide_detail_panel(self):
        if self.right is None:
            return
        self._detail_panel_visible = False
        self.operation_log = None
        self._clear_right()
        self.right.grid_remove()

    def _toggle_detail_panel(self):
        if self._detail_panel_visible:
            self._hide_detail_panel()
        else:
            self._show_detail_panel()
            self.operation_log = self._build_right_panel("Monitor Detail")

    def _clear_main(self):
        for child in self.main.winfo_children():
            child.destroy()
        for row in range(6):
            self.main.grid_rowconfigure(row, weight=0)
        self.main.grid_rowconfigure(1, weight=1)

    def _clear_right(self):
        if self.right is None:
            self._right_widgets.clear()
            return
        for child in self.right.winfo_children():
            child.destroy()
        self._right_widgets.clear()

    def _page_title(self, title: str, subtitle: str = ""):
        top = tk.Frame(self.main, bg=COLORS["bg"])
        top.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        tk.Label(top, text=title, bg=COLORS["bg"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 22)).pack(anchor="w")
        if subtitle:
            tk.Label(top, text=subtitle, bg=COLORS["bg"], fg=COLORS["muted"],
                     wraplength=850, justify="left", font=("Segoe UI", 10)).pack(anchor="w", pady=(4, 0))

    def _surface(self, parent: tk.Widget | None = None) -> tk.Frame:
        parent = parent or self.main
        return RoundedFrame(parent, fill=COLORS["surface"], border=COLORS["border"], radius=12)

    def _field(self, parent: tk.Widget, label: str, show: str | None = None) -> ttk.Entry:
        tk.Label(parent, text=label, bg=COLORS["surface"], fg=COLORS["muted"]).pack(anchor="w", pady=(10, 3))
        entry = ttk.Entry(parent, show=show)
        entry.pack(fill="x", ipady=5)
        return entry

    def _pill(self, parent: tk.Widget, text: str, tone: str) -> tk.Label:
        return RoundedPill(parent, text, tone)

    def _set_pill(self, label: tk.Label, text: str, tone: str):
        if hasattr(label, "set"):
            label.set(text, tone)
            return
        label.configure(text=text, bg=COLORS.get(tone, COLORS["gray"]))

    def _append_log(self, line: str):
        ts = dt.datetime.now().strftime("%H:%M:%S")
        self._log_history.append(f"[{ts}] {line}")
        if self.operation_log is None:
            return
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

    def _require_key(self) -> bool:
        """Require both a valid session AND a usable private key.

        If the user is logged in but their local private key is missing
        or corrupted (restricted mode), redirect them to the Security /
        Recovery screen instead of crashing.
        """
        if not self._require_login():
            return False
        if self.state_data.ctx.get("privkey") is not None:
            return True
        messagebox.showwarning(
            "SecureMail",
            "Local private key is missing or corrupted.\n"
            "You are in restricted mode.\n\n"
            "Please go to Security / Recovery to restore your key.",
        )
        self.show_security()
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
                    if label == "Send secure mail":
                        self._set_compose_busy(False, "Failed")
                    if self.mode == "client" and label in {"Login", "Register identity"}:
                        self._set_auth_error(message)
                        continue
                    detail = "" if label == "Login" else (tb or "")
                    self._show_error(message, detail)
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
        self._show_default_page()

    def _show_default_page(self):
        if not self.state_data.ctx:
            self.show_login()
            return
        if self.mode == "monitor":
            if self.state_data.role == "admin":
                self.show_monitor()
            else:
                self.show_monitor_access_denied()
            return
        self.show_inbox()

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

    def _on_close(self):
        self.state_data.ctx = None
        self.state_data.inbox.clear()
        self.state_data.sent.clear()
        self.state_data.selected_message = None
        with contextlib.suppress(Exception):
            client_core.clear_session()
        self.destroy()

    # ------------------------------------------------------------------
    # Login / Register
    # ------------------------------------------------------------------
    def show_monitor_access_denied(self):
        self._set_active_nav("access")
        self._clear_main()
        self.operation_log = self._build_right_panel("Monitor Access")
        self._page_title("Monitor Access", "Dang nhap bang tai khoan admin de quan tri service, audit va alert.")

        card = self._surface()
        card.grid(row=1, column=0, sticky="ew")
        inner = tk.Frame(card, bg=COLORS["surface"])
        inner.pack(fill="x", padx=18, pady=18)
        tk.Label(inner, text="Admin session required", bg=COLORS["surface"], fg=COLORS["danger"],
                 font=("Segoe UI Semibold", 14)).pack(anchor="w")
        tk.Label(
            inner,
            text="Tai khoan hien tai khong co role admin. Hay logout va dang nhap bang tai khoan admin duoc cap.",
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            wraplength=760,
            justify="left",
        ).pack(anchor="w", pady=(6, 0))
        self._append_log("Monitor mode requires role=admin.")

    def show_login(self):
        self._set_active_nav("login")
        self._clear_main()
        self.operation_log = self._build_right_panel("Authentication Flow")
        if self.mode == "monitor":
            self._set_client_chrome(True)
            self._page_title("Monitor Login", "Admin console for service control, audit and incident evidence.")
        else:
            self._set_client_chrome(False)

        wrapper = tk.Frame(self.main, bg=COLORS["bg"])

        if self.mode == "monitor":
            wrapper.grid(row=1, column=0, sticky="nsew")
            self._build_monitor_login(wrapper)
            self._append_log("1. Login bang admin de mo Monitor Dashboard")
            self._append_log("2. Monitor co quyen start/stop services, xem log, warning, audit")
            self._append_log("3. Neu chua co admin, dung Bootstrap data de khoi tao du lieu demo")
            return

        for row in range(6):
            self.main.grid_rowconfigure(row, weight=0)
        self.main.grid_rowconfigure(0, weight=1)
        wrapper.grid(row=0, column=0, sticky="nsew")
        self._build_client_login(wrapper)
        self._append_log("1. Doc private key local / tao keypair khi register")
        self._append_log("2. AS-REQ/AS-REP de lay TGT khi login")
        self._append_log("3. Session san sang cho SMTP/POP3 service ticket")

    def _build_client_login(self, parent: tk.Widget):
        parent.configure(bg=COLORS["auth_bg"])
        parent.grid_columnconfigure(0, weight=1)
        parent.grid_columnconfigure(1, weight=0)
        parent.grid_columnconfigure(2, weight=1)
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_rowconfigure(1, weight=0)
        parent.grid_rowconfigure(2, weight=1)

        auth_card = RoundedFrame(
            parent,
            fill=COLORS["surface"],
            border=COLORS["border"],
            radius=18,
            width=460,
            height=660 if self._client_auth_view == "register" else 545,
        )
        auth_card.grid(row=1, column=1, sticky="n", pady=30)
        auth_card.grid_propagate(False)
        tk.Frame(auth_card, bg=COLORS["primary"], height=4).pack(fill="x", padx=26, pady=(18, 0))
        auth_inner = tk.Frame(auth_card, bg=COLORS["surface"])
        auth_inner.pack(fill="both", expand=True, padx=34, pady=(22, 32))

        mark = tk.Label(
            auth_inner,
            text="SM",
            bg=COLORS["primary"],
            fg="#FFFFFF",
            width=4,
            height=2,
            font=("Segoe UI Semibold", 10),
        )
        mark.pack(anchor="center", pady=(0, 12))
        tk.Label(auth_inner, text="SecureMail", bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 24)).pack(anchor="center")
        tk.Label(
            auth_inner,
            text="Encrypted internal mail client",
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            font=("Segoe UI", 10),
        ).pack(anchor="center", pady=(2, 22))

        self._auth_error_label = tk.Label(
            auth_inner,
            text=self._auth_error_message or " ",
            bg="#2B1620" if self._auth_error_message else COLORS["surface"],
            fg="#FDA4AF" if self._auth_error_message else COLORS["surface"],
            wraplength=370,
            justify="left",
            anchor="w",
            padx=10,
            pady=8 if self._auth_error_message else 0,
            font=("Segoe UI", 9),
        )
        self._auth_error_label.pack(fill="x", pady=(0, 14 if self._auth_error_message else 2))

        if self._client_auth_view == "register":
            self._build_register_form(auth_inner)
        else:
            self._build_login_form(auth_inner)

    def _build_login_form(self, parent: tk.Widget):
        tk.Label(parent, text="Welcome back", bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 22)).pack(anchor="w")
        tk.Label(parent, text="Sign in to open your encrypted mailbox.",
                 bg=COLORS["surface"], fg=COLORS["muted"], wraplength=360, justify="left").pack(anchor="w", pady=(4, 18))
        email_entry = self._field(parent, "Email")
        password_entry = self._field(parent, "Password", show="*")
        remember = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent, text="Remember session", variable=remember).pack(anchor="w", pady=(12, 14))
        self._web_button(
            parent,
            "Open mailbox",
            lambda: self._login(email_entry.get().strip(), password_entry.get(), remember.get()),
        ).pack(fill="x")
        footer = tk.Frame(parent, bg=COLORS["surface"])
        footer.pack(fill="x", pady=(18, 0))
        tk.Label(footer, text="New to SecureMail?", bg=COLORS["surface"], fg=COLORS["muted"]).pack(side="left")
        self._link_label(footer, "Create account", lambda: self._switch_client_auth("register")).pack(side="left", padx=(6, 0))

    def _build_register_form(self, parent: tk.Widget):
        tk.Label(parent, text="Create account", bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 22)).pack(anchor="w")
        tk.Label(parent, text="Public registration creates a normal user identity with local keypair and CA-signed certificate.",
                 bg=COLORS["surface"], fg=COLORS["muted"], wraplength=380, justify="left").pack(anchor="w", pady=(4, 14))
        name_entry = self._field(parent, "Display name")
        reg_email_entry = self._field(parent, "Email")
        reg_password_entry = self._field(parent, "Password", show="*")
        reg_confirm_entry = self._field(parent, "Confirm password", show="*")
        self._web_button(
            parent,
            "Generate identity",
            lambda: self._register_account(
                reg_email_entry.get().strip(),
                reg_password_entry.get(),
                reg_confirm_entry.get(),
                name_entry.get().strip(),
            ),
        ).pack(fill="x", pady=(16, 0))
        footer = tk.Frame(parent, bg=COLORS["surface"])
        footer.pack(fill="x", pady=(18, 0))
        tk.Label(footer, text="Already have an account?", bg=COLORS["surface"], fg=COLORS["muted"]).pack(side="left")
        self._link_label(footer, "Sign in", lambda: self._switch_client_auth("login")).pack(side="left", padx=(6, 0))

    def _switch_client_auth(self, view: str):
        self._client_auth_view = view
        self._set_auth_error("")
        self.show_login()

    def _set_auth_error(self, message: str):
        self._auth_error_message = message
        label = self._auth_error_label
        if label is None:
            return
        if message:
            label.configure(text=message, bg="#2B1620", fg="#FDA4AF", pady=8)
        else:
            label.configure(text=" ", bg=COLORS["surface"], fg=COLORS["surface"], pady=0)

    def _web_button(self, parent: tk.Widget, text: str, command: Callable[[], None], tone: str = "primary") -> RoundedButton:
        return RoundedButton(parent, text, command, tone)

    def _link_label(self, parent: tk.Widget, text: str, command: Callable[[], None]) -> tk.Label:
        label = tk.Label(parent, text=text, bg=COLORS["surface"], fg=COLORS["primary"],
                         font=("Segoe UI Semibold", 10), cursor="hand2")

        def enter(_event: tk.Event):
            label.configure(fg=COLORS["info"])

        def leave(_event: tk.Event):
            label.configure(fg=COLORS["primary"])

        label.bind("<Enter>", enter)
        label.bind("<Leave>", leave)
        label.bind("<Button-1>", lambda _event: command())
        return label

    def _build_monitor_login(self, parent: tk.Widget):
        parent.grid_columnconfigure(0, weight=1)
        card = self._surface(parent)
        card.grid(row=0, column=0, sticky="nsew")
        inner = tk.Frame(card, bg=COLORS["surface"])
        inner.pack(fill="both", expand=True, padx=24, pady=24)
        tk.Label(inner, text="Administrator access", bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 18)).pack(anchor="w")
        tk.Label(inner, text="Use the monitor to operate services, inspect audit trails and collect scenario evidence.",
                 bg=COLORS["surface"], fg=COLORS["muted"], wraplength=680, justify="left").pack(anchor="w", pady=(4, 14))
        email_entry = self._field(inner, "Admin email")
        password_entry = self._field(inner, "Password", show="*")
        tk.Label(
            inner,
            text="Nhap thong tin admin da dang ky de mo Monitor.",
            bg=COLORS["surface"],
            fg=COLORS["muted"],
            font=("Segoe UI", 9),
        ).pack(anchor="w", pady=(8, 0))
        remember = tk.BooleanVar(value=True)
        ttk.Checkbutton(inner, text="Remember admin session", variable=remember).pack(anchor="w", pady=10)
        actions = tk.Frame(inner, bg=COLORS["surface"])
        actions.pack(fill="x")
        ttk.Button(actions, text="Open Monitor", style="Primary.TButton",
                   command=lambda: self._login(email_entry.get().strip(), password_entry.get(), remember.get())).pack(side="left")
        ttk.Button(actions, text="Bootstrap data",
                   command=lambda: self._run_scenario_cmd("bootstrap")).pack(side="left", padx=10)

    def _login(self, email: str, password: str, remember: bool):
        if not email or not password:
            if self.mode == "client":
                self._set_auth_error("Enter both email and password.")
            else:
                messagebox.showwarning("SecureMail", "Nhap email va password.")
            return
        self._set_auth_error("")

        def action():
            ctx = client_core.login(email, password)
            if remember:
                client_core.save_session(ctx)
            return ctx

        def done(ctx: dict[str, Any]):
            self._set_auth_error("")
            self.state_data.ctx = ctx
            self._set_header_user()
            self._append_log(f"TGT length={len(ctx['tgt'])}; current user={ctx['email']}")
            self._show_default_page()

        self._run_task("Login", action, done)

    def _register_account(self, email: str, password: str, confirm_password: str, display_name: str):
        email = email.strip().lower()
        if not email or not password:
            self._set_auth_error("Enter email and password to create your identity.")
            return
        if not is_valid_email(email):
            self._set_auth_error("Email is not valid. Example: user@mail.local")
            return
        if len(password) < 6:
            self._set_auth_error("Password must be at least 6 characters.")
            return
        if password != confirm_password:
            self._set_auth_error("Password and confirm password do not match.")
            return
        if client_core.account_exists(email):
            self._set_auth_error(f"Account already exists: {email}")
            return
        self._set_auth_error("")

        def action():
            return client_core.public_register(email, password, display_name)

        def done(result: dict[str, Any]):
            self._set_auth_error("")
            self._append_log(f"Registered {email}; serial={result.get('serial')}")
            messagebox.showinfo("SecureMail", f"Registered {email}\nSerial: {result.get('serial')}\nBan co the dang nhap ngay.")
            self._client_auth_view = "login"
            self.show_login()

        self._run_task("Register identity", action, done)

    # ------------------------------------------------------------------
    # Mailbox
    # ------------------------------------------------------------------
    def _nav_to_folder(self, folder: str):
        """Navigate to inbox or sent and auto-fetch on arrival."""
        self._active_nav_key = folder
        if folder == "inbox":
            self.show_inbox()
        else:
            self.show_sent()

    def show_inbox(self):
        if not self._require_key():
            return
        self._show_mailbox("inbox")

    def show_sent(self):
        if not self._require_key():
            return
        self._show_mailbox("sent")

    def _show_mailbox(self, folder: str):
        self._set_client_chrome(True)
        self._set_active_nav("inbox" if folder == "inbox" else "sent")
        self._clear_main()
        self.operation_log = self._build_right_panel("Message Security")
        title = "Inbox" if folder == "inbox" else "Sent"
        subtitle = f"{self.state_data.email or ''} - signed, encrypted and policy-checked mail"
        self._page_title(title, subtitle)
        self.state_data.current_folder = folder
        self.main.grid_rowconfigure(1, weight=0)
        self.main.grid_rowconfigure(2, weight=0)
        self.main.grid_rowconfigure(3, weight=1)

        stats = tk.Frame(self.main, bg=COLORS["bg"])
        stats.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        self._build_mail_stats(stats, folder)

        toolbar = tk.Frame(self.main, bg=COLORS["bg"])
        toolbar.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        toolbar.grid_columnconfigure(1, weight=1)
        tk.Label(toolbar, text="Search", bg=COLORS["bg"], fg=COLORS["muted"]).grid(row=0, column=0, sticky="w", padx=(0, 8))
        search_var = tk.StringVar()
        search_entry = ttk.Entry(toolbar, textvariable=search_var)
        search_entry.grid(row=0, column=1, sticky="ew", ipady=6)
        filter_var = tk.StringVar(value="All")
        ttk.Combobox(toolbar, textvariable=filter_var,
                     values=("All", "Secure", "Warning", "Dangerous", "Signed", "Failed", "Quarantine"),
                     state="readonly", width=16).grid(row=0, column=2, padx=10, ipady=4)
        ttk.Button(toolbar, text="Refresh", style="Primary.TButton",
                   command=lambda: self.refresh_mailbox(folder, tree, search_var.get(), filter_var.get())).grid(row=0, column=3)
        if folder == "inbox":
            ttk.Button(toolbar, text="Compose", style="Secondary.TButton",
                       command=self.show_compose).grid(row=0, column=4, padx=(10, 0))

        table_frame = self._surface()
        table_frame.grid(row=3, column=0, sticky="nsew")
        table_frame.grid_rowconfigure(1, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)
        table_head = tk.Frame(table_frame, bg=COLORS["surface"])
        table_head.grid(row=0, column=0, columnspan=2, sticky="ew", padx=12, pady=(12, 4))
        table_head.grid_columnconfigure(0, weight=1)
        tk.Label(table_head, text="Messages", bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 12)).grid(row=0, column=0, sticky="w")
        tk.Label(table_head, text="Open a row to inspect signature and policy details.",
                 bg=COLORS["surface"], fg=COLORS["muted"]).grid(row=1, column=0, sticky="w", pady=(2, 0))
        columns = ("from_to", "subject", "date", "security")
        tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        headings = {
            "from_to": "Nguoi gui" if folder == "inbox" else "Nguoi nhan",
            "subject": "Tieu de",
            "date": "Thoi gian",
            "security": "Bao mat",
        }
        widths = {"from_to": 230, "subject": 420, "date": 210, "security": 220}
        for col in columns:
            tree.heading(col, text=headings[col])
            tree.column(col, width=widths[col], anchor="w")
        tree.tag_configure("SECURE", foreground=COLORS["success"])
        tree.tag_configure("WARNING", foreground=COLORS["warning"])
        tree.tag_configure("DANGEROUS", foreground=COLORS["danger"])
        tree.grid(row=1, column=0, sticky="nsew", padx=10, pady=(6, 10))
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        scroll.grid(row=1, column=1, sticky="ns", pady=(6, 10))
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
            self._update_mail_stats(folder)
            self._append_log(f"Loaded {len(messages)} {folder} message(s)")

        self._run_task(f"Refresh {folder}", action, done)

    def _build_mail_stats(self, parent: tk.Widget, folder: str):
        self._mail_stat_labels = {}
        for i, (key, title, tone) in enumerate((
            ("total", "Total", "info"),
            ("secure", "Secure", "success"),
            ("warning", "Warning", "warning"),
            ("dangerous", "Dangerous", "danger"),
        )):
            card = RoundedFrame(parent, fill=COLORS["surface_2"], border=COLORS["border"], radius=10)
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 10, 0))
            parent.grid_columnconfigure(i, weight=1)
            tk.Label(card, text=title, bg=COLORS["surface_2"], fg=COLORS["muted"],
                     font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=12, pady=(10, 0))
            value = tk.Label(card, text="0", bg=COLORS["surface_2"], fg=COLORS[tone],
                             font=("Segoe UI Semibold", 18))
            value.pack(anchor="w", padx=12, pady=(0, 10))
            self._mail_stat_labels[key] = value
        self._update_mail_stats(folder)

    def _update_mail_stats(self, folder: str):
        if not self._mail_stat_labels:
            return
        messages = self.state_data.inbox if folder == "inbox" else self.state_data.sent
        counts = {"total": len(messages), "secure": 0, "warning": 0, "dangerous": 0}
        for msg in messages:
            label, _reason = client_core.classify_security(msg)
            if label == "SECURE":
                counts["secure"] += 1
            elif label == "WARNING":
                counts["warning"] += 1
            elif label == "DANGEROUS":
                counts["dangerous"] += 1
        for key, value in counts.items():
            if key in self._mail_stat_labels:
                self._mail_stat_labels[key].configure(text=str(value))

    def _populate_mail_tree(self, tree: ttk.Treeview, folder: str, search: str, filter_name: str):
        messages = self.state_data.inbox if folder == "inbox" else self.state_data.sent
        query = search.lower().strip()
        tree.delete(*tree.get_children())
        inserted = 0
        for msg in messages:
            label, _reason = client_core.classify_security(msg)
            if not self._mail_matches_filter(msg, label, filter_name):
                continue
            haystack = " ".join(str(msg.get(k, "")) for k in ("sender", "to", "subject", "date", "body")).lower()
            if query and query not in haystack:
                continue
            from_to = msg.get("sender") if folder == "inbox" else (msg.get("to") or msg.get("recipient"))
            tree.insert("", "end", iid=str(msg["id"]), values=(
                from_to or "",
                msg.get("subject", ""),
                msg.get("date", ""),
                self._security_summary(msg, label),
            ), tags=(label,))
            inserted += 1
        if inserted == 0:
            tree.insert("", "end", iid="empty", values=(
                "No messages",
                "Try refresh, change filter, or compose a new secure mail.",
                "",
                "",
            ))

    def _security_summary(self, msg: dict[str, Any], label: str) -> str:
        signature = "signed" if msg.get("signature_valid") else "signature issue"
        dmarc = msg.get("dmarc_action") or "policy n/a"
        return f"{label} - {signature}, {dmarc}"

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
        try:
            msg_id = int(selected[0])
        except ValueError:
            return
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
        detail.title(f"{msg.get('subject', 'Message')} - {label}")
        detail.geometry("860x660")
        detail.minsize(760, 560)
        detail.transient(self)
        detail.configure(bg=COLORS["bg"])
        shell = tk.Frame(detail, bg=COLORS["bg"])
        shell.pack(fill="both", expand=True, padx=18, pady=18)
        shell.grid_columnconfigure(0, weight=1)
        shell.grid_rowconfigure(1, weight=1)

        top = tk.Frame(shell, bg=COLORS["surface"], highlightbackground=COLORS["border"], highlightthickness=1)
        top.grid(row=0, column=0, sticky="ew")
        top.grid_columnconfigure(0, weight=1)
        tk.Label(top, text=msg.get("subject", "(no subject)"), bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 18), wraplength=760, justify="left").grid(
            row=0, column=0, sticky="w", padx=18, pady=(16, 4)
        )
        meta = tk.Frame(top, bg=COLORS["surface"])
        meta.grid(row=1, column=0, sticky="ew", padx=18, pady=(4, 12))
        meta.grid_columnconfigure(1, weight=1)
        for row, (name, value) in enumerate((
            ("From", msg.get("sender", "")),
            ("To", msg.get("to") or msg.get("recipient", "")),
            ("Date", msg.get("date", "")),
        )):
            tk.Label(meta, text=name, bg=COLORS["surface"], fg=COLORS["subtle"], width=8,
                     anchor="w").grid(row=row, column=0, sticky="w", pady=2)
            tk.Label(meta, text=value, bg=COLORS["surface"], fg=COLORS["text"],
                     anchor="w", wraplength=680, justify="left").grid(row=row, column=1, sticky="ew", pady=2)

        chips = tk.Frame(top, bg=COLORS["surface"])
        chips.grid(row=2, column=0, sticky="ew", padx=18, pady=(0, 16))
        security_tone = "success" if label == "SECURE" else ("warning" if label == "WARNING" else "danger")
        self._pill(chips, label, security_tone).pack(side="left", padx=(0, 6))
        for chip in (
            f"SPF {msg.get('spf_result') or 'n/a'}",
            f"DKIM {msg.get('dkim_result') or 'n/a'}",
            f"DMARC {msg.get('dmarc_action') or 'n/a'}",
        ):
            self._pill(chips, chip, "gray").pack(side="left", padx=(0, 6))
        tk.Label(chips, text=reason, bg=COLORS["surface"], fg=COLORS["muted"],
                 wraplength=360, justify="left").pack(side="left", padx=(8, 0))

        body_shell = tk.Frame(shell, bg=COLORS["surface"], highlightbackground=COLORS["border"], highlightthickness=1)
        body_shell.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        body_shell.grid_columnconfigure(0, weight=1)
        body_shell.grid_rowconfigure(1, weight=1)
        if msg.get("error"):
            tk.Label(body_shell, text=msg.get("error"), bg="#2B1620", fg="#FDA4AF",
                     anchor="w", wraplength=780, justify="left", padx=12, pady=10).grid(
                row=0, column=0, sticky="ew", padx=12, pady=(12, 0)
            )
        else:
            tk.Label(body_shell, text="Message body", bg=COLORS["surface"], fg=COLORS["muted"]).grid(
                row=0, column=0, sticky="w", padx=12, pady=(12, 0)
            )
        body = tk.Text(
            body_shell,
            wrap="word",
            bg=COLORS["input"],
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            padx=16,
            pady=16,
            borderwidth=0,
            font=("Segoe UI", 10),
        )
        body.grid(row=1, column=0, sticky="nsew", padx=12, pady=12)
        body.insert("1.0", msg.get("error") or msg.get("body", ""))
        body.configure(state="disabled")

    # ------------------------------------------------------------------
    # Compose
    # ------------------------------------------------------------------
    def show_compose(self):
        if not self._require_key():
            return
        self._set_client_chrome(True)
        self._set_active_nav("compose")
        self._clear_main()
        self._compose_send_button = None
        self._compose_status_label = None
        self.operation_log = self._build_right_panel("Send Security Flow")
        self._page_title("New Message", f"From {self.state_data.email or ''} · end-to-end encrypted & signed")

        card = self._surface()
        card.grid(row=1, column=0, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(0, weight=1)
        inner = tk.Frame(card, bg=COLORS["surface"])
        inner.grid(row=0, column=0, sticky="nsew", padx=0, pady=0)
        inner.grid_columnconfigure(0, weight=1)
        inner.grid_rowconfigure(3, weight=1)

        # ---- Header ----
        head = tk.Frame(inner, bg=COLORS["surface"])
        head.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 14))
        head.grid_columnconfigure(0, weight=1)
        tk.Label(head, text="New Secure Message", bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 16)).grid(row=0, column=0, sticky="w")
        tk.Label(head, text="Recipient certs verified · S/MIME encrypted · DKIM signed",
                 bg=COLORS["surface"], fg=COLORS["muted"], font=("Segoe UI", 9)).grid(row=1, column=0, sticky="w", pady=(3, 0))
        self._compose_status_label = self._pill(head, "Ready", "gray")
        self._compose_status_label.grid(row=0, column=1, rowspan=2, sticky="e")

        tk.Frame(inner, bg=COLORS["border"], height=1).grid(row=1, column=0, sticky="ew")

        # ---- Form (inline label + entry) ----
        form = tk.Frame(inner, bg=COLORS["surface"])
        form.grid(row=2, column=0, sticky="ew", padx=24, pady=(16, 0))
        form.grid_columnconfigure(1, weight=1)

        # To
        tk.Label(form, text="To", bg=COLORS["surface"], fg=COLORS["muted"],
                 font=("Segoe UI Semibold", 9), width=9, anchor="w").grid(row=0, column=0, sticky="w", pady=(0, 8), padx=(0, 10))
        to_entry = ttk.Entry(form)
        to_entry.grid(row=0, column=1, sticky="ew", ipady=7, pady=(0, 8))

        tk.Frame(form, bg=COLORS["border"], height=1).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 8))

        # Subject
        tk.Label(form, text="Subject", bg=COLORS["surface"], fg=COLORS["muted"],
                 font=("Segoe UI Semibold", 9), width=9, anchor="w").grid(row=2, column=0, sticky="w", pady=(0, 4), padx=(0, 10))
        subject_entry = ttk.Entry(form)
        subject_entry.grid(row=2, column=1, sticky="ew", ipady=7, pady=(0, 4))

        # ---- Body editor ----
        editor = tk.Frame(inner, bg=COLORS["surface"])
        editor.grid(row=3, column=0, sticky="nsew", padx=24, pady=(14, 0))
        editor.grid_columnconfigure(0, weight=1)
        editor.grid_rowconfigure(1, weight=1)
        tk.Label(editor, text="Message", bg=COLORS["surface"], fg=COLORS["muted"],
                 font=("Segoe UI Semibold", 9)).grid(row=0, column=0, sticky="w", pady=(0, 6))
        body = tk.Text(
            editor,
            height=16,
            wrap="word",
            bg=COLORS["input"],
            fg=COLORS["text"],
            insertbackground=COLORS["primary"],
            padx=16,
            pady=16,
            borderwidth=0,
            font=("Segoe UI", 10),
            relief="flat",
        )
        body.grid(row=1, column=0, sticky="nsew")

        # ---- Action bar ----
        actions = tk.Frame(inner, bg=COLORS["surface_2"], highlightbackground=COLORS["border"], highlightthickness=1)
        actions.grid(row=4, column=0, sticky="ew", padx=0, pady=(14, 0))
        actions.grid_columnconfigure(1, weight=1)
        ttk.Button(actions, text="Preview Certificate",
                   command=lambda: self._preview_cert(to_entry.get().strip())).grid(row=0, column=0, padx=18, pady=12)
        tk.Label(actions, text="S/MIME · Service ticket · SPF/DKIM/DMARC",
                 bg=COLORS["surface_2"], fg=COLORS["muted"], font=("Segoe UI", 9)).grid(row=0, column=1, sticky="w")

        def clear_compose_and_open_inbox():
            with contextlib.suppress(tk.TclError):
                to_entry.delete(0, "end")
                subject_entry.delete(0, "end")
                body.delete("1.0", "end")
            self.show_inbox()

        send_button = ttk.Button(
            actions,
            text="Send Secure Mail",
            style="Primary.TButton",
            command=lambda: self._send_mail(
                to_entry.get().strip(),
                subject_entry.get().strip(),
                body.get("1.0", "end-1c"),
                clear_compose_and_open_inbox,
            ),
        )
        send_button.grid(row=0, column=2, padx=18, pady=12)
        self._compose_send_button = send_button
        if self._send_in_progress:
            self._set_compose_busy(True)

        for step in (
            "1. Fetch CA root cert & CRL from KDS",
            "2. Bulk lookup recipient certificate",
            "3. Verify chain + OCSP",
            "4. Sign body with sender private key (RSA-PSS)",
            "5. Encrypt body with CEK, wrap CEK with RSA-OAEP",
            "6. Fetch Service Ticket & SMTP STARTTLS-lite",
            "7. Mail Server signs DKIM, checks SPF/DKIM/DMARC, stores encrypted envelope",
        ):
            self._append_log(step)

    def _set_compose_busy(self, busy: bool, status: str | None = None):
        self._send_in_progress = busy
        button = self._compose_send_button
        if button is not None:
            try:
                if button.winfo_exists():
                    button.configure(
                        state="disabled" if busy else "normal",
                        text="Sending..." if busy else "Send Secure Mail",
                    )
            except tk.TclError:
                self._compose_send_button = None
        label = self._compose_status_label
        if label is not None:
            try:
                if label.winfo_exists():
                    if status is None:
                        status = "Sending" if busy else "Ready"
                    status_key = status.lower()
                    if busy:
                        tone = "info"
                    elif status_key.startswith("sent"):
                        tone = "success"
                    elif status_key.startswith("fail"):
                        tone = "danger"
                    else:
                        tone = "gray"
                    self._set_pill(label, status, tone)
            except tk.TclError:
                self._compose_status_label = None

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
            if self.mode == "client":
                messagebox.showinfo(
                    "Recipient certificate",
                    "\n".join((
                        f"Subject: {cert.subject.rfc4514_string()}",
                        f"Serial: {hex(cert.serial_number)}",
                        f"Valid until: {cert.not_valid_after_utc}",
                    )),
                )

        self._run_task("Preview recipient cert", action, done)

    def _send_mail(self, to_text: str, subject: str, body: str, on_sent: Callable[[], None] | None = None):
        if self._send_in_progress:
            self._set_compose_busy(True, "Sending")
            return
        if not self.state_data.ctx:
            messagebox.showwarning("SecureMail", "Ban can login truoc khi gui mail.")
            return
        recipients = [part.strip() for part in to_text.split(",") if part.strip()]
        if not recipients or not subject or not body.strip():
            messagebox.showwarning("SecureMail", "Nhap To, Subject va Body.")
            return
        self._set_compose_busy(True, "Sending")

        def action():
            return client_core.send_secure_email(
                self.state_data.ctx,
                recipients,
                subject,
                body,
            )

        def done(result: dict[str, Any]):
            self._set_compose_busy(False, "Sent")
            self._append_log(f"Envelope={result.get('envelope_len')} bytes; sender_copy={result.get('sender_copy_len')} bytes")
            for rcpt, resp in result.get("results", []):
                self._append_log(f"{rcpt}: ok={resp.get('ok')} dmarc={resp.get('dmarc_action')} id={resp.get('message_id')}")
            if on_sent:
                on_sent()
            else:
                self.show_inbox()
            messagebox.showinfo("SecureMail", "Email da gui thanh cong.")

        self._run_task("Send secure mail", action, done)

    # ------------------------------------------------------------------
    # Security / Recovery
    # ------------------------------------------------------------------
    def show_security(self):
        if not self._require_login():
            return
        self._set_client_chrome(True)
        self._set_active_nav("security")
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
        email_var = tk.StringVar(value=self.state_data.email or "")
        self._field_with_var(cert_inner, "Email", email_var)
        ttk.Button(cert_inner, text="Inspect local cert/key", style="Primary.TButton",
                   command=lambda: self._inspect_identity(email_var.get().strip())).pack(anchor="w", pady=12)

        recovery_card = self._surface(grid)
        recovery_card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        recovery_inner = tk.Frame(recovery_card, bg=COLORS["surface"])
        recovery_inner.pack(fill="both", expand=True, padx=18, pady=18)
        tk.Label(recovery_inner, text="Key Recovery", bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 14)).pack(anchor="w")
        rec_email_var = tk.StringVar(value=self.state_data.email or "")
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
        lines = [
            f"Key file: {'FOUND' if key_path.exists() else 'MISSING'} - {key_path}",
            f"Cert file: {'FOUND' if cert_path.exists() else 'MISSING'} - {cert_path}",
            f"Salt file: {'FOUND' if salt_path.exists() else 'MISSING'} - {salt_path}",
        ]
        for line in lines:
            self._append_log(line)
        if cert_path.exists():
            try:
                cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
                cert_lines = [
                    f"Subject: {cert.subject.rfc4514_string()}",
                    f"Issuer: {cert.issuer.rfc4514_string()}",
                    f"Serial: {hex(cert.serial_number)}",
                    f"Valid: {cert.not_valid_before_utc} -> {cert.not_valid_after_utc}",
                ]
                lines.extend(cert_lines)
                for line in cert_lines:
                    self._append_log(line)
            except Exception as exc:
                line = f"Cannot parse cert: {exc}"
                lines.append(line)
                self._append_log(line)
        if not silent:
            messagebox.showinfo("SecureMail Identity", "\n".join(lines))

    def _recover_key(self, email: str, shares: list[int]):
        if len(shares) != 2:
            messagebox.showwarning("SecureMail", "Chon dung 2 share trong 3 share.")
            return
        try:
            client_core.require_recovery_authorized(self.state_data.ctx, email)
        except PermissionError as exc:
            messagebox.showwarning("SecureMail", str(exc))
            return

        def action():
            return client_core.recover_user_key(email, shares)

        def done(recovered: bytes):
            self._append_log(f"Recovered {len(recovered)} bytes for {email} using shares {shares}")
            messagebox.showinfo(
                "SecureMail",
                f"Key recovered successfully for {email}!\n\n"
                f"Please log out and log in again to activate your key.",
            )

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
                if name == "MAIL" and not mail_server_identity_exists():
                    skipped.append("MAIL (bootstrap required)")
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
                already_running = [item for item in skipped if "(" not in item]
                skipped_with_reason = [item for item in skipped if "(" in item]
                if already_running:
                    self._append_log(f"Already running: {', '.join(already_running)}")
                if skipped_with_reason:
                    self._append_log(f"Skipped: {', '.join(skipped_with_reason)}")
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
    # Account Management
    # ------------------------------------------------------------------
    def show_accounts(self):
        if not self._require_admin():
            return
        self._set_active_nav("accounts")
        self._clear_main()
        self.operation_log = self._build_right_panel("Account Admin")
        self._page_title("Accounts", "Tao tai khoan moi bang phien admin da dang nhap.")

        card = self._surface()
        card.grid(row=1, column=0, sticky="ew")
        card.grid_columnconfigure(0, weight=1)
        inner = tk.Frame(card, bg=COLORS["surface"])
        inner.grid(row=0, column=0, sticky="ew", padx=18, pady=18)
        inner.grid_columnconfigure(0, weight=1)

        tk.Label(inner, text="Create Account", bg=COLORS["surface"], fg=COLORS["text"],
                 font=("Segoe UI Semibold", 14)).grid(row=0, column=0, sticky="w")

        display_var = tk.StringVar()
        email_var = tk.StringVar()
        password_var = tk.StringVar()
        confirm_var = tk.StringVar()
        role_var = tk.StringVar(value="admin")
        roles = tuple(sorted(client_core.ALLOWED_ROLES))

        fields = (
            ("Display name", display_var, False),
            ("Email", email_var, False),
            ("Password", password_var, True),
            ("Confirm password", confirm_var, True),
        )
        for row_index, (label, var, masked) in enumerate(fields, start=1):
            tk.Label(inner, text=label, bg=COLORS["surface"], fg=COLORS["muted"]).grid(
                row=row_index * 2 - 1, column=0, sticky="w", pady=(12, 3)
            )
            ttk.Entry(inner, textvariable=var, show="*" if masked else "").grid(
                row=row_index * 2, column=0, sticky="ew", ipady=5
            )

        tk.Label(inner, text="Role", bg=COLORS["surface"], fg=COLORS["muted"]).grid(
            row=9, column=0, sticky="w", pady=(12, 3)
        )
        ttk.Combobox(inner, textvariable=role_var, values=roles, state="readonly").grid(
            row=10, column=0, sticky="ew", ipady=5
        )

        ttk.Button(
            inner,
            text="Create account",
            style="Primary.TButton",
            command=lambda: self._create_account(
                email_var.get().strip(),
                password_var.get(),
                confirm_var.get(),
                display_var.get().strip(),
                role_var.get(),
            ),
        ).grid(row=11, column=0, sticky="w", pady=(16, 0))

        self._append_log(f"Current admin={self.state_data.email}")
        self._append_log("Public Register chi tao role=user; role=admin phai tao tai day.")

    def _create_account(self, email: str, password: str, confirm_password: str, display_name: str, role: str):
        if not self._require_admin():
            return
        if not email or not password:
            messagebox.showwarning("SecureMail", "Nhap email va password de tao tai khoan.")
            return
        if password != confirm_password:
            messagebox.showwarning("SecureMail", "Password va confirm password khong khop.")
            return

        actor_ctx = self.state_data.ctx

        def action():
            return client_core.admin_register_account(actor_ctx, email, password, display_name, role)

        def done(result: dict[str, Any]):
            created_role = result.get("role", role)
            self._append_log(f"Created {email}; role={created_role}; serial={result.get('serial')}")
            messagebox.showinfo(
                "SecureMail",
                f"Created {email}\nRole: {created_role}\nSerial: {result.get('serial')}",
            )

        self._run_task("Create account", action, done)

    # ------------------------------------------------------------------
    # DKIM Domain Management
    # ------------------------------------------------------------------
    def show_dkim_domains(self):
        if not self._require_admin():
            return
        self._set_active_nav("dkim")
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
        self._set_active_nav("monitor")
        self._clear_main()
        self.operation_log = self._build_right_panel("Monitor Detail")
        self._page_title("Monitor Dashboard", "Service health, audit trail, security alerts and operational metrics.")
        self.main.grid_rowconfigure(1, weight=0)
        self.main.grid_rowconfigure(2, weight=0)
        self.main.grid_rowconfigure(3, weight=1)

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
        ttk.Button(actions, text="Detail panel",
                   command=self._toggle_detail_panel).pack(fill="x", pady=(6, 0))

        metric_bar = tk.Frame(self.main, bg=COLORS["bg"])
        metric_bar.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        self.monitor_metric_values: dict[str, tk.Label] = {}
        metric_defs = (
            ("total_mails", "Mail stored", "info"),
            ("dmarc_quarantine", "Quarantine", "warning"),
            ("revoked_certs", "Revoked certs", "danger"),
            ("active_principals", "Principals", "success"),
            ("revoked_tgts", "Revoked TGT", "primary"),
        )
        for i, (key, label, tone) in enumerate(metric_defs):
            card, value_label = self._metric_card(metric_bar, label, "0", tone)
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 8, 0))
            metric_bar.grid_columnconfigure(i, weight=1)
            self.monitor_metric_values[key] = value_label

        lower = tk.Frame(self.main, bg=COLORS["bg"])
        lower.grid(row=3, column=0, sticky="nsew")
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
        self.alert_text = tk.Text(alerts_card, wrap="word", bg=COLORS["input"], fg=COLORS["text"], padx=12, pady=12,
                                  insertbackground=COLORS["text"], borderwidth=0, font=("Consolas", 9))
        self.alert_text.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self._refresh_monitor_data()

    def _metric_card(self, parent: tk.Widget, title: str, value: str, tone: str) -> tuple[tk.Frame, tk.Label]:
        card = RoundedFrame(parent, fill=COLORS["surface_2"], border=COLORS["border"], radius=10)
        tk.Label(card, text=title, bg=COLORS["surface_2"], fg=COLORS["muted"],
                 font=("Segoe UI Semibold", 8)).pack(anchor="w", padx=12, pady=(10, 1))
        value_label = tk.Label(card, text=value, bg=COLORS["surface_2"], fg=COLORS.get(tone, COLORS["text"]),
                               font=("Segoe UI Semibold", 15))
        value_label.pack(anchor="w", padx=12, pady=(0, 10))
        return card, value_label

    def refresh_services(self):
        def action():
            return {name: is_port_open(port) for name, port in SERVICE_PORTS.items()}

        def done(statuses: dict[str, bool]):
            self.state_data.services = statuses
            for name, ok in statuses.items():
                if name in self._service_labels:
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
            self._populate_metric_cards(data["metrics"])
            self._populate_logs(data["logs"])
            self._populate_alerts(data["logs"], data["metrics"])

        self._run_task("Load monitoring data", action, done)

    def _populate_metric_cards(self, metrics: dict[str, Any]):
        values = getattr(self, "monitor_metric_values", {})
        if not values:
            return
        if metrics.get("error"):
            for key, label in values.items():
                label.configure(text="ERR", fg=COLORS["danger"])
            return
        for key, label in values.items():
            label.configure(text=str(metrics.get(key, 0)))

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
        self._show_detail_panel()
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
        self._set_active_nav("scenario")
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
            else:
                lines = [line for line in output.splitlines() if line.strip()]
                for line in lines[-8:]:
                    self._append_log(line[:260])
            passed = code == 0 and ("[FAIL]" not in output)
            status_text = "PASS" if passed else "CHECK"
            if cmd in getattr(self, "scenario_rows", {}):
                self._set_pill(self.scenario_rows[cmd], status_text, "success" if passed else "warning")
                self.state_data.scenario_status[cmd] = status_text
            self._append_log(f"Scenario {cmd} exit_code={code}; status={status_text}")
            self._append_log(explain_scenario(cmd, output))
            if cmd == "bootstrap" and code == 0:
                self.refresh_services()
                self._append_log("Bootstrap completed; admin identity is ready.")
                messagebox.showinfo(
                    "SecureMail",
                    "Bootstrap/repair done.\nUse your assigned admin account to open Monitor.",
                )

        self._run_task(f"Run scenario {cmd}", action, done)


def friendly_error(exc: BaseException) -> str:
    text = str(exc)
    lower = text.lower()
    if isinstance(exc, FileNotFoundError):
        if "share" in lower and "not found in database" in lower:
            return f"Escrow share not found: {text}. Re-run Bootstrap to create recovery shares for existing users."
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
    if "incorrect password" in lower or "wrong password" in lower:
        return "Sai email/password hoac local key khong khop. Vui long kiem tra thong tin dang nhap."
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


def mail_server_identity_exists() -> bool:
    return (
        (PROJECT_ROOT / "data/server/mail_key.pem").exists()
        and (PROJECT_ROOT / "data/server/mail_cert.pem").exists()
    )


def is_valid_email(email: str) -> bool:
    if not email or email.count("@") != 1:
        return False
    local, domain = email.split("@", 1)
    if not local or not domain or any(ch.isspace() for ch in email):
        return False
    return "." in domain and not domain.startswith(".") and not domain.endswith(".")


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


def _parse_gui_args(argv: list[str] | None) -> str:
    parser = argparse.ArgumentParser(description="SecureMail Tkinter GUI")
    parser.add_argument(
        "mode",
        nargs="?",
        choices=sorted(APP_MODES),
        help="GUI mode to open: client, monitor, or all",
    )
    parser.add_argument(
        "--mode",
        dest="mode_option",
        choices=sorted(APP_MODES),
        help="GUI mode to open: client, monitor, or all",
    )
    args = parser.parse_args(argv)
    return args.mode_option or args.mode or "client"


def launch(mode: str = "client"):
    os.chdir(PROJECT_ROOT)
    app = SecureMailApp(mode=mode)
    app.mainloop()


def main(argv: list[str] | None = None):
    launch(_parse_gui_args(argv))


if __name__ == "__main__":
    main()
