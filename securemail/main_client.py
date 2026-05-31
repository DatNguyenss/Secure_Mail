"""CLI cho Mail Client — hỗ trợ phiên đăng nhập (stateful session).

Chế độ 1 — Stateful CLI (lệnh đơn, lưu phiên vào file):
  python -m securemail.main_client register <email> <password> [<display>]
  python -m securemail.main_client login <email> <password>
  python -m securemail.main_client logout
  python -m securemail.main_client send <to> <subject>
  python -m securemail.main_client fetch
  python -m securemail.main_client list
  python -m securemail.main_client read <id>
  python -m securemail.main_client recover [<share1> <share2>]
  python -m securemail.main_client status

Chế độ 2 — Interactive Shell (REPL, phiên trong bộ nhớ):
  python -m securemail.main_client              # khởi chạy shell tương tác
"""
import cmd
import os
import sys

from securemail import client_core


# ======================================================================
# ANSI color helpers (degrade gracefully on dumb terminals)
# ======================================================================
def _ansi_supported() -> bool:
    """Return True when stdout probably supports ANSI escape codes."""
    if os.environ.get("NO_COLOR"):
        return False
    if hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
        return True
    return False


_USE_COLOR = _ansi_supported()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOR else text


def green(t: str) -> str: return _c("32", t)
def yellow(t: str) -> str: return _c("33", t)
def red(t: str) -> str: return _c("31", t)
def bold(t: str) -> str: return _c("1", t)
def cyan(t: str) -> str: return _c("36", t)
def dim(t: str) -> str: return _c("2", t)


def _security_badge(label: str) -> str:
    """Return a colored badge string for a security classification."""
    if label == "SECURE":
        return green("✅ SECURE")
    elif label == "WARNING":
        return yellow("⚠️  WARNING")
    else:  # DANGEROUS
        return red("🚫 DANGEROUS")


# ======================================================================
# Helper: print inbox messages (legacy, full dump)
# ======================================================================
def _print_inbox(email: str, msgs: list[dict]):
    print(f"=== Inbox of {email} — {len(msgs)} message(s) ===")
    for m in msgs:
        print(f"\n--- id={m['id']} from={m['sender']} ---")
        print(f"  Subject: {m.get('subject', '')}")
        print(f"  Date: {m.get('date', '')}")
        print(f"  Signature: {'VALID' if m.get('signature_valid') else 'INVALID'}")
        if m.get("signer_subject"):
            print(f"  Signer: {m['signer_subject']}")
        print(
            f"  DMARC: {m.get('dmarc_action')} | "
            f"SPF: {m.get('spf_result')} | "
            f"DKIM: {m.get('dkim_result')}"
        )
        if m.get("error"):
            print(f"  ERROR: {m['error']}")
        else:
            print(f"  --- Body ---")
            print(m.get("body", ""))


# ======================================================================
# Helper: compact inbox listing with security status
# ======================================================================
def _print_inbox_list(email: str, msgs: list[dict]):
    """Display a compact table of messages with security badges."""
    print(f"\n{bold('═══ Inbox of ' + email + ' ═══')}")
    print(f"  {len(msgs)} message(s)\n")
    if not msgs:
        print(dim("  (empty inbox)"))
        return
    # Header
    print(f"  {bold('ID'):>6}  {bold('Status'):<18}  {bold('Date'):<25}  {bold('From'):<28}  {bold('Subject')}")
    print(f"  {'─' * 6}  {'─' * 18}  {'─' * 25}  {'─' * 28}  {'─' * 30}")
    for m in msgs:
        label, _reason = client_core.classify_security(m)
        badge = _security_badge(label)
        date_str = m.get("date", "")[:25]
        sender = m.get("sender", "?")[:28]
        subj = m.get("subject", "(no subject)")[:40]
        mid = str(m["id"])
        print(f"  {mid:>6}  {badge:<18}  {date_str:<25}  {sender:<28}  {subj}")
    print(f"\n  {dim('Use')} {bold('read <id>')} {dim('to view message details.')}")


# ======================================================================
# Helper: detailed single-message view
# ======================================================================
def _print_message_detail(m: dict):
    """Print the full details of a single message."""
    label, reason = client_core.classify_security(m)
    badge = _security_badge(label)

    print(f"\n{bold('══════════════════════════════════════════════════')}")
    print(f"  {bold('Message ID:')}   {m['id']}")
    print(f"  {bold('From:')}         {m.get('sender', '?')}")
    print(f"  {bold('Subject:')}      {m.get('subject', '(no subject)')}")
    print(f"  {bold('Date:')}         {m.get('date', '?')}")
    print(f"  {bold('Security:')}     {badge}")
    print(f"  {bold('Reason:')}       {reason}")
    print(f"{bold('──────────────────────────────────────────────────')}")
    print(f"  {bold('Signature:')}    {'VALID' if m.get('signature_valid') else red('INVALID')}")
    if m.get("signer_subject"):
        print(f"  {bold('Signer:')}       {m['signer_subject']}")
    print(f"  {bold('SPF:')}          {m.get('spf_result', 'N/A')}")
    print(f"  {bold('DKIM:')}         {m.get('dkim_result', 'N/A')}")
    print(f"  {bold('DMARC:')}        {m.get('dmarc_action', 'N/A')}")
    print(f"{bold('──────────────────────────────────────────────────')}")
    if m.get("error"):
        print(f"  {red('ERROR:')} {m['error']}")
    else:
        print(f"  {bold('Body:')}")
        print()
        for line in m.get("body", "").splitlines():
            print(f"    {line}")
    print(f"\n{bold('══════════════════════════════════════════════════')}")


# ======================================================================
# Stateful CLI — one-shot commands that read/write session file
# ======================================================================
def cli_main():
    """Dispatch a single CLI command, using the session file for auth."""
    cmd_name = sys.argv[1]

    # --- register (unchanged, no session needed) ---
    if cmd_name == "register":
        email, password = sys.argv[2], sys.argv[3]
        display = sys.argv[4] if len(sys.argv) > 4 else ""
        client_core.register(email, password, display)

    # --- login: authenticate + save session ---
    elif cmd_name == "login":
        email, password = sys.argv[2], sys.argv[3]
        ctx = client_core.login(email, password)
        client_core.save_session(ctx)
        print(f"Logged in as {email}. Session saved.")
        print(f"  TGT length={len(ctx['tgt'])}")

    # --- logout: clear session ---
    elif cmd_name == "logout":
        client_core.clear_session()
        print("Logged out. Session cleared.")

    # --- send: use saved session ---
    elif cmd_name == "send":
        ctx = client_core.load_session()
        if ctx is None:
            print("Error: No active session. Please login first.")
            print("  python -m securemail.main_client login <email> <password>")
            sys.exit(1)
        to_addr = sys.argv[2]
        subject = sys.argv[3] if len(sys.argv) > 3 else "(no subject)"
        print("Enter email body (end with Ctrl-Z on Windows / Ctrl-D on Unix):")
        body = sys.stdin.read()
        r = client_core.send_secure_email(ctx, [to_addr], subject, body)
        print(f"Sent: {r['envelope_len']} bytes envelope")
        for rcpt, resp in r["results"]:
            print(f"  {rcpt}: {resp}")

    # --- fetch: use saved session (legacy, full dump) ---
    elif cmd_name == "fetch":
        ctx = client_core.load_session()
        if ctx is None:
            print("Error: No active session. Please login first.")
            sys.exit(1)
        msgs = client_core.fetch_inbox(ctx)
        _print_inbox(ctx["email"], msgs)

    # --- list: compact inbox listing with security status ---
    elif cmd_name == "list":
        ctx = client_core.load_session()
        if ctx is None:
            print("Error: No active session. Please login first.")
            sys.exit(1)
        msgs = client_core.fetch_inbox(ctx)
        _print_inbox_list(ctx["email"], msgs)

    # --- read <id>: detailed single-message view ---
    elif cmd_name == "read":
        ctx = client_core.load_session()
        if ctx is None:
            print("Error: No active session. Please login first.")
            sys.exit(1)
        if len(sys.argv) < 3:
            print("Usage: read <id>")
            sys.exit(1)
        try:
            msg_id = int(sys.argv[2])
        except ValueError:
            print(f"Error: '{sys.argv[2]}' is not a valid message ID (must be integer).")
            sys.exit(1)
        msg = client_core.fetch_message(ctx, msg_id)
        if msg is None:
            print(f"Message with id={msg_id} not found.")
        else:
            _print_message_detail(msg)

    # --- recover: key escrow recovery ---
    elif cmd_name == "recover":
        ctx = client_core.load_session()
        if ctx is None:
            print("Error: No active session. Please login first.")
            sys.exit(1)
        shares = None
        if len(sys.argv) >= 4:
            shares = [int(x) for x in sys.argv[2:4]]
        client_core.recover_user_key(ctx["email"], shares)

    # --- status: show who is logged in ---
    elif cmd_name == "status":
        ctx = client_core.load_session()
        if ctx is None:
            print("No active session.")
        else:
            print(f"Logged in as: {ctx['email']}")
            print(f"  TGT length: {len(ctx['tgt'])}")

    else:
        print(f"Unknown command: {cmd_name}")
        print(__doc__)


# ======================================================================
# Interactive Shell (REPL) — session in memory
# ======================================================================
class SecureMailShell(cmd.Cmd):
    """Interactive command shell for Secure Mail."""

    intro = (
        "\n"
        "╔══════════════════════════════════════════════════╗\n"
        "║       Secure Mail — Interactive Shell           ║\n"
        "║  Type 'help' for available commands.            ║\n"
        "╚══════════════════════════════════════════════════╝\n"
    )
    prompt = "securemail> "

    def __init__(self):
        super().__init__()
        self._ctx = None  # in-memory session context
        self._cached_msgs: dict[int, dict] = {}  # cache from last 'list'

    # ------------------------------------------------------------------
    # login <email> <password>
    # ------------------------------------------------------------------
    def do_login(self, line: str):
        """Login: login <email> <password>"""
        parts = line.split()
        if len(parts) < 2:
            print("Usage: login <email> <password>")
            return
        email, password = parts[0], parts[1]
        try:
            self._ctx = client_core.login(email, password)
            self.prompt = f"{email}> "
            print(f"Logged in as {email}.")
            print(f"  TGT length={len(self._ctx['tgt'])}")
        except Exception as exc:
            print(f"Login failed: {exc}")

    # ------------------------------------------------------------------
    # logout
    # ------------------------------------------------------------------
    def do_logout(self, _line: str):
        """Logout current user."""
        if self._ctx is None:
            print("No user logged in.")
            return
        email = self._ctx["email"]
        self._ctx = None
        self.prompt = "securemail> "
        print(f"Logged out from {email}.")

    # ------------------------------------------------------------------
    # send <to> <subject>
    # ------------------------------------------------------------------
    def do_send(self, line: str):
        """Send email: send <to> <subject>"""
        if self._ctx is None:
            print("Error: Not logged in. Use 'login <email> <password>' first.")
            return
        parts = line.split(maxsplit=1)
        if len(parts) < 1:
            print("Usage: send <to> [<subject>]")
            return
        to_addr = parts[0]
        subject = parts[1] if len(parts) > 1 else "(no subject)"
        print("Enter body (blank line to finish):")
        lines = []
        while True:
            try:
                l = input()
            except EOFError:
                break
            if l == "":
                break
            lines.append(l)
        body = "\n".join(lines)
        if not body.strip():
            print("Empty body — cancelled.")
            return
        try:
            r = client_core.send_secure_email(
                self._ctx, [to_addr], subject, body
            )
            print(f"Sent: {r['envelope_len']} bytes envelope")
            for rcpt, resp in r["results"]:
                print(f"  {rcpt}: {resp}")
        except Exception as exc:
            print(f"Send failed: {exc}")

    # ------------------------------------------------------------------
    # fetch (legacy — full dump)
    # ------------------------------------------------------------------
    def do_fetch(self, _line: str):
        """Fetch and decrypt inbox messages (legacy full dump)."""
        if self._ctx is None:
            print("Error: Not logged in. Use 'login <email> <password>' first.")
            return
        try:
            msgs = client_core.fetch_inbox(self._ctx)
            _print_inbox(self._ctx["email"], msgs)
        except Exception as exc:
            print(f"Fetch failed: {exc}")

    # ------------------------------------------------------------------
    # list — compact inbox with security badges
    # ------------------------------------------------------------------
    def do_list(self, _line: str):
        """List inbox messages with security status (compact view)."""
        if self._ctx is None:
            print("Error: Not logged in. Use 'login <email> <password>' first.")
            return
        try:
            msgs = client_core.fetch_inbox(self._ctx)
            # cache for subsequent 'read' without round-trip
            self._cached_msgs = {m["id"]: m for m in msgs}
            _print_inbox_list(self._ctx["email"], msgs)
        except Exception as exc:
            print(f"List failed: {exc}")

    # ------------------------------------------------------------------
    # read <id> — detailed single-message view
    # ------------------------------------------------------------------
    def do_read(self, line: str):
        """Read a specific message: read <id>"""
        if self._ctx is None:
            print("Error: Not logged in. Use 'login <email> <password>' first.")
            return
        parts = line.strip().split()
        if not parts:
            print("Usage: read <id>")
            return
        try:
            msg_id = int(parts[0])
        except ValueError:
            print(f"Error: '{parts[0]}' is not a valid message ID.")
            return

        # Try cache first, fall back to POP3 fetch
        msg = self._cached_msgs.get(msg_id)
        if msg is None:
            try:
                msg = client_core.fetch_message(self._ctx, msg_id)
            except Exception as exc:
                print(f"Read failed: {exc}")
                return
        if msg is None:
            print(f"Message with id={msg_id} not found.")
            return
        _print_message_detail(msg)

    # ------------------------------------------------------------------
    # recover [share1 share2]
    # ------------------------------------------------------------------
    def do_recover(self, line: str):
        """Recover escrowed private key: recover [<share1> <share2>]"""
        if self._ctx is None:
            print("Error: Not logged in. Use 'login <email> <password>' first.")
            return
        parts = line.split()
        shares = None
        if len(parts) >= 2:
            shares = [int(x) for x in parts[:2]]
        try:
            client_core.recover_user_key(self._ctx["email"], shares)
            print("Key recovered successfully.")
        except Exception as exc:
            print(f"Recovery failed: {exc}")

    # ------------------------------------------------------------------
    # status
    # ------------------------------------------------------------------
    def do_status(self, _line: str):
        """Show current session info."""
        if self._ctx is None:
            print("No user logged in.")
        else:
            print(f"Logged in as: {self._ctx['email']}")
            print(f"  TGT length: {len(self._ctx['tgt'])}")
            print(f"  Key size: RSA-{self._ctx['privkey'].key_size}")

    # ------------------------------------------------------------------
    # exit / quit
    # ------------------------------------------------------------------
    def do_exit(self, _line: str):
        """Exit the shell."""
        print("Bye!")
        return True

    do_quit = do_exit

    # Handle Ctrl-D
    def do_EOF(self, _line: str):
        """Exit on Ctrl-D."""
        print()
        return self.do_exit("")

    # Don't repeat last command on empty input
    def emptyline(self):
        pass


# ======================================================================
# Entry point
# ======================================================================
def main():
    if len(sys.argv) < 2:
        # No arguments → launch interactive shell (REPL)
        SecureMailShell().cmdloop()
        return
    cli_main()


if __name__ == "__main__":
    main()
