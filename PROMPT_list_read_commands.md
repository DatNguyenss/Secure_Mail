# AI Prompt: Add Inbox Listing with Security Classification and Detailed Message View to Secure Mail CLI

## Context

You are modifying the client-side code of the `Secure_Mail` project — an academic demonstration of applied cryptography concepts (S/MIME, Kerberos, SPF, DKIM, DMARC). The project uses Python and runs all services locally.

The client already supports a **stateful session** (login persisted to `data/active_session.json`) and an **interactive REPL shell** (using Python's `cmd.Cmd`). The current `fetch` command dumps all inbox messages at once, including full bodies. This is unwieldy and provides no quick security overview.

### Key files:
- `securemail/client_core.py` — core logic (login, send, fetch, session management)
- `securemail/main_client.py` — CLI entry point + interactive REPL shell
- `securemail/network/pop3_client.py` — POP3-lite client (`list()`, `retr(id)`, `quit()`)
- `securemail/network/pop3_server.py` — POP3-lite server (returns `id, sender, received_at, dmarc_action, spf_result, dkim_result` on LIST; full envelope on RETR)
- `securemail/mail/smime_handler.py` — S/MIME envelope open (`open_envelope()` returns `body, signer_subject, signature_valid`)
- `securemail/policy/dmarc_engine.py` — DMARC decision: `accept`, `quarantine`, `reject`
- `CHANGELOG.md` — all changes must be logged here

### Available security fields per message (returned by `fetch_inbox()`):
| Field | Type | Source |
|-------|------|--------|
| `signature_valid` | bool | S/MIME verification (client-side) |
| `dmarc_action` | str | `"accept"`, `"quarantine"`, or `"reject"` (server-side) |
| `spf_result` | str | `"pass"` or `"fail"` (server-side) |
| `dkim_result` | str | `"pass"`, `"fail"`, `"none"`, or `"error:..."` (server-side) |
| `error` | str | Decryption/verification error message (if any) |
| `signer_subject` | str | X.509 subject of the signing certificate |

Each message has a unique integer `id` field from the POP3 server's database.

---

## Objective

Implement the following features:

---

### Task 1: Security Classification Function

**File:** `securemail/client_core.py`
**Location:** After the existing `fetch_inbox()` function (around line 314)

**Add function:**
```python
def classify_security(msg: dict) -> tuple[str, str]:
```

**Logic:**
1. If `msg["error"]` exists → return `("DANGEROUS", "Decryption/verification error: {error}")`
2. If `msg["signature_valid"]` is `False` → return `("DANGEROUS", "S/MIME signature is INVALID")`
3. If `dmarc_action == "reject"` → return `("DANGEROUS", "DMARC policy: reject")`
4. Collect issues: `dmarc_action == "quarantine"`, `spf_result == "fail"`, `dkim_result == "fail"` or anomalous value
5. If any issues → return `("WARNING", "; ".join(issues))`
6. Otherwise → return `("SECURE", "Signature valid, SPF pass, DMARC accept")`

---

### Task 2: Single Message Fetch Function

**File:** `securemail/client_core.py`
**Location:** After `classify_security()`

**Add function:**
```python
def fetch_message(ctx: dict, msg_id: int, host="127.0.0.1", port=1100) -> dict | None:
```

**Logic:**
1. Get service ticket via `get_service_ticket(ctx)`
2. Connect to POP3, authenticate, call `cli.retr(msg_id)`
3. If not found, return `None`
4. Decrypt with `smime_handler.open_envelope()`, return same dict structure as `fetch_inbox()` elements
5. On exception, return dict with `error` field and `signature_valid=False`
6. Always call `cli.quit()` before returning

---

### Task 3: ANSI Color Helpers

**File:** `securemail/main_client.py`
**Location:** After imports, before the existing `_print_inbox()` helper

**Add:**
- `_ansi_supported()` → detect if stdout is a TTY (respect `NO_COLOR` env var)
- Module-level `_USE_COLOR` flag
- Color functions: `green()`, `yellow()`, `red()`, `bold()`, `cyan()`, `dim()`
- `_security_badge(label)` → return colored emoji+text badge:
  - `"SECURE"` → green `"✅ SECURE"`
  - `"WARNING"` → yellow `"⚠️  WARNING"`
  - `"DANGEROUS"` → red `"🚫 DANGEROUS"`

---

### Task 4: Compact Inbox List Printer

**File:** `securemail/main_client.py`
**Location:** After the legacy `_print_inbox()` function

**Add function:**
```python
def _print_inbox_list(email: str, msgs: list[dict]):
```

**Behavior:**
- Print a bold header line: `═══ Inbox of <email> ═══`
- Print message count
- Print a table with columns: `ID`, `Status` (security badge), `From`, `Subject`
- Use Unicode box-drawing characters (`─`) for separator lines
- At the bottom, print a hint: `Use 'read <id>' to view message details.`

---

### Task 5: Detailed Message View Printer

**File:** `securemail/main_client.py`
**Location:** After `_print_inbox_list()`

**Add function:**
```python
def _print_message_detail(m: dict):
```

**Behavior:**
- Print bordered section with bold Unicode box-drawing (`══`, `──`)
- Show: Message ID, From, Subject, Date, Security badge + reason
- Show crypto details: Signature status, Signer, SPF, DKIM, DMARC
- Show body text (indented), or error message if decryption failed

---

### Task 6: Add `list` and `read` Commands to CLI Mode

**File:** `securemail/main_client.py`
**Function:** `cli_main()`

**Add two new `elif` branches:**

1. **`list`** command:
   - Load session (fail if none)
   - Call `client_core.fetch_inbox(ctx)`
   - Call `_print_inbox_list(ctx["email"], msgs)`

2. **`read`** command:
   - Load session (fail if none)
   - Parse `sys.argv[2]` as integer message ID (validate)
   - Call `client_core.fetch_message(ctx, msg_id)`
   - If `None`, print "not found"; else call `_print_message_detail(msg)`

**Update the module docstring** to include `list` and `read <id>` in the usage section.

---

### Task 7: Add `do_list` and `do_read` Commands to REPL Shell

**File:** `securemail/main_client.py`
**Class:** `SecureMailShell`

1. **Add instance variable** in `__init__()`:
   ```python
   self._cached_msgs: dict[int, dict] = {}
   ```

2. **Add `do_list(self, _line)`:**
   - Check login
   - Call `client_core.fetch_inbox(self._ctx)`
   - Update `self._cached_msgs = {m["id"]: m for m in msgs}`
   - Call `_print_inbox_list(self._ctx["email"], msgs)`

3. **Add `do_read(self, line)`:**
   - Check login
   - Parse message ID from `line`
   - Try `self._cached_msgs.get(msg_id)` first (cache hit)
   - If cache miss, call `client_core.fetch_message(self._ctx, msg_id)`
   - Call `_print_message_detail(msg)` or print "not found"

---

### Task 8: Update CHANGELOG.md

**File:** `CHANGELOG.md` (project root)

Add a new version section documenting:
- `classify_security()` function and its 3-tier classification
- `fetch_message()` for single-message retrieval
- `list` command (compact table with security badges)
- `read <id>` command (detailed view)
- ANSI color support
- REPL message caching
- Legacy `fetch` command preserved for backward compatibility

---

## Constraints
- Do NOT modify server-side files (POP3 server, SMTP server, etc.)
- Keep the existing `fetch` command working (backward compatibility)
- All terminal colors must degrade gracefully (check `NO_COLOR`, non-TTY)
- Use only Python standard library (no external dependencies for the CLI)
- ALL changes must be recorded in `CHANGELOG.md`
