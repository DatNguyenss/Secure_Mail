"""SMTP-lite server — cổng 2525.

Protocol (JSON-over-TCP với length framing, KHÔNG dùng ASCII SMTP thật):
  C → S: {op: "EHLO", domain}
  S → C: {ok, starttls: true, auth: "kerberos"}
  C → S: {op: "STARTTLS"}   ← optional, nếu có sẽ wrap tất cả frame sau trong AES-GCM
    (TLS-lite handshake)
  C → S: {op: "AUTH", ticket_v, authenticator}
  S → C: {ok, mutual_b64}   ← E(Kc,v, [TS5+1]) — mutual auth response (A7)
  C → S: {op: "MAIL", from, to, size}
  S → C: {ok}
  C → S: {op: "DATA", envelope_b64, dkim_sig (optional), headers}
  S → C: {ok, accepted: true, message_id, spf_result, dmarc_action}
  C → S: {op: "QUIT"}
"""
import base64
import datetime as dt
import json
import re
import socket
import threading
import time
import traceback
import uuid
from pathlib import Path

from securemail.network.json_framing import send_json, recv_json, b64, unb64
from securemail.network import tls_lite
from securemail.crypto.aes_handler import aes_gcm_encrypt, aes_gcm_decrypt
from securemail.ticket_service import ticket as ticket_mod
from securemail.ticket_service import authenticator as auth_mod
from securemail.ticket_service import ts_client
from securemail.ticket_service.as_tgs_server import MAIL_SRV_NAME
from securemail.auth import access_control
from securemail.mail import dkim_signer, mime_lite
from securemail.policy import spf_checker, dmarc_engine
from securemail.db_conn import get_conn


SMTP_HOST = "127.0.0.1"
SMTP_PORT = 2525
DOMAIN = "mail.local"
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

SRV_REPLAY = auth_mod.ReplayCache(window_seconds=300)


_MAILBOX_FOLDER_READY = False


def _mta_dkim_key_path(domain: str) -> Path | None:
    normalized = domain.strip().lower()
    if not DOMAIN_RE.match(normalized):
        return None
    return Path(f"data/server/mta_{normalized}_key.pem")


def _ensure_mailbox_folder():
    """Add the Sent/Inbox folder column for existing SQL Server mailstores."""
    global _MAILBOX_FOLDER_READY
    if _MAILBOX_FOLDER_READY:
        return
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("""
    IF NOT EXISTS (
        SELECT 1
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = 'mail'
          AND TABLE_NAME = 'mailbox'
          AND COLUMN_NAME = 'folder'
    )
    BEGIN
        ALTER TABLE mail.mailbox
        ADD folder NVARCHAR(20) NOT NULL
            CONSTRAINT DF_mailbox_folder DEFAULT 'inbox'
    END
    """)
    try:
        cursor.execute("""
        IF NOT EXISTS (
            SELECT 1 FROM sys.indexes
            WHERE name = 'idx_mailbox_recipient_folder'
              AND object_id = OBJECT_ID('mail.mailbox')
        )
        BEGIN
            CREATE INDEX idx_mailbox_recipient_folder
            ON mail.mailbox(recipient, folder, fetched)
        END
        """)
        conn.commit()
    except pymssql.exceptions.OperationalError as e:
        # Ignore if index was concurrently created by another service
        if "already exists" not in str(e):
            raise
    conn.close()
    _MAILBOX_FOLDER_READY = True


def log_event(event: str, details: str = ""):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO mail.server_log(ts, event, details) VALUES (%s, %s, %s)",
        (dt.datetime.now(dt.timezone.utc), event, details),
    )
    conn.close()


def store_mail(recipient: str, sender: str, envelope: bytes, headers: dict,
               dmarc_action: str, spf_result: str, dkim_result: str,
               folder: str = "inbox") -> int:
    _ensure_mailbox_folder()
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO mail.mailbox(recipient, sender, received_at, envelope, headers_json, "
        "dmarc_action, spf_result, dkim_result, folder, fetched) "
        "OUTPUT INSERTED.id "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 0)",
        (recipient, sender, dt.datetime.now(dt.timezone.utc),
         bytearray(envelope), json.dumps(headers), dmarc_action, spf_result,
         dkim_result, folder),
    )
    row = cursor.fetchone()
    mid = row[0]
    conn.close()
    return mid


def _envelope_has_recipient(envelope: bytes, email: str) -> bool:
    try:
        env = json.loads(envelope.decode("utf-8"))
    except Exception:
        return False
    return any(r.get("email") == email for r in env.get("recipients", []))


def _handle_client(conn: socket.socket, addr):
    peer_ip = addr[0]
    framer = None  # set after STARTTLS
    auth_ctx = None  # {id_c, role, k_c_v}

    def send(obj):
        if framer:
            framer.send(obj)
        else:
            send_json(conn, obj)

    def recv():
        if framer:
            return framer.recv()
        return recv_json(conn)

    try:
        state = {"from": None, "to": None}
        while True:
            try:
                msg = recv()
            except ConnectionError:
                break
            op = msg.get("op")

            if op == "EHLO":
                send({"ok": True, "starttls": True, "auth": "kerberos",
                      "domain": DOMAIN, "hello": f"SecureMail-MTA@{DOMAIN}"})

            elif op == "STARTTLS":
                # Load server cert (cert của domain mail, đăng ký qua KDS)
                server_cert_pem = Path("data/server/mail_cert.pem").read_bytes()
                server_priv = _load_server_privkey()
                key = tls_lite.server_handshake(conn, server_cert_pem, server_priv)
                framer = tls_lite.SecureFramer(conn, key)
                log_event("STARTTLS", f"peer={peer_ip}")

            elif op == "AUTH":
                # Kerberos-lite service exchange
                kv = ts_client.get_service_key(MAIL_SRV_NAME)
                try:
                    tv = ticket_mod.open_ticket(kv, msg["ticket_v"])
                except Exception as e:
                    send({"ok": False, "error": f"bad ticket: {e}"})
                    log_event("AUTH_FAIL", f"peer={peer_ip} reason=bad_ticket error={e}")
                    continue
                if ticket_mod.is_expired(tv):
                    send({"ok": False, "error": "ticket expired"})
                    log_event("AUTH_FAIL", f"peer={peer_ip} reason=ticket_expired")
                    continue
                k_c_v = base64.b64decode(tv["session_key_b64"])
                try:
                    a = auth_mod.open_auth(k_c_v, msg["authenticator"])
                except Exception as e:
                    send({"ok": False, "error": f"bad authenticator: {e}"})
                    log_event("AUTH_FAIL", f"peer={peer_ip} reason=bad_authenticator error={e}")
                    continue
                if a["id_c"] != tv["id_c"]:
                    send({"ok": False, "error": "id_c mismatch"})
                    log_event("AUTH_FAIL", f"peer={peer_ip} reason=id_mismatch id_c_ticket={tv['id_c']} id_c_auth={a['id_c']}")
                    continue
                if not SRV_REPLAY.check_and_add(a["id_c"] + "@mail", a.get("nonce", ""), a["ts"]):
                    send({"ok": False, "error": "replay detected"})
                    log_event("REPLAY_REJECTED", a["id_c"])
                    continue
                # A7 — server mutual auth: E(K_c,v, TS5+1)
                resp = {"ts_plus_1": a["ts"] + 1}
                data = json.dumps(resp).encode("utf-8")
                nonce, ct = aes_gcm_encrypt(k_c_v, data, aad=b"mutual-v1")
                auth_ctx = {"id_c": a["id_c"], "role": tv["role"], "k_c_v": k_c_v}
                send({"ok": True, "mutual_b64": b64(nonce + ct), "role": tv["role"]})
                log_event("AUTH_OK", f"{a['id_c']} role={tv['role']}")

            elif op == "MAIL":
                if not auth_ctx:
                    send({"ok": False, "error": "not authenticated"})
                    continue
                if not access_control.allowed(auth_ctx["role"], "smtp.send"):
                    send({"ok": False, "error": "forbidden"})
                    log_event("SMTP_FORBIDDEN", f"user={auth_ctx['id_c']} action=smtp.send")
                    continue
                state["from"] = msg["from"]
                state["to"] = msg["to"]
                send({"ok": True})

            elif op == "DATA":
                if not auth_ctx or not state["from"]:
                    send({"ok": False, "error": "no MAIL/AUTH"})
                    continue

                envelope = unb64(msg["envelope_b64"])
                headers = msg.get("headers", {})
                sender_domain = state["from"].split("@", 1)[-1]

                # --- SPF check ---
                if spf_checker.domain_has_spf(sender_domain):
                    spf_pass = spf_checker.check(sender_domain, peer_ip)
                else:
                    spf_pass = True  # no SPF record → neutral
                spf_result = "pass" if spf_pass else "fail"

                # --- DKIM: MTA signs controlled domains, then verifies via KDS ---
                dkim_sig = msg.get("dkim_sig")
                mta_dkim = None
                if not dkim_sig:
                    try:
                        mta_priv_path = _mta_dkim_key_path(sender_domain)
                        if mta_priv_path and mta_priv_path.exists():
                            from securemail.crypto import rsa_handler as rh
                            mta_priv = rh.load_private_pem(mta_priv_path.read_bytes(), b"mta-domain-key")
                            dkim_sig = dkim_signer.sign(headers, envelope, sender_domain, "default", mta_priv)
                            mta_dkim = dkim_sig
                            log_event("MTA_DKIM_SIGNED", sender_domain)
                    except Exception as e:
                        log_event("MTA_DKIM_ERROR", str(e))

                dkim_pass = True
                dkim_result = "none"
                if dkim_sig:
                    try:
                        from securemail.kds import kds_client
                        dkim_cert = kds_client.get_cert(f"_dkim.{sender_domain}")
                        if dkim_cert:
                            dkim_pass = dkim_signer.verify(headers, envelope, dkim_sig, dkim_cert)
                            dkim_result = "pass" if dkim_pass else "fail"
                        else:
                            dkim_result = "no_key"
                            dkim_pass = False
                    except Exception as e:
                        dkim_result = f"error:{e}"
                        dkim_pass = False

                # --- DMARC ---
                policy = dmarc_engine.get_policy(sender_domain)
                action = dmarc_engine.decide(spf_pass, dkim_pass, policy)

                if action == "reject":
                    send({"ok": False, "error": "rejected by DMARC",
                          "spf_result": spf_result, "dkim_result": dkim_result,
                          "dmarc_action": action})
                    log_event("REJECT", f"{state['from']}→{state['to']} dmarc=reject")
                    continue

                # Store
                mid = store_mail(state["to"], state["from"], envelope, headers,
                                 action, spf_result, dkim_result, folder="inbox")
                sent_mid = None
                sender_copy_b64 = msg.get("sender_copy_envelope_b64")
                if sender_copy_b64:
                    sender_copy = unb64(sender_copy_b64)
                    if _envelope_has_recipient(sender_copy, state["from"]):
                        sent_mid = store_mail(
                            state["from"], state["from"], sender_copy, headers,
                            action, spf_result, dkim_result, folder="sent"
                        )
                        log_event("SENT_COPY", f"id={sent_mid} sender={state['from']} rcpt={state['to']}")
                    else:
                        log_event("SENT_COPY_REJECTED", f"sender={state['from']} reason=not_recipient")
                log_event("DELIVER", f"id={mid} {state['from']}→{state['to']} dmarc={action}")
                send({"ok": True, "accepted": True, "message_id": f"<{mid}@{DOMAIN}>",
                      "sent_copy_id": sent_mid,
                      "spf_result": spf_result, "dkim_result": dkim_result,
                      "dmarc_action": action, "mta_dkim": mta_dkim})
                state["from"] = None
                state["to"] = None

            elif op == "QUIT":
                send({"ok": True, "bye": True})
                break
            else:
                send({"ok": False, "error": f"unknown op {op}"})
    except Exception as e:
        traceback.print_exc()
        log_event("ERROR", str(e))
    finally:
        conn.close()


def _load_server_privkey():
    from securemail.crypto import rsa_handler
    return rsa_handler.load_private_pem(
        Path("data/server/mail_key.pem").read_bytes(), b"mail-srv-key")


def serve():
    _ensure_mailbox_folder()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((SMTP_HOST, SMTP_PORT))
    sock.listen(50)
    print(f"[SMTP] SMTP-lite on {SMTP_HOST}:{SMTP_PORT} domain={DOMAIN}")
    try:
        while True:
            c, a = sock.accept()
            threading.Thread(target=_handle_client, args=(c, a), daemon=True).start()
    finally:
        sock.close()


if __name__ == "__main__":
    serve()
