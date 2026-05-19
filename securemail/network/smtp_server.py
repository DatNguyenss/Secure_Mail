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
import socket
import sqlite3
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


SMTP_HOST = "127.0.0.1"
SMTP_PORT = 2525
DOMAIN = "mail.local"

MAIL_DIR = Path("data/mail")
MAIL_DB = MAIL_DIR / "mailstore.db"
SRV_REPLAY = auth_mod.ReplayCache(window_seconds=300)


def _ensure_db():
    MAIL_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(MAIL_DB)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS mailbox (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        recipient TEXT NOT NULL,
        sender TEXT,
        received_at TEXT,
        envelope BLOB,
        headers_json TEXT,
        dmarc_action TEXT,
        spf_result TEXT,
        dkim_result TEXT,
        fetched INTEGER DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_recipient ON mailbox(recipient, fetched);
    CREATE TABLE IF NOT EXISTS server_log (
        ts TEXT, event TEXT, details TEXT
    );
    """)
    conn.commit()
    conn.close()


def log_event(event: str, details: str = ""):
    _ensure_db()
    conn = sqlite3.connect(MAIL_DB)
    conn.execute("INSERT INTO server_log(ts, event, details) VALUES (?, ?, ?)",
                 (dt.datetime.now(dt.timezone.utc).isoformat(), event, details))
    conn.commit()
    conn.close()


def store_mail(recipient: str, sender: str, envelope: bytes, headers: dict,
               dmarc_action: str, spf_result: str, dkim_result: str) -> int:
    _ensure_db()
    conn = sqlite3.connect(MAIL_DB)
    cur = conn.execute(
        "INSERT INTO mailbox(recipient, sender, received_at, envelope, headers_json, "
        "dmarc_action, spf_result, dkim_result) VALUES (?,?,?,?,?,?,?,?)",
        (recipient, sender, dt.datetime.now(dt.timezone.utc).isoformat(),
         envelope, json.dumps(headers), dmarc_action, spf_result, dkim_result),
    )
    mid = cur.lastrowid
    conn.commit()
    conn.close()
    return mid


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

                # --- DKIM verify nếu có ---
                dkim_sig = msg.get("dkim_sig")
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

                # --- MTA adds its own DKIM-lite signature (A4) ---
                mta_dkim = None
                try:
                    from securemail.kds import kds_client
                    mta_priv_path = Path(f"data/server/mta_{DOMAIN}_key.pem")
                    if mta_priv_path.exists():
                        from securemail.crypto import rsa_handler as rh
                        mta_priv = rh.load_private_pem(mta_priv_path.read_bytes(), b"mta-domain-key")
                        mta_dkim = dkim_signer.sign(headers, envelope, DOMAIN, "default", mta_priv)
                        log_event("MTA_DKIM_SIGNED", sender_domain)
                except Exception as e:
                    log_event("MTA_DKIM_ERROR", str(e))

                if action == "reject":
                    send({"ok": False, "error": "rejected by DMARC",
                          "spf_result": spf_result, "dkim_result": dkim_result,
                          "dmarc_action": action})
                    log_event("REJECT", f"{state['from']}→{state['to']} dmarc=reject")
                    continue

                # Store
                mid = store_mail(state["to"], state["from"], envelope, headers,
                                 action, spf_result, dkim_result)
                log_event("DELIVER", f"id={mid} {state['from']}→{state['to']} dmarc={action}")
                send({"ok": True, "accepted": True, "message_id": f"<{mid}@{DOMAIN}>",
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
    _ensure_db()
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
