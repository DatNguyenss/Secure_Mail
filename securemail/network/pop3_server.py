"""POP3-lite — cổng 1100. Dùng Kerberos ticket để authenticate.

Protocol:
  C → S: {op: "HELO"}
  S → C: {ok, starttls: true}
  C → S: {op: "STARTTLS"} (optional)
  C → S: {op: "AUTH", ticket_v, authenticator}
  S → C: {ok, mutual_b64, role}
  C → S: {op: "LIST"}
  S → C: {ok, messages: [{id, sender, received_at, dmarc_action, ...}]}
  C → S: {op: "RETR", id}
  S → C: {ok, envelope_b64, headers, dmarc_action, ...}
  C → S: {op: "DELE", id}
  C → S: {op: "QUIT"}
"""
import base64
import json
import socket
import sqlite3
import threading
import traceback
from pathlib import Path

from securemail.network.json_framing import send_json, recv_json, b64, unb64
from securemail.network import tls_lite
from securemail.network.smtp_server import log_event
from securemail.crypto.aes_handler import aes_gcm_encrypt
from securemail.ticket_service import ticket as ticket_mod
from securemail.ticket_service import authenticator as auth_mod
from securemail.ticket_service import ts_client
from securemail.ticket_service.as_tgs_server import MAIL_SRV_NAME
from securemail.auth import access_control


POP_HOST = "127.0.0.1"
POP_PORT = 1100
MAIL_DB = Path("data/mail/mailstore.db")
SRV_REPLAY = auth_mod.ReplayCache(window_seconds=300)


def _load_server_privkey():
    from securemail.crypto import rsa_handler
    return rsa_handler.load_private_pem(
        Path("data/server/mail_key.pem").read_bytes(), b"mail-srv-key")


def _handle(conn: socket.socket, addr):
    framer = None
    auth_ctx = None

    def s(obj):
        if framer:
            framer.send(obj)
        else:
            send_json(conn, obj)

    def r():
        if framer:
            return framer.recv()
        return recv_json(conn)

    try:
        while True:
            try:
                msg = r()
            except ConnectionError:
                break
            op = msg.get("op")

            if op == "HELO":
                s({"ok": True, "starttls": True, "server": "SecureMail-POP3"})

            elif op == "STARTTLS":
                cert = Path("data/server/mail_cert.pem").read_bytes()
                key = tls_lite.server_handshake(conn, cert, _load_server_privkey())
                framer = tls_lite.SecureFramer(conn, key)

            elif op == "AUTH":
                kv = ts_client.get_service_key(MAIL_SRV_NAME)
                try:
                    tv = ticket_mod.open_ticket(kv, msg["ticket_v"])
                except Exception as e:
                    s({"ok": False, "error": f"bad ticket: {e}"})
                    log_event("POP3_AUTH_FAIL", f"reason=bad_ticket error={e}")
                    continue
                if ticket_mod.is_expired(tv):
                    s({"ok": False, "error": "ticket expired"})
                    log_event("POP3_AUTH_FAIL", f"reason=ticket_expired")
                    continue
                k_c_v = base64.b64decode(tv["session_key_b64"])
                try:
                    a = auth_mod.open_auth(k_c_v, msg["authenticator"])
                except Exception as e:
                    s({"ok": False, "error": f"bad authenticator: {e}"})
                    log_event("POP3_AUTH_FAIL", f"reason=bad_authenticator error={e}")
                    continue
                if not SRV_REPLAY.check_and_add(a["id_c"] + "@pop3", a.get("nonce", ""), a["ts"]):
                    s({"ok": False, "error": "replay"})
                    log_event("POP3_REPLAY", f"user={a['id_c']}")
                    continue
                resp = {"ts_plus_1": a["ts"] + 1}
                nonce, ct = aes_gcm_encrypt(k_c_v, json.dumps(resp).encode(), aad=b"mutual-v1")
                auth_ctx = {"id_c": a["id_c"], "role": tv["role"], "k_c_v": k_c_v}
                s({"ok": True, "mutual_b64": b64(nonce + ct), "role": tv["role"]})
                log_event("POP3_AUTH_OK", f"user={auth_ctx['id_c']} role={tv['role']}")

            elif op == "LIST":
                if not auth_ctx or not access_control.allowed(auth_ctx["role"], "pop3.fetch"):
                    s({"ok": False, "error": "forbidden"})
                    if auth_ctx:
                        log_event("POP3_FORBIDDEN", f"user={auth_ctx['id_c']} action=pop3.fetch")
                    continue
                conn2 = sqlite3.connect(MAIL_DB)
                rows = conn2.execute(
                    "SELECT id, sender, received_at, dmarc_action, spf_result, dkim_result "
                    "FROM mailbox WHERE recipient=? AND fetched=0 ORDER BY id",
                    (auth_ctx["id_c"],),
                ).fetchall()
                conn2.close()
                s({"ok": True, "messages": [
                    {"id": r[0], "sender": r[1], "received_at": r[2],
                     "dmarc_action": r[3], "spf_result": r[4], "dkim_result": r[5]}
                    for r in rows]})

            elif op == "RETR":
                if not auth_ctx:
                    s({"ok": False, "error": "auth"})
                    continue
                conn2 = sqlite3.connect(MAIL_DB)
                row = conn2.execute(
                    "SELECT sender, envelope, headers_json, dmarc_action, spf_result, dkim_result "
                    "FROM mailbox WHERE id=? AND recipient=?",
                    (msg["id"], auth_ctx["id_c"]),
                ).fetchone()
                conn2.close()
                if not row:
                    s({"ok": False, "error": "not found"})
                    continue
                log_event("POP3_RETR", f"user={auth_ctx['id_c']} msg_id={msg['id']}")
                s({"ok": True, "sender": row[0], "envelope_b64": b64(row[1]),
                   "headers": json.loads(row[2]),
                   "dmarc_action": row[3], "spf_result": row[4], "dkim_result": row[5]})

            elif op == "DELE":
                if not auth_ctx:
                    s({"ok": False, "error": "auth"})
                    continue
                conn2 = sqlite3.connect(MAIL_DB)
                conn2.execute("UPDATE mailbox SET fetched=1 WHERE id=? AND recipient=?",
                              (msg["id"], auth_ctx["id_c"]))
                conn2.commit()
                conn2.close()
                log_event("POP3_DELE", f"user={auth_ctx['id_c']} msg_id={msg['id']}")
                s({"ok": True})

            elif op == "QUIT":
                s({"ok": True, "bye": True})
                break
            else:
                s({"ok": False, "error": f"unknown op {op}"})
    except Exception as e:
        traceback.print_exc()
    finally:
        conn.close()


def serve():
    MAIL_DB.parent.mkdir(parents=True, exist_ok=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((POP_HOST, POP_PORT))
    sock.listen(50)
    print(f"[POP3] POP3-lite on {POP_HOST}:{POP_PORT}")
    try:
        while True:
            c, a = sock.accept()
            threading.Thread(target=_handle, args=(c, a), daemon=True).start()
    finally:
        sock.close()


if __name__ == "__main__":
    serve()
