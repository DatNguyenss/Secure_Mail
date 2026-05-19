"""Ticket Service (AS + TGS) — cổng 9002.

Endpoints:
  ts.register_principal  { id_c, salt_b64, kc_b64 }       (admin)
  ts.as_req              { id_c, id_tgs, ts1 }            → AS-REP encrypted with Kc
  ts.tgs_req             { id_v, tgt, authenticator }     → TGS-REP encrypted with Kc,tgs
  ts.renew_tgt           { tgt, authenticator }           → fresh TGT
  ts.service_keys        { id_v }                          (server-only) → Kv hex
"""
import base64
import datetime as dt
import json
import os
import socket
import sqlite3
import threading
import time
import traceback
from pathlib import Path

from securemail.network.json_framing import send_json, recv_json, b64, unb64
from securemail.crypto.aes_handler import aes_gcm_encrypt, aes_gcm_decrypt, random_key
from . import ticket as ticket_mod
from . import authenticator as auth_mod


TS_HOST = "127.0.0.1"
TS_PORT = 9002

TS_DIR = Path("data/ticket")
TS_DB = TS_DIR / "ticket.db"

# Service keys — shared between Ticket Service and corresponding service
# Trong demo: sinh và lưu trong SQLite, server khác đọc chung file.
TGS_NAME = "tgs/securemail"
MAIL_SRV_NAME = "mail/securemail"

REPLAY_CACHE = auth_mod.ReplayCache(window_seconds=300)
TGT_LIFETIME = 8 * 3600       # 8 hours
SVC_LIFETIME = 30 * 60        # 30 minutes


def _ensure_db():
    TS_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(TS_DB)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS principals (
        id_c TEXT PRIMARY KEY,
        salt BLOB,
        kc   BLOB,
        role TEXT DEFAULT 'user'
    );
    CREATE TABLE IF NOT EXISTS service_keys (
        id_v TEXT PRIMARY KEY,
        kv   BLOB
    );
    CREATE TABLE IF NOT EXISTS revoked_tgts (
        tgt_hash TEXT PRIMARY KEY,
        revoked_at TEXT
    );
    CREATE TABLE IF NOT EXISTS audit_log (ts TEXT, event TEXT, details TEXT);
    """)
    conn.commit()
    conn.close()


def _audit(event: str, details: str = ""):
    """Ghi một dòng audit log vào SQLite."""
    conn = sqlite3.connect(TS_DB)
    conn.execute(
        "INSERT INTO audit_log(ts, event, details) VALUES (?, ?, ?)",
        (dt.datetime.now(dt.timezone.utc).isoformat(), event, details),
    )
    conn.commit()
    conn.close()


def _get_or_create_service_key(id_v: str) -> bytes:
    _ensure_db()
    conn = sqlite3.connect(TS_DB)
    row = conn.execute("SELECT kv FROM service_keys WHERE id_v=?", (id_v,)).fetchone()
    if row:
        conn.close()
        return row[0]
    kv = random_key(32)
    conn.execute("INSERT INTO service_keys(id_v, kv) VALUES (?, ?)", (id_v, kv))
    conn.commit()
    conn.close()
    return kv


def get_service_key(id_v: str) -> bytes:
    """Callable từ các service khác (Mail Server đọc Kv để mở ticket)."""
    return _get_or_create_service_key(id_v)


def register_principal(id_c: str, salt: bytes, kc: bytes, role: str = "user"):
    _ensure_db()
    conn = sqlite3.connect(TS_DB)
    conn.execute(
        "INSERT INTO principals(id_c, salt, kc, role) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(id_c) DO UPDATE SET salt=excluded.salt, kc=excluded.kc, role=excluded.role",
        (id_c, salt, kc, role),
    )
    conn.commit()
    conn.close()
    _audit("REGISTER_PRINCIPAL", f"id_c={id_c} role={role}")
    print(f"[TS] Registered principal {id_c} role={role}")


def _get_principal(id_c: str) -> dict | None:
    conn = sqlite3.connect(TS_DB)
    row = conn.execute("SELECT id_c, salt, kc, role FROM principals WHERE id_c=?", (id_c,)).fetchone()
    conn.close()
    if not row:
        return None
    return {"id_c": row[0], "salt": row[1], "kc": row[2], "role": row[3]}


def _seal_for_user(kc: bytes, payload: dict) -> str:
    data = json.dumps(payload, sort_keys=True).encode("utf-8")
    nonce, ct = aes_gcm_encrypt(kc, data, aad=b"as-rep-v1")
    return base64.b64encode(nonce + ct).decode("ascii")


def handle_as_req(req: dict) -> dict:
    id_c = req["id_c"]
    id_tgs = req["id_tgs"]
    ts1 = req["ts1"]
    p = _get_principal(id_c)
    if not p:
        _audit("AS_REQ_FAIL", f"id_c={id_c} reason=unknown_principal")
        return {"ok": False, "error": "unknown principal"}

    kc = p["kc"]
    k_c_tgs = random_key(32)
    tgt_payload = {
        "session_key_b64": base64.b64encode(k_c_tgs).decode("ascii"),
        "id_c": id_c,
        "ad_c": req.get("ad_c", "127.0.0.1"),
        "id_srv": id_tgs,
        "ts": int(time.time()),
        "lifetime": TGT_LIFETIME,
        "role": p["role"],
    }
    tgs_key = _get_or_create_service_key(TGS_NAME)
    tgt = ticket_mod.seal_ticket(tgs_key, tgt_payload)

    as_rep_payload = {
        "k_c_tgs_b64": base64.b64encode(k_c_tgs).decode("ascii"),
        "id_tgs": id_tgs,
        "ts2": int(time.time()),
        "lifetime": TGT_LIFETIME,
        "tgt": tgt,
        "nonce_echo": ts1,
    }
    _audit("AS_REQ_OK", f"id_c={id_c}")
    return {"ok": True, "as_rep_b64": _seal_for_user(kc, as_rep_payload),
            "salt_b64": base64.b64encode(p["salt"]).decode("ascii")}


def handle_tgs_req(req: dict) -> dict:
    tgs_key = _get_or_create_service_key(TGS_NAME)
    try:
        tgt_payload = ticket_mod.open_ticket(tgs_key, req["tgt"])
    except Exception as e:
        _audit("TGS_REQ_FAIL", f"reason=bad_tgt error={e}")
        return {"ok": False, "error": f"bad tgt: {e}"}
    if ticket_mod.is_expired(tgt_payload):
        _audit("TGS_REQ_FAIL", f"id_c={tgt_payload.get('id_c')} reason=tgt_expired")
        return {"ok": False, "error": "tgt expired"}

    k_c_tgs = base64.b64decode(tgt_payload["session_key_b64"])
    try:
        auth_plain = auth_mod.open_auth(k_c_tgs, req["authenticator"])
    except Exception as e:
        _audit("TGS_REQ_FAIL", f"id_c={tgt_payload.get('id_c')} reason=bad_authenticator error={e}")
        return {"ok": False, "error": f"bad authenticator: {e}"}

    if auth_plain["id_c"] != tgt_payload["id_c"]:
        _audit("TGS_REQ_FAIL", f"id_c_tgt={tgt_payload['id_c']} id_c_auth={auth_plain['id_c']} reason=id_mismatch")
        return {"ok": False, "error": "id_c mismatch"}
    if not REPLAY_CACHE.check_and_add(
        auth_plain["id_c"] + "@tgs",
        auth_plain.get("nonce", ""),
        auth_plain["ts"],
    ):
        _audit("TGS_REQ_REPLAY", f"id_c={auth_plain['id_c']}")
        return {"ok": False, "error": "replay detected"}

    id_v = req["id_v"]
    kv = _get_or_create_service_key(id_v)
    k_c_v = random_key(32)
    ticket_v_payload = {
        "session_key_b64": base64.b64encode(k_c_v).decode("ascii"),
        "id_c": tgt_payload["id_c"],
        "ad_c": tgt_payload["ad_c"],
        "id_srv": id_v,
        "ts": int(time.time()),
        "lifetime": SVC_LIFETIME,
        "role": tgt_payload["role"],
    }
    ticket_v = ticket_mod.seal_ticket(kv, ticket_v_payload)

    tgs_rep_payload = {
        "k_c_v_b64": base64.b64encode(k_c_v).decode("ascii"),
        "id_v": id_v,
        "ts4": int(time.time()),
        "lifetime": SVC_LIFETIME,
        "ticket_v": ticket_v,
    }
    data = json.dumps(tgs_rep_payload, sort_keys=True).encode("utf-8")
    nonce, ct = aes_gcm_encrypt(k_c_tgs, data, aad=b"tgs-rep-v1")
    _audit("TGS_REQ_OK", f"id_c={tgt_payload['id_c']} id_v={id_v}")
    return {"ok": True, "tgs_rep_b64": base64.b64encode(nonce + ct).decode("ascii")}


def _handle(conn: socket.socket, addr):
    try:
        req = recv_json(conn)
        op = req.get("op")
        if op == "ts.register_principal":
            register_principal(req["id_c"], unb64(req["salt_b64"]),
                               unb64(req["kc_b64"]), req.get("role", "user"))
            send_json(conn, {"ok": True})
        elif op == "ts.as_req":
            send_json(conn, handle_as_req(req))
        elif op == "ts.tgs_req":
            send_json(conn, handle_tgs_req(req))
        elif op == "ts.get_service_key":
            # chỉ dùng nội bộ (localhost) để Mail Server lấy Kv
            send_json(conn, {"ok": True, "kv_b64": b64(_get_or_create_service_key(req["id_v"]))})
        else:
            send_json(conn, {"ok": False, "error": f"unknown op: {op}"})
    except Exception as e:
        traceback.print_exc()
        try:
            send_json(conn, {"ok": False, "error": str(e)})
        except Exception:
            pass
    finally:
        conn.close()


def serve():
    _ensure_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((TS_HOST, TS_PORT))
    sock.listen(50)
    print(f"[TS] Ticket Service on {TS_HOST}:{TS_PORT}")
    try:
        while True:
            c, a = sock.accept()
            threading.Thread(target=_handle, args=(c, a), daemon=True).start()
    finally:
        sock.close()


if __name__ == "__main__":
    serve()
