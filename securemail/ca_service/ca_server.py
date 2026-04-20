"""CA Service JSON API — cổng 9000.

Endpoints (op field):
  ca.sign_csr      { csr_pem_b64, email }                      → { cert_pem_b64 }
  ca.revoke        { serial_hex }                              → { ok }
  ca.crl           {}                                          → { crl_pem_b64 }
  ca.ocsp          { serial_hex }                              → { status }
  ca.root_cert     {}                                          → { cert_pem_b64 }
  ca.list_issued   {}                                          → { rows: [...] }
"""
import socket
import threading
import sqlite3
import traceback
from pathlib import Path

from securemail.network.json_framing import send_json, recv_json, b64, unb64
from . import ca_core, crl_manager, ocsp_responder


CA_HOST = "127.0.0.1"
CA_PORT = 9000


def _handle(conn: socket.socket, addr):
    try:
        req = recv_json(conn)
        op = req.get("op")
        if op == "ca.sign_csr":
            cert = ca_core.sign_csr(unb64(req["csr_pem_b64"]), req["email"])
            send_json(conn, {"ok": True, "cert_pem_b64": b64(cert)})
        elif op == "ca.revoke":
            ok = ca_core.revoke_cert(req["serial_hex"])
            send_json(conn, {"ok": ok})
        elif op == "ca.crl":
            pem = crl_manager.build_crl()
            send_json(conn, {"ok": True, "crl_pem_b64": b64(pem)})
        elif op == "ca.ocsp":
            send_json(conn, {"ok": True, "status": ocsp_responder.check(req["serial_hex"])})
        elif op == "ca.root_cert":
            send_json(conn, {"ok": True, "cert_pem_b64": b64(ca_core.CA_CERT_FILE.read_bytes())})
        elif op == "ca.list_issued":
            conn2 = sqlite3.connect(ca_core.CA_DB)
            rows = conn2.execute(
                "SELECT serial, email, not_before, not_after, status FROM issued"
            ).fetchall()
            conn2.close()
            send_json(conn, {"ok": True, "rows": [
                {"serial": r[0], "email": r[1], "not_before": r[2],
                 "not_after": r[3], "status": r[4]} for r in rows]})
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
    ca_core.init_root_ca()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((CA_HOST, CA_PORT))
    sock.listen(50)
    print(f"[CA] Serving on {CA_HOST}:{CA_PORT}")
    try:
        while True:
            c, a = sock.accept()
            threading.Thread(target=_handle, args=(c, a), daemon=True).start()
    finally:
        sock.close()


if __name__ == "__main__":
    serve()
