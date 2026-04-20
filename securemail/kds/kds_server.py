"""KDS — cổng 9001. Tra cứu cert & phân phối CRL.

Endpoints:
  kds.put_cert     { email, serial_hex, cert_pem_b64 }   (CA-only trong demo)
  kds.get_cert     { email }                             → { cert_pem_b64 }
  kds.bulk         { emails: [...] }                     → { certs: {email: cert_b64} }
  kds.sync_crl     { crl_pem_b64 }                       (CA push)
  kds.get_crl      {}                                    → { crl_pem_b64 }
  kds.list_emails  {}                                    → { emails: [...] }
"""
import socket
import threading
import traceback

from securemail.network.json_framing import send_json, recv_json, b64, unb64
from . import key_store


KDS_HOST = "127.0.0.1"
KDS_PORT = 9001


def _handle(conn: socket.socket, addr):
    try:
        req = recv_json(conn)
        op = req.get("op")
        if op == "kds.put_cert":
            key_store.put_cert(req["email"], req["serial_hex"], unb64(req["cert_pem_b64"]))
            send_json(conn, {"ok": True})
        elif op == "kds.get_cert":
            rec = key_store.get_cert(req["email"])
            if not rec:
                send_json(conn, {"ok": False, "error": "not found"})
            else:
                send_json(conn, {"ok": True, "cert_pem_b64": b64(rec["cert_pem"]),
                                 "serial": rec["serial"]})
        elif op == "kds.bulk":
            out = {}
            for e in req["emails"]:
                rec = key_store.get_cert(e)
                if rec:
                    out[e] = b64(rec["cert_pem"])
            send_json(conn, {"ok": True, "certs": out})
        elif op == "kds.sync_crl":
            key_store.put_crl(unb64(req["crl_pem_b64"]))
            send_json(conn, {"ok": True})
        elif op == "kds.get_crl":
            crl = key_store.get_crl()
            if crl is None:
                send_json(conn, {"ok": False, "error": "no crl yet"})
            else:
                send_json(conn, {"ok": True, "crl_pem_b64": b64(crl)})
        elif op == "kds.list_emails":
            send_json(conn, {"ok": True, "emails": key_store.list_emails()})
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
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((KDS_HOST, KDS_PORT))
    sock.listen(50)
    print(f"[KDS] Serving on {KDS_HOST}:{KDS_PORT}")
    try:
        while True:
            c, a = sock.accept()
            threading.Thread(target=_handle, args=(c, a), daemon=True).start()
    finally:
        sock.close()


if __name__ == "__main__":
    serve()
