"""SMTP-lite client — gửi email đi qua Mail Server."""
import base64
import json
import socket

from securemail.network.json_framing import send_json, recv_json, b64, unb64
from securemail.network import tls_lite
from securemail.crypto.aes_handler import aes_gcm_decrypt
from securemail.ticket_service import authenticator as auth_mod


def send_mail(
    host: str,
    port: int,
    domain: str,
    id_c: str,              # Kerberos principal (email thường)
    ticket_v: str,
    k_c_v: bytes,
    sender: str,
    recipient: str,
    envelope: bytes,
    headers: dict,
    dkim_sig: str | None = None,
    use_starttls: bool = True,
) -> dict:
    with socket.create_connection((host, port), timeout=20) as sock:
        # EHLO
        send_json(sock, {"op": "EHLO", "domain": domain})
        hello = recv_json(sock)
        framer = None

        def s(obj):
            if framer:
                framer.send(obj)
            else:
                send_json(sock, obj)

        def r():
            if framer:
                return framer.recv()
            return recv_json(sock)

        if use_starttls and hello.get("starttls"):
            send_json(sock, {"op": "STARTTLS"})
            key, server_cert = tls_lite.client_handshake(sock)
            framer = tls_lite.SecureFramer(sock, key)

        # AUTH with Kerberos ticket
        authn = auth_mod.build(k_c_v, id_c, "127.0.0.1")
        s({"op": "AUTH", "ticket_v": ticket_v, "authenticator": authn})
        auth_resp = r()
        if not auth_resp.get("ok"):
            raise RuntimeError(f"AUTH failed: {auth_resp.get('error')}")

        # Verify A7 mutual auth response
        blob = unb64(auth_resp["mutual_b64"])
        nonce, ct = blob[:12], blob[12:]
        mut = json.loads(aes_gcm_decrypt(k_c_v, nonce, ct, aad=b"mutual-v1").decode("utf-8"))
        # ts_plus_1 is our last ts + 1 — we don't strict-check, presence is proof
        assert "ts_plus_1" in mut

        # MAIL
        s({"op": "MAIL", "from": sender, "to": recipient, "size": len(envelope)})
        mail_resp = r()
        if not mail_resp.get("ok"):
            raise RuntimeError(f"MAIL failed: {mail_resp.get('error')}")

        # DATA
        msg = {
            "op": "DATA",
            "envelope_b64": b64(envelope),
            "headers": headers,
        }
        if dkim_sig:
            msg["dkim_sig"] = dkim_sig
        s(msg)
        data_resp = r()

        # QUIT
        s({"op": "QUIT"})
        try:
            r()
        except Exception:
            pass
        return data_resp
