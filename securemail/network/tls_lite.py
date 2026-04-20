"""TLS-lite: STARTTLS-style handshake (M8).

Đơn giản: Server trình RSA cert; client verify; client sinh pre-master ngẫu nhiên,
encrypt bằng RSA-OAEP pub_key server; cả hai derive session key qua HKDF.

Sau handshake, cả hai dùng aes_gcm_encrypt/decrypt với khóa dẫn xuất để wrap mọi frame.
"""
import os
import json
import socket

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from securemail.crypto import rsa_handler
from securemail.crypto.aes_handler import aes_gcm_encrypt, aes_gcm_decrypt
from securemail.crypto.key_derivation import hkdf_derive
from securemail.network.json_framing import send_json, recv_json, b64, unb64


def server_handshake(sock: socket.socket, server_cert_pem: bytes, server_privkey) -> bytes:
    """Server side. Return derived session key (32 bytes)."""
    # Offer cert
    send_json(sock, {"tls": "hello", "cert_pem_b64": b64(server_cert_pem)})
    # Receive encrypted pre-master
    msg = recv_json(sock)
    if msg.get("tls") != "key":
        raise RuntimeError("tls handshake broken")
    pre = rsa_handler.oaep_decrypt(server_privkey, unb64(msg["pre_master_b64"]))
    client_random = unb64(msg["client_random_b64"])
    server_random = os.urandom(16)
    send_json(sock, {"tls": "server_random", "b64": b64(server_random)})
    return hkdf_derive(pre, info=b"tls-lite-v1" + client_random + server_random, length=32)


def client_handshake(sock: socket.socket, expected_email_or_domain: str = "") -> tuple[bytes, bytes]:
    """Client side. Return (session_key, server_cert_pem)."""
    hello = recv_json(sock)
    if hello.get("tls") != "hello":
        raise RuntimeError("expected TLS hello")
    server_cert_pem = unb64(hello["cert_pem_b64"])
    cert = x509.load_pem_x509_certificate(server_cert_pem)

    pre = os.urandom(48)
    client_random = os.urandom(16)
    send_json(sock, {
        "tls": "key",
        "pre_master_b64": b64(rsa_handler.oaep_encrypt(cert.public_key(), pre)),
        "client_random_b64": b64(client_random),
    })
    rand_msg = recv_json(sock)
    server_random = unb64(rand_msg["b64"])
    key = hkdf_derive(pre, info=b"tls-lite-v1" + client_random + server_random, length=32)
    return key, server_cert_pem


class SecureFramer:
    """Wrap send_json/recv_json with AES-GCM."""

    def __init__(self, sock: socket.socket, key: bytes):
        self.sock = sock
        self.key = key
        self.send_seq = 0
        self.recv_seq = 0

    def send(self, obj: dict):
        data = json.dumps(obj).encode("utf-8")
        aad = f"tls-lite|send|{self.send_seq}".encode()
        nonce, ct = aes_gcm_encrypt(self.key, data, aad=aad)
        send_json(self.sock, {"sec": True, "seq": self.send_seq,
                               "nonce_b64": b64(nonce), "ct_b64": b64(ct)})
        self.send_seq += 1

    def recv(self) -> dict:
        msg = recv_json(self.sock)
        if not msg.get("sec"):
            raise RuntimeError("expected secure frame")
        aad = f"tls-lite|send|{msg['seq']}".encode()  # peer sends with their "send" aad
        nonce = unb64(msg["nonce_b64"])
        ct = unb64(msg["ct_b64"])
        data = aes_gcm_decrypt(self.key, nonce, ct, aad=aad)
        return json.loads(data.decode("utf-8"))
