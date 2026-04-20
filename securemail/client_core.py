"""Client-side helpers: registration, login, send, fetch.

Gom toàn bộ logic client để main_client.py và run_demo.py tái sử dụng.
"""
import base64
import datetime as dt
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from securemail.auth import cert_validator
from securemail.crypto import rsa_handler
from securemail.crypto.hmac_utils import password_hash
from securemail.crypto.key_derivation import hkdf_derive
from securemail.kds import kds_client
from securemail.mail import smime_handler, dkim_signer, mime_lite
from securemail.network import smtp_client, pop3_client
from securemail.network.json_framing import request, b64, unb64
from securemail.ticket_service import ts_client
from securemail.ticket_service.as_tgs_server import MAIL_SRV_NAME


USER_DIR = Path("data/users")


def _user_path(email: str, suffix: str) -> Path:
    safe = email.replace("@", "_at_")
    return USER_DIR / f"{safe}.{suffix}"


def register(email: str, password: str, display_name: str = "", role: str = "user"):
    """Đăng ký user mới: tạo keypair, CSR → CA → cert, push KDS, đăng ký tại Ticket Service.

    Store locally: cert.pem + encrypted_key.pem + salt.bin
    """
    USER_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Generate RSA keypair
    priv = rsa_handler.generate_keypair(2048)

    # 2. Build CSR
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, display_name or email),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ]))
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(email)]),
            critical=False,
        )
        .sign(priv, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # 3. Send to CA
    resp = request("127.0.0.1", 9000, {
        "op": "ca.sign_csr", "csr_pem_b64": b64(csr_pem), "email": email,
    })
    if not resp.get("ok"):
        raise RuntimeError(f"CA refused: {resp.get('error')}")
    cert_pem = unb64(resp["cert_pem_b64"])
    cert = x509.load_pem_x509_certificate(cert_pem)
    serial_hex = hex(cert.serial_number)

    # 4. Push cert to KDS
    kds_client.put_cert(email, serial_hex, cert_pem)

    # 5. Register principal at Ticket Service (Kc derived from password)
    salt, kc = password_hash(password, None)
    ts_client.register(email, salt, kc, role)

    # 6. Save locally
    priv_pem = rsa_handler.serialize_private_pem(priv, password.encode("utf-8"))
    _user_path(email, "key.pem").write_bytes(priv_pem)
    _user_path(email, "cert.pem").write_bytes(cert_pem)
    _user_path(email, "salt.bin").write_bytes(salt)

    print(f"[REG] Registered {email} — serial={serial_hex}")
    return {"cert_pem": cert_pem, "serial": serial_hex}


def login(email: str, password: str) -> dict:
    """AS-REQ → get TGT. Also load local private key.

    Returns ctx = {email, privkey, cert_pem, tgt, k_c_tgs}.
    """
    key_pem = _user_path(email, "key.pem").read_bytes()
    cert_pem = _user_path(email, "cert.pem").read_bytes()
    privkey = rsa_handler.load_private_pem(key_pem, password.encode("utf-8"))

    as_resp = ts_client.as_request(email, password)
    return {
        "email": email,
        "privkey": privkey,
        "cert_pem": cert_pem,
        "tgt": as_resp["tgt"],
        "k_c_tgs": as_resp["k_c_tgs"],
    }


def get_service_ticket(ctx: dict, id_v: str = MAIL_SRV_NAME) -> dict:
    r = ts_client.tgs_request(ctx["k_c_tgs"], ctx["tgt"], ctx["email"], id_v)
    return r  # {k_c_v, ticket_v, lifetime}


def send_secure_email(
    ctx: dict,
    recipient_emails: list[str],
    subject: str,
    body: str,
    smtp_host: str = "127.0.0.1",
    smtp_port: int = 2525,
    domain: str = "mail.local",
    dkim_sign: bool = False,
) -> dict:
    """Full E2E: fetch recipient certs → verify chain → build S/MIME → SMTP over TLS-lite."""
    # 1. Get CA root cert (for chain validation)
    ca_resp = request("127.0.0.1", 9000, {"op": "ca.root_cert"})
    ca_cert_pem = unb64(ca_resp["cert_pem_b64"])

    # 2. Get CRL
    crl_pem = kds_client.get_crl()  # may be None

    # 3. Fetch and validate recipient certs
    recipient_blobs = kds_client.bulk_get(recipient_emails)
    recipients = []
    for email in recipient_emails:
        if email not in recipient_blobs:
            raise RuntimeError(f"no cert for {email}")
        cert_pem = recipient_blobs[email]
        ok, msg = cert_validator.verify_chain(cert_pem, ca_cert_pem, crl_pem)
        if not ok:
            raise RuntimeError(f"cert {email} invalid: {msg}")
        # Also check OCSP
        cert_obj = x509.load_pem_x509_certificate(cert_pem)
        ocsp = request("127.0.0.1", 9000, {
            "op": "ca.ocsp", "serial_hex": hex(cert_obj.serial_number),
        })
        if ocsp.get("status") != "good":
            raise RuntimeError(f"cert {email} OCSP={ocsp.get('status')}")
        recipients.append((email, cert_pem))

    # 4. Build S/MIME envelope (sign then encrypt)
    body_bytes = body.encode("utf-8")
    envelope = smime_handler.build_envelope(
        body_bytes, recipients, ctx["cert_pem"], ctx["privkey"]
    )

    # 5. Get Service Ticket for mail
    st = get_service_ticket(ctx)

    # 6. Headers
    headers = {
        "From": ctx["email"],
        "To": ",".join(recipient_emails),
        "Subject": subject,
        "Date": dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000"),
        "Message-ID": f"<{os.urandom(8).hex()}@{domain}>",
        "Content-Type": "application/smime-lite; version=1",
    }

    # 7. Optional DKIM by sender's domain (normally MTA does this, demo allows sender)
    dkim_value = None
    if dkim_sign:
        # Use a domain key registered as _dkim.<domain>
        dkim_key_path = Path(f"data/server/dkim_{domain}_key.pem")
        if dkim_key_path.exists():
            from securemail.crypto import rsa_handler as rh
            dk = rh.load_private_pem(dkim_key_path.read_bytes(), b"dkim-key")
            dkim_value = dkim_signer.sign(headers, envelope, domain, "default", dk)

    # 8. Send per recipient
    results = []
    for rcpt in recipient_emails:
        r = smtp_client.send_mail(
            smtp_host, smtp_port, domain,
            ctx["email"], st["ticket_v"], st["k_c_v"],
            ctx["email"], rcpt, envelope, headers, dkim_value,
        )
        results.append((rcpt, r))
    return {"envelope_len": len(envelope), "results": results}


def fetch_inbox(ctx: dict, host: str = "127.0.0.1", port: int = 1100) -> list[dict]:
    """Fetch + decrypt + verify all new messages."""
    st = get_service_ticket(ctx)
    cli = pop3_client.Pop3Client(host, port)
    cli.helo_starttls()
    cli.auth(ctx["email"], st["ticket_v"], st["k_c_v"])
    msgs = cli.list()

    out = []
    for m in msgs:
        full = cli.retr(m["id"])
        if not full:
            continue
        try:
            opened = smime_handler.open_envelope(
                full["envelope"], ctx["email"], ctx["privkey"]
            )
            out.append({
                "id": m["id"],
                "sender": full["sender"],
                "subject": full["headers"].get("Subject", ""),
                "date": full["headers"].get("Date", ""),
                "body": opened["body"].decode("utf-8", errors="replace"),
                "signer_subject": opened["signer_subject"],
                "signature_valid": True,
                "dmarc_action": full["dmarc_action"],
                "spf_result": full["spf_result"],
                "dkim_result": full["dkim_result"],
            })
        except Exception as e:
            out.append({
                "id": m["id"],
                "sender": full["sender"],
                "subject": full["headers"].get("Subject", ""),
                "error": str(e),
                "signature_valid": False,
                "dmarc_action": full["dmarc_action"],
            })
    cli.quit()
    return out
