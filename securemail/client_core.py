"""Client-side helpers: registration, login, send, fetch.

Gom toàn bộ logic client để main_client.py và run_demo.py tái sử dụng.
"""
import base64
import datetime as dt
import json
import os
import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from securemail.auth import cert_validator
from securemail.crypto import rsa_handler
from securemail.crypto.hmac_utils import password_hash
from securemail.crypto.key_derivation import hkdf_derive
from securemail.kds import kds_client
from securemail.mail import smime_handler, mime_lite
from securemail.network import smtp_client, pop3_client
from securemail.network.json_framing import request, b64, unb64
from securemail.ticket_service import ts_client
from securemail.ticket_service.as_tgs_server import MAIL_SRV_NAME


USER_DIR = Path("data/users")
SERVER_DIR = Path("data/server")
SESSION_FILE = Path("data/active_session.json")
SESSION_SCHEMA_VERSION = 2
RESERVED_PUBLIC_REGISTER_EMAILS = {"admin@mail.local"}
ALLOWED_ROLES = {"user", "admin", "mailing_list_manager"}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _user_path(email: str, suffix: str) -> Path:
    safe = email.replace("@", "_at_")
    return USER_DIR / f"{safe}.{suffix}"


def _normalize_domain(domain: str) -> str:
    normalized = domain.strip().lower().removeprefix("@")
    if not DOMAIN_RE.match(normalized):
        raise ValueError("invalid domain name")
    return normalized


def _normalize_role(role: str) -> str:
    normalized = (role or "user").strip().lower()
    if normalized not in ALLOWED_ROLES:
        allowed = ", ".join(sorted(ALLOWED_ROLES))
        raise ValueError(f"invalid role '{role}', expected one of: {allowed}")
    return normalized


# ======================================================================
# Session persistence (stateful CLI mode)
# ======================================================================
def save_session(ctx: dict):
    """Serialize login context to a JSON file so later CLI invocations
    can reuse the session without re-entering email/password.

    The private key is stored as unencrypted PEM (session-local only).
    If the session has no private key (restricted mode), the field is omitted.
    """
    SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "schema_version": SESSION_SCHEMA_VERSION,
        "email": ctx["email"],
        "role": ctx.get("role", "user"),
        "tgt": ctx["tgt"],
        "k_c_tgs_b64": base64.b64encode(ctx["k_c_tgs"]).decode("ascii"),
        "cert_pem": ctx["cert_pem"].decode("utf-8") if ctx.get("cert_pem") else "",
        "key_status": ctx.get("key_status", "ok"),
    }
    if ctx.get("privkey") is not None:
        data["privkey_pem"] = rsa_handler.serialize_private_pem(ctx["privkey"]).decode("utf-8")
    SESSION_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_session() -> dict | None:
    """Load a previously saved session.  Returns ctx dict or None.

    Sessions saved in restricted mode (no private key) are loaded with
    ``privkey=None`` and ``key_status`` preserved so the UI can direct
    the user to recovery.
    """
    if not SESSION_FILE.exists():
        return None
    try:
        data = json.loads(SESSION_FILE.read_text(encoding="utf-8"))
        if data.get("schema_version") != SESSION_SCHEMA_VERSION:
            print("[Session] Ignoring old session format. Please login again.")
            clear_session()
            return None
        privkey = None
        key_status = data.get("key_status", "ok")
        if "privkey_pem" in data and data["privkey_pem"]:
            try:
                privkey = rsa_handler.load_private_pem(
                    data["privkey_pem"].encode("utf-8"), None
                )
                key_status = "ok"
            except Exception:
                key_status = "corrupt"
        else:
            key_status = key_status if key_status != "ok" else "missing"
        return {
            "email": data["email"],
            "role": data.get("role", "user"),
            "tgt": data["tgt"],
            "k_c_tgs": base64.b64decode(data["k_c_tgs_b64"]),
            "cert_pem": data["cert_pem"].encode("utf-8") if data.get("cert_pem") else b"",
            "privkey": privkey,
            "key_status": key_status,
        }
    except Exception as exc:
        print(f"[Session] Failed to load session: {exc}")
        clear_session()
        return None


def clear_session():
    """Delete the cached session file."""
    if SESSION_FILE.exists():
        SESSION_FILE.unlink()


# ======================================================================
# Key recovery wrapper (Shamir escrow)
# ======================================================================
def recover_user_key(email: str, share_indices: list[int] | None = None) -> bytes:
    """Recover a user's escrowed private key via Shamir 2-of-3.

    If *share_indices* is ``None``, automatically detect available share
    files and pick the first two.  The recovered PEM is written back to
    the user's local key file so they can log in again.
    """
    from securemail.ca_service import key_escrow

    if share_indices is None:
        # Auto-detect shares
        safe = email.replace("@", "_at_")
        found = []
        for i in range(1, 4):
            p = key_escrow.ESCROW_DIR / f"{safe}.share{i}.bin"
            if p.exists():
                found.append(i)
        if len(found) < 2:
            raise RuntimeError(
                f"Not enough shares found for {email} "
                f"(found {found}, need >=2)"
            )
        share_indices = found[:2]

    recovered_pem = key_escrow.recover_key(email, share_indices)

    # Overwrite the local key file so the user can log in again
    key_path = _user_path(email, "key.pem")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_bytes(recovered_pem)
    print(f"[Recovery] Restored private key for {email} "
          f"using shares {share_indices} -> {key_path}")
    return recovered_pem


def can_recover_key(actor_ctx: dict | None, target_email: str) -> bool:
    if actor_ctx is None:
        return False
    actor_email = actor_ctx.get("email", "")
    actor_role = actor_ctx.get("role", "user")
    return actor_role == "admin" or actor_email.lower() == target_email.lower()


def require_recovery_authorized(actor_ctx: dict | None, target_email: str):
    if actor_ctx is None:
        raise PermissionError("login required for key recovery")
    if not can_recover_key(actor_ctx, target_email):
        raise PermissionError("only admin can recover another user's key")


def escrow_local_user_keys() -> list[str]:
    """Create/update escrow shares for every local ENCRYPTION private key file.

    Signing keys are intentionally excluded — they must never be escrowed
    to preserve non-repudiation guarantees.
    """
    from securemail.ca_service import key_escrow

    USER_DIR.mkdir(parents=True, exist_ok=True)
    escrowed: list[str] = []
    enc_suffix = ".enc_key.pem"
    for key_path in sorted(USER_DIR.glob(f"*{enc_suffix}")):
        safe_name = key_path.name[:-len(enc_suffix)]
        email = safe_name.replace("_at_", "@")
        key_escrow.escrow_key(email, key_path.read_bytes())
        escrowed.append(email)
    return escrowed


def register(email: str, password: str, display_name: str = "", role: str = "user",
             force: bool = False):
    """Register a new user with DUAL keypairs (signing + encryption).

    Signing keypair  → stays on device, never escrowed (non-repudiation).
    Encryption keypair → escrowed via Shamir 2-of-3 for key recovery.

    Local files saved:
      {email}.sign_key.pem, {email}.sign_cert.pem
      {email}.enc_key.pem,  {email}.enc_cert.pem
      {email}.salt.bin

    Args:
        force: If True, allow re-registration over existing account (demo/admin only).
    """
    email = email.strip().lower()
    role = _normalize_role(role)
    USER_DIR.mkdir(parents=True, exist_ok=True)

    # Guard: block silent re-registration
    if not force:
        try:
            existing_cert = kds_client.get_cert(email)
        except Exception:
            existing_cert = None
        if existing_cert:
            raise ValueError(
                f"Tài khoản '{email}' đã tồn tại trong hệ thống. "
                "Vui lòng đăng nhập (Login). Nếu mất khóa, dùng 'Recovery Key' "
                "trong phần Security."
            )

    def _build_csr(priv, cn: str, email_addr: str):
        return (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, email_addr),
            ]))
            .add_extension(
                x509.SubjectAlternativeName([x509.RFC822Name(email_addr)]),
                critical=False,
            )
            .sign(priv, hashes.SHA256())
        ).public_bytes(serialization.Encoding.PEM)

    cn = display_name or email

    # 1. Generate SIGNING keypair
    sign_priv = rsa_handler.generate_keypair(2048)
    sign_csr_pem = _build_csr(sign_priv, cn, email)

    # 2. Generate ENCRYPTION keypair
    enc_priv = rsa_handler.generate_keypair(2048)
    enc_csr_pem = _build_csr(enc_priv, cn, email)

    # 3. Issue signing cert from CA (key_usage='sign')
    sign_resp = request("127.0.0.1", 9000, {
        "op": "ca.sign_csr", "csr_pem_b64": b64(sign_csr_pem),
        "email": email, "key_usage": "sign",
    })
    if not sign_resp.get("ok"):
        raise RuntimeError(f"CA refused signing cert: {sign_resp.get('error')}")
    sign_cert_pem = unb64(sign_resp["cert_pem_b64"])
    sign_serial = hex(x509.load_pem_x509_certificate(sign_cert_pem).serial_number)

    # 4. Issue encryption cert from CA (key_usage='enc')
    enc_resp = request("127.0.0.1", 9000, {
        "op": "ca.sign_csr", "csr_pem_b64": b64(enc_csr_pem),
        "email": email, "key_usage": "enc",
    })
    if not enc_resp.get("ok"):
        raise RuntimeError(f"CA refused encryption cert: {enc_resp.get('error')}")
    enc_cert_pem = unb64(enc_resp["cert_pem_b64"])
    enc_serial = hex(x509.load_pem_x509_certificate(enc_cert_pem).serial_number)

    # 5. Push both certs to KDS
    kds_client.put_cert(email, sign_serial, sign_cert_pem, cert_type="sign")
    kds_client.put_cert(email, enc_serial,  enc_cert_pem,  cert_type="enc")

    # 6. Register principal at Ticket Service
    salt, kc = password_hash(password, None)
    ts_client.register(email, salt, kc, role)

    # 7. Save both keypairs locally (password-encrypted)
    pw_bytes = password.encode("utf-8")
    sign_priv_pem = rsa_handler.serialize_private_pem(sign_priv, pw_bytes)
    enc_priv_pem  = rsa_handler.serialize_private_pem(enc_priv,  pw_bytes)

    _user_path(email, "sign_key.pem").write_bytes(sign_priv_pem)
    _user_path(email, "sign_cert.pem").write_bytes(sign_cert_pem)
    _user_path(email, "enc_key.pem").write_bytes(enc_priv_pem)
    _user_path(email, "enc_cert.pem").write_bytes(enc_cert_pem)
    _user_path(email, "salt.bin").write_bytes(salt)

    # 8. Escrow ONLY the encryption key (signing key must NEVER be escrowed)
    from securemail.ca_service import key_escrow
    key_escrow.escrow_key(email, enc_priv_pem)

    print(f"[REG] Registered {email}")
    print(f"  sign_serial={sign_serial}  enc_serial={enc_serial}")
    return {
        "email": email, "role": role,
        "sign_cert_pem": sign_cert_pem, "sign_serial": sign_serial,
        "enc_cert_pem":  enc_cert_pem,  "enc_serial":  enc_serial,
        # Backward-compat aliases
        "cert_pem": sign_cert_pem, "serial": sign_serial,
    }



def public_register(email: str, password: str, display_name: str = ""):
    """Register a self-service account. Public signup always creates a normal user."""
    normalized = email.strip().lower()
    if normalized in RESERVED_PUBLIC_REGISTER_EMAILS:
        raise RuntimeError("admin account can only be created by a logged-in admin")
    if account_exists(normalized):
        raise RuntimeError(f"account already exists: {normalized}")
    return register(normalized, password, display_name, role="user")


def account_exists(email: str) -> bool:
    """Best-effort duplicate check across local identity files, KDS and Ticket DB."""
    normalized = email.strip().lower()
    if not normalized:
        return False
    # Check new dual-key local files first, then fall back to old single-key file
    for suffix in ("sign_key.pem", "enc_key.pem", "key.pem", "cert.pem", "salt.bin"):
        if _user_path(normalized, suffix).exists():
            return True
    try:
        # Check either cert type in KDS
        if kds_client.get_sign_cert(normalized) or kds_client.get_enc_cert(normalized):
            return True
    except Exception:
        pass
    try:
        from securemail.db_conn import get_conn
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM ticket.principals WHERE id_c=%s", (normalized,))
        row = cursor.fetchone()
        conn.close()
        return bool(row and row[0])
    except Exception:
        return False


def admin_register_account(
    actor_ctx: dict | None,
    email: str,
    password: str,
    display_name: str = "",
    role: str = "user",
):
    """Create an account from an authenticated admin session."""
    if actor_ctx is None:
        raise PermissionError("admin login required to create accounts")
    if actor_ctx.get("role") != "admin":
        raise PermissionError("only admin can create accounts")
    normalized_role = _normalize_role(role)
    return register(email, password, display_name, role=normalized_role)


def register_dkim_domain(domain: str, overwrite: bool = False) -> dict:
    """Register an MTA-controlled DKIM identity for a domain.

    This is an admin operation for domains controlled by this SecureMail
    deployment. It creates/stores the MTA private key locally and publishes the
    CA-signed public certificate to KDS as ``_dkim.<domain>``.
    """
    normalized = _normalize_domain(domain)
    dkim_identity = f"_dkim.{normalized}"
    key_path = SERVER_DIR / f"mta_{normalized}_key.pem"
    cert_path = SERVER_DIR / f"mta_{normalized}_cert.pem"

    existing = kds_client.get_cert(dkim_identity)
    if existing and key_path.exists() and not overwrite:
        cert = x509.load_pem_x509_certificate(existing)
        return {
            "domain": normalized,
            "identity": dkim_identity,
            "serial": hex(cert.serial_number),
            "key_path": str(key_path),
            "cert_path": str(cert_path),
            "created": False,
        }

    SERVER_DIR.mkdir(parents=True, exist_ok=True)
    priv = rsa_handler.generate_keypair(2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"dkim.{normalized}"),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, dkim_identity),
        ]))
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(dkim_identity)]),
            critical=False,
        )
        .sign(priv, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    resp = request("127.0.0.1", 9000, {
        "op": "ca.sign_csr",
        "csr_pem_b64": b64(csr_pem),
        "email": dkim_identity,
    })
    if not resp.get("ok"):
        raise RuntimeError(f"CA refused: {resp.get('error')}")

    cert_pem = unb64(resp["cert_pem_b64"])
    cert = x509.load_pem_x509_certificate(cert_pem)
    serial_hex = hex(cert.serial_number)
    kds_client.put_cert(dkim_identity, serial_hex, cert_pem)

    key_path.write_bytes(rsa_handler.serialize_private_pem(priv, b"mta-domain-key"))
    cert_path.write_bytes(cert_pem)
    return {
        "domain": normalized,
        "identity": dkim_identity,
        "serial": serial_hex,
        "key_path": str(key_path),
        "cert_path": str(cert_path),
        "created": True,
    }


def _lookup_principal_role(email: str) -> str | None:
    try:
        from securemail.db_conn import get_conn
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT role FROM ticket.principals WHERE id_c=%s", (email,))
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:
        return None


def login(email: str, password: str) -> dict:
    """AS-REQ → TGT. Load both signing and encryption private keys.

    - Sign key (sign_key.pem): loaded from local only. If missing, key_status='sign_key_missing'.
      NO auto-recovery from server — signing key must NEVER leave the device.
    - Enc key (enc_key.pem): loaded from local. If missing/mismatched vs KDS enc cert,
      auto-recovery from Shamir escrow is attempted.

    Returns ctx with dual-key fields plus backward-compat aliases:
      sign_privkey, enc_privkey, sign_cert_pem, enc_cert_pem,
      privkey (alias sign_privkey), cert_pem (alias sign_cert_pem)
    """
    # 1. Authenticate with Ticket Service
    as_resp = ts_client.as_request(email, password)
    pw_bytes = password.encode("utf-8")

    # 2. Fetch authoritative certs from KDS
    try:
        sign_cert_pem = kds_client.get_sign_cert(email) or b""
    except Exception:
        sign_cert_pem = b""
    try:
        enc_cert_pem = kds_client.get_enc_cert(email) or b""
    except Exception:
        enc_cert_pem = b""

    # Sync local cert files from KDS
    for suffix, pem in (("sign_cert.pem", sign_cert_pem), ("enc_cert.pem", enc_cert_pem)):
        if pem:
            try:
                _user_path(email, suffix).write_bytes(pem)
            except Exception:
                pass

    # Fallback: read local cert files if KDS unreachable
    if not sign_cert_pem:
        try:
            sign_cert_pem = _user_path(email, "sign_cert.pem").read_bytes()
        except FileNotFoundError:
            pass
    if not enc_cert_pem:
        try:
            enc_cert_pem = _user_path(email, "enc_cert.pem").read_bytes()
        except FileNotFoundError:
            pass

    # 3. Helper functions
    def _try_load_key(pem: bytes):
        try:
            return rsa_handler.load_private_pem(pem, pw_bytes)
        except Exception:
            return None

    def _key_matches_cert(priv_key, cert_pem_bytes: bytes) -> bool:
        if not priv_key or not cert_pem_bytes:
            return False
        try:
            cert = x509.load_pem_x509_certificate(cert_pem_bytes)
            cert_pub = cert.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            local_pub = priv_key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return cert_pub == local_pub
        except Exception:
            return False

    def _auto_recover_enc() -> object | None:
        """Recover enc_key from Shamir escrow and write to disk."""
        from securemail.ca_service import key_escrow
        try:
            recovered_pem = key_escrow.recover_key(email, [1, 2])
            recovered = _try_load_key(recovered_pem)
            if recovered and _key_matches_cert(recovered, enc_cert_pem):
                enc_path = _user_path(email, "enc_key.pem")
                if enc_path.exists():
                    bak = enc_path.with_suffix(
                        f".pem.bak.{dt.datetime.now().strftime('%Y%m%d_%H%M%S')}"
                    )
                    enc_path.rename(bak)
                    print(f"[Login] Old enc key backed up to {bak}")
                enc_path.parent.mkdir(parents=True, exist_ok=True)
                enc_path.write_bytes(recovered_pem)
                print(f"[Login] Auto-recovered enc_key for {email} from escrow.")
                return recovered
            print(f"[Login] Escrow enc_key did not match KDS enc cert for {email}.")
            return None
        except Exception as exc:
            print(f"[Login] Escrow auto-recovery failed for {email}: {exc}")
            return None

    # 4. Load SIGNING key (never auto-recover from server)
    sign_privkey = None
    sign_key_status = "ok"
    sign_key_path = _user_path(email, "sign_key.pem")
    if not sign_key_path.exists():
        sign_key_status = "sign_key_missing"
        print(f"[Login] Signing key missing for {email}. "
              "Non-repudiation: cannot recover from server. "
              "Outgoing email will fail until key is restored.")
    else:
        sign_privkey = _try_load_key(sign_key_path.read_bytes())
        if sign_privkey is None:
            sign_key_status = "sign_key_corrupt"
            print(f"[Login] Cannot load signing key for {email}.")

    # 5. Load ENCRYPTION key (auto-recover from escrow if missing/mismatched)
    enc_privkey = None
    enc_key_status = "ok"
    enc_key_path = _user_path(email, "enc_key.pem")
    if not enc_key_path.exists():
        enc_key_status = "enc_key_missing"
        print(f"[Login] Enc key missing for {email}. Attempting auto-recovery...")
        enc_privkey = _auto_recover_enc()
        if enc_privkey:
            enc_key_status = "ok"
        else:
            print(f"[Login] Auto-recovery failed. Cannot decrypt incoming mail.")
    else:
        enc_privkey = _try_load_key(enc_key_path.read_bytes())
        if enc_privkey is None:
            enc_key_status = "enc_key_corrupt"
            print(f"[Login] Cannot load enc key for {email}. Attempting auto-recovery...")
            enc_privkey = _auto_recover_enc()
            if enc_privkey:
                enc_key_status = "ok"
        elif not _key_matches_cert(enc_privkey, enc_cert_pem):
            print(f"[Login] Enc key mismatch vs KDS cert for {email}. Attempting auto-recovery...")
            enc_key_status = "enc_key_mismatch"
            recovered = _auto_recover_enc()
            if recovered:
                enc_privkey = recovered
                enc_key_status = "ok"
            else:
                print(f"[Login] Warning: enc key mismatch persists for {email}.")

    # Determine overall key_status for UI
    if sign_key_status != "ok":
        key_status = sign_key_status
    elif enc_key_status != "ok":
        key_status = enc_key_status
    else:
        key_status = "ok"

    return {
        "email": email,
        "role": as_resp.get("role") or _lookup_principal_role(email) or "user",
        # Dual-key fields
        "sign_privkey":   sign_privkey,
        "enc_privkey":    enc_privkey,
        "sign_cert_pem":  sign_cert_pem,
        "enc_cert_pem":   enc_cert_pem,
        # Backward-compat aliases (privkey = signing key for sender auth)
        "privkey":   sign_privkey,
        "cert_pem":  sign_cert_pem,
        # Kerberos
        "tgt":      as_resp["tgt"],
        "k_c_tgs":  as_resp["k_c_tgs"],
        "key_status": key_status,
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

    # 3. Fetch and validate recipient ENCRYPTION certs
    recipient_blobs = kds_client.bulk_get(recipient_emails)
    recipients = []
    for email in recipient_emails:
        if email not in recipient_blobs:
            raise RuntimeError(f"no cert for {email}")
        certs = recipient_blobs[email]
        # Use encryption cert for CEK wrapping
        enc_cert_pem = certs.get("enc")
        # Validate chain against signing cert (or enc cert if sign unavailable)
        chain_cert_pem = certs.get("sign") or enc_cert_pem
        if not enc_cert_pem:
            raise RuntimeError(f"no encryption cert for {email}")
        ok, msg = cert_validator.verify_chain(chain_cert_pem, ca_cert_pem, crl_pem)
        if not ok:
            raise RuntimeError(f"cert {email} invalid: {msg}")
        # Also check OCSP using sign cert serial
        cert_obj = x509.load_pem_x509_certificate(chain_cert_pem)
        ocsp = request("127.0.0.1", 9000, {
            "op": "ca.ocsp", "serial_hex": hex(cert_obj.serial_number),
        })
        if ocsp.get("status") != "good":
            raise RuntimeError(f"cert {email} OCSP={ocsp.get('status')}")
        recipients.append((email, enc_cert_pem))

    # 4. Build S/MIME envelope (sign then encrypt)
    # Sign with sender's SIGNING key, encrypt CEK with recipient's ENC public key
    sign_privkey = ctx.get("sign_privkey") or ctx.get("privkey")
    sign_cert_pem = ctx.get("sign_cert_pem") or ctx.get("cert_pem", b"")
    body_bytes = body.encode("utf-8")
    envelope = smime_handler.build_envelope(
        body_bytes, recipients, sign_cert_pem, sign_privkey
    )
    # Sender copy: encrypt CEK with sender's OWN enc cert
    try:
        sender_enc_cert_pem = kds_client.get_enc_cert(ctx["email"]) or b""
    except Exception:
        sender_enc_cert_pem = b""
    if sender_enc_cert_pem:
        sender_copy_envelope = smime_handler.build_envelope(
            body_bytes, [(ctx["email"], sender_enc_cert_pem)], sign_cert_pem, sign_privkey
        )
    else:
        sender_copy_envelope = envelope  # fallback

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

    # 7. Send per recipient. DKIM is an MTA/domain policy, so SMTP server
    # signs controlled domains before SPF/DKIM/DMARC evaluation.
    results = []
    for index, rcpt in enumerate(recipient_emails):
        r = smtp_client.send_mail(
            smtp_host, smtp_port, domain,
            ctx["email"], st["ticket_v"], st["k_c_v"],
            ctx["email"], rcpt, envelope, headers, None,
            sender_copy_envelope=sender_copy_envelope if index == 0 else None,
        )
        results.append((rcpt, r))
    return {
        "envelope_len": len(envelope),
        "sender_copy_len": len(sender_copy_envelope),
        "results": results,
    }


def _decode_pop3_message(ctx: dict, msg_id: int, full: dict, folder: str = "inbox") -> dict:
    """Convert a POP3 RETR response into the public inbox message shape."""
    headers = full.get("headers", {})
    base = {
        "id": msg_id,
        "folder": folder,
        "sender": full.get("sender", ""),
        "recipient": ctx["email"],
        "to": headers.get("To", ctx["email"]),
        "subject": headers.get("Subject", ""),
        "date": headers.get("Date", ""),
        "dmarc_action": full.get("dmarc_action", ""),
        "spf_result": full.get("spf_result", ""),
        "dkim_result": full.get("dkim_result", ""),
    }

    try:
        # Use ENCRYPTION private key to decrypt the CEK
        enc_privkey = ctx.get("enc_privkey") or ctx.get("privkey")
        opened = smime_handler.open_envelope(
            full["envelope"], ctx["email"], enc_privkey
        )
        base.update({
            "body": opened["body"].decode("utf-8", errors="replace"),
            "signer_subject": opened.get("signer_subject", ""),
            "signature_valid": bool(opened.get("signature_valid", True)),
        })
    except Exception as e:
        base.update({
            "error": str(e),
            "signature_valid": False,
        })
    return base


def fetch_inbox(ctx: dict, host: str = "127.0.0.1", port: int = 1100) -> list[dict]:
    """Fetch + decrypt + verify all new messages."""
    st = get_service_ticket(ctx)
    cli = pop3_client.Pop3Client(host, port)
    try:
        cli.helo_starttls()
        cli.auth(ctx["email"], st["ticket_v"], st["k_c_v"])
        msgs = cli.list()

        out = []
        for m in msgs:
            full = cli.retr(m["id"])
            if not full:
                continue
            out.append(_decode_pop3_message(ctx, m["id"], full, folder="inbox"))
        return out
    finally:
        cli.quit()


def fetch_sent(ctx: dict, host: str = "127.0.0.1", port: int = 1100) -> list[dict]:
    """Fetch + decrypt messages stored in the sender's Sent folder."""
    st = get_service_ticket(ctx)
    cli = pop3_client.Pop3Client(host, port)
    try:
        cli.helo_starttls()
        cli.auth(ctx["email"], st["ticket_v"], st["k_c_v"])
        msgs = cli.list(folder="sent")

        out = []
        for m in msgs:
            full = cli.retr(m["id"], folder="sent")
            if not full:
                continue
            out.append(_decode_pop3_message(ctx, m["id"], full, folder="sent"))
        return out
    finally:
        cli.quit()


def fetch_sent_list(ctx: dict, host: str = "127.0.0.1", port: int = 1100) -> list[dict]:
    """Backward-compatible alias for older CLI code."""
    return fetch_sent(ctx, host, port)


# ======================================================================
# Security classification
# ======================================================================
def classify_security(
    msg: dict | str,
    body: str | None = None,
    sender: str | None = None,
) -> tuple[str, str]:
    """Classify a message's security posture.

    The primary API accepts a decoded message dict.  For compatibility
    with the changelog description, this function also accepts
    classify_security(subject, body, sender).

    Returns (label, reason) where label is one of:
      - "SECURE"    — signature valid, SPF pass, DKIM pass/none, DMARC accept
      - "WARNING"   — minor issues, suspicious keywords, or external sender
      - "DANGEROUS" — invalid crypto, DMARC reject, or dangerous keywords

    The *reason* string gives a short human-readable explanation.
    """
    if isinstance(msg, dict):
        subject = msg.get("subject", "")
        body_text = msg.get("body", "")
        sender_addr = msg.get("sender", "")
    else:
        subject = msg or ""
        body_text = body or ""
        sender_addr = sender or ""
        msg = {
            "subject": subject,
            "body": body_text,
            "sender": sender_addr,
            "signature_valid": True,
            "dmarc_action": "accept",
            "spf_result": "pass",
            "dkim_result": "none",
        }

    # --- Decryption / signature error is always dangerous ---
    if msg.get("error"):
        return ("DANGEROUS", f"Decryption/verification error: {msg['error']}")

    if msg.get("signature_valid") is False:
        return ("DANGEROUS", "S/MIME signature is INVALID")

    dmarc = msg.get("dmarc_action", "accept")
    spf = msg.get("spf_result", "pass")
    dkim = msg.get("dkim_result", "none")

    # DMARC reject -> always dangerous
    if dmarc == "reject":
        return ("DANGEROUS", "DMARC policy: reject")

    text = f"{subject}\n{body_text}".lower()
    dangerous_keywords = ("virus", "malware", "hack", "phishing")
    warning_keywords = ("warning", "critical", "suspicious")

    for keyword in dangerous_keywords:
        if keyword in text:
            return ("DANGEROUS", f"Dangerous keyword detected: {keyword}")

    # Build a list of minor issues
    issues: list[str] = []
    if dmarc == "quarantine":
        issues.append("DMARC quarantine")
    if spf == "fail":
        issues.append("SPF failed")
    if dkim == "fail":
        issues.append("DKIM failed")
    elif dkim not in ("pass", "none"):
        issues.append(f"DKIM anomaly: {dkim}")
    for keyword in warning_keywords:
        if keyword in text:
            issues.append(f"Suspicious keyword: {keyword}")
            break
    if sender_addr and not sender_addr.lower().endswith("@mail.local") and dkim != "pass":
        issues.append("External sender without DKIM pass")

    if issues:
        return ("WARNING", "; ".join(issues))

    return ("SECURE", "Signature valid, SPF pass, DKIM trusted, DMARC accept")


# ======================================================================
# Fetch a single message by ID
# ======================================================================
def fetch_message(
    ctx: dict, msg_id: int,
    host: str = "127.0.0.1", port: int = 1100,
) -> dict | None:
    """Retrieve and decrypt a single message from POP3 by its numeric ID.

    Returns the same dict structure as elements of fetch_inbox(), or None
    if the message was not found.
    """
    st = get_service_ticket(ctx)
    cli = pop3_client.Pop3Client(host, port)
    try:
        cli.helo_starttls()
        cli.auth(ctx["email"], st["ticket_v"], st["k_c_v"])

        full = cli.retr(msg_id)
        if not full:
            return None
        return _decode_pop3_message(ctx, msg_id, full, folder="inbox")
    finally:
        cli.quit()


def fetch_sent_message(
    ctx: dict, msg_id: int,
    host: str = "127.0.0.1", port: int = 1100,
) -> dict | None:
    """Retrieve and decrypt a single message from the Sent folder."""
    st = get_service_ticket(ctx)
    cli = pop3_client.Pop3Client(host, port)
    try:
        cli.helo_starttls()
        cli.auth(ctx["email"], st["ticket_v"], st["k_c_v"])

        full = cli.retr(msg_id, folder="sent")
        if not full:
            return None
        return _decode_pop3_message(ctx, msg_id, full, folder="sent")
    finally:
        cli.quit()
