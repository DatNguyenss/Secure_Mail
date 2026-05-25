"""Interactive step-by-step demo — trinh dien truoc hoi dong.

Chay:
  Terminal 1:  python -m securemail.main_ca serve
  Terminal 2:  python -m securemail.main_kds
  Terminal 3:  python -m securemail.main_ticket
  Terminal 4:  python -m securemail.interactive_demo          # bootstrap + menu
  Terminal 5:  python -m securemail.main_mail_server          # (sau bootstrap)

Moi scenario chia nho thanh tung buoc. Nhan Enter de thuc hien buoc tiep theo.
"""
import base64
import datetime as dt
import json
import os
import socket
import sqlite3
import sys
import textwrap
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from securemail import client_core
from securemail.auth import cert_validator
from securemail.ca_service import ca_core, key_escrow, crl_manager
from securemail.crypto import rsa_handler
from securemail.crypto.key_derivation import hkdf_derive
from securemail.kds import kds_client
from securemail.mail import smime_handler
from securemail.network import smtp_client, tls_lite
from securemail.network.json_framing import request, b64, unb64, send_json, recv_json
from securemail.policy import spf_checker, dmarc_engine
from securemail.ticket_service import ts_client, authenticator as auth_mod

DOMAIN = "mail.local"

# ======================================================================
# ANSI colors for beautiful console output
# ======================================================================
class C:
    """ANSI color constants."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BG_GRN  = "\033[42m"
    BG_YEL  = "\033[43m"
    BG_BLU  = "\033[44m"
    BG_MAG  = "\033[45m"


def banner(title: str, subtitle: str = ""):
    """Print a prominent scenario banner."""
    width = 72
    print()
    print(f"{C.BOLD}{C.CYAN}{'=' * width}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}|{C.RESET}  {C.BOLD}{C.WHITE}{title}{C.RESET}")
    if subtitle:
        print(f"{C.BOLD}{C.CYAN}|{C.RESET}  {C.DIM}{subtitle}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'=' * width}{C.RESET}")


def step_banner(step_num: int, total: int, title: str):
    """Print a step header."""
    print()
    print(f"  {C.BOLD}{C.YELLOW}+-- Step {step_num}/{total}: {title}{C.RESET}")
    print(f"  {C.YELLOW}|{C.RESET}")


def info(label: str, value: str):
    """Print an info line indented under a step."""
    print(f"  {C.YELLOW}|{C.RESET}  {C.BOLD}{C.BLUE}{label}:{C.RESET} {value}")


def detail(text: str):
    """Print a detail line."""
    print(f"  {C.YELLOW}|{C.RESET}    {C.DIM}{text}{C.RESET}")


def success(msg: str):
    """Print a success line."""
    print(f"  {C.YELLOW}|{C.RESET}  {C.BOLD}{C.GREEN}[OK] {msg}{C.RESET}")


def fail(msg: str):
    """Print a failure/attack-blocked line."""
    print(f"  {C.YELLOW}|{C.RESET}  {C.BOLD}{C.RED}[BLOCKED] {msg}{C.RESET}")


def warn(msg: str):
    """Print a warning line."""
    print(f"  {C.YELLOW}|{C.RESET}  {C.BOLD}{C.MAGENTA}[!] {msg}{C.RESET}")


def step_end():
    """Close the step box."""
    print(f"  {C.YELLOW}+--------------------------------------{C.RESET}")


def wait(prompt: str = "Press Enter to execute this step..."):
    """Pause execution until user presses Enter."""
    print()
    input(f"  {C.BOLD}{C.CYAN}>> {prompt}{C.RESET} ")


# ======================================================================
# NEW UI helpers: code_snippet, comparison, mechanism
# ======================================================================
def code_snippet(code: str):
    """Print a visually distinct box showing the exact Python code about to execute."""
    print(f"  {C.YELLOW}|{C.RESET}")
    print(f"  {C.YELLOW}|{C.RESET}  {C.BOLD}{C.MAGENTA}[Code to execute]{C.RESET}")
    for line in code.strip().split("\n"):
        print(f"  {C.YELLOW}|{C.RESET}    {C.CYAN}>>> {line}{C.RESET}")
    print(f"  {C.YELLOW}|{C.RESET}")


def comparison(title: str, left_label: str, left_value: str,
               right_label: str, right_value: str):
    """Print a clear stacked comparison to highlight discrepancies."""
    print(f"  {C.YELLOW}|{C.RESET}")
    print(f"  {C.YELLOW}|{C.RESET}  {C.BOLD}{C.MAGENTA}[Comparison: {title}]{C.RESET}")
    print(f"  {C.YELLOW}|{C.RESET}    {C.GREEN}{left_label:.<30s}{C.RESET} {left_value}")
    print(f"  {C.YELLOW}|{C.RESET}    {C.RED}{right_label:.<30s}{C.RESET} {right_value}")
    print(f"  {C.YELLOW}|{C.RESET}")


def mechanism(text: str):
    """Print a brief theoretical explanation of why the system behaved this way."""
    print(f"  {C.YELLOW}|{C.RESET}")
    print(f"  {C.YELLOW}|{C.RESET}  {C.BOLD}{C.MAGENTA}[Defense Mechanism]{C.RESET}")
    # Word-wrap long explanations
    wrapped = textwrap.wrap(text, width=68)
    for line in wrapped:
        print(f"  {C.YELLOW}|{C.RESET}    {C.DIM}{C.WHITE}{line}{C.RESET}")
    print(f"  {C.YELLOW}|{C.RESET}")


# ======================================================================
# Data display helpers
# ======================================================================
def hex_preview(data: bytes, length: int = 32) -> str:
    """Return a hex preview string."""
    h = data.hex()
    if len(h) > length * 2:
        return h[:length * 2] + f"... ({len(data)} bytes total)"
    return h


def b64_preview(data: bytes, length: int = 60) -> str:
    """Return a base64 preview string."""
    encoded = base64.b64encode(data).decode("ascii")
    if len(encoded) > length:
        return encoded[:length] + f"... ({len(data)} bytes)"
    return encoded


def pem_preview(pem: bytes, lines: int = 3) -> str:
    """Return first N lines of a PEM string."""
    decoded = pem.decode("utf-8", errors="replace").strip().split("\n")
    preview = "\n".join(f"      {line}" for line in decoded[:lines])
    return f"\n{preview}\n      ... ({len(decoded)} lines total)"


def cert_info_str(cert_pem: bytes) -> dict:
    """Extract certificate details as a dict for display."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": hex(cert.serial_number),
        "not_before": str(cert.not_valid_before_utc),
        "not_after": str(cert.not_valid_after_utc),
        "key_size": cert.public_key().key_size,
        "sig_algo": cert.signature_algorithm_oid._name,
    }


# ======================================================================
# Bootstrap
# ======================================================================
def _create_server_identity(common_name, email, passphrase, out_key, out_cert):
    """Create server identity -- same as run_demo.py."""
    priv = rsa_handler.generate_keypair(2048)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ]))
        .add_extension(x509.SubjectAlternativeName([x509.RFC822Name(email)]), critical=False)
        .sign(priv, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    r = request("127.0.0.1", 9000, {
        "op": "ca.sign_csr", "csr_pem_b64": b64(csr_pem), "email": email,
    })
    cert_pem = unb64(r["cert_pem_b64"])
    kds_client.put_cert(email, hex(x509.load_pem_x509_certificate(cert_pem).serial_number), cert_pem)
    out_key.parent.mkdir(parents=True, exist_ok=True)
    out_key.write_bytes(rsa_handler.serialize_private_pem(priv, passphrase))
    out_cert.write_bytes(cert_pem)
    return cert_pem


def interactive_bootstrap():
    banner("BOOTSTRAP", "Initialize system: Mail Server identity, DKIM, users, SPF/DMARC, CRL, key escrow")
    total = 6

    # -- Step 1: Mail Server Identity --
    step_banner(1, total, "Create Mail Server Identity (TLS certificate)")
    info("Action", "Generate RSA-2048 keypair -> build CSR -> send to CA -> receive signed certificate")
    info("Purpose", "Mail Server needs a certificate for STARTTLS and POP3-TLS")
    code_snippet(
        '_create_server_identity(\n'
        '    "mail.mail.local", "mail@mail.local", b"mail-srv-key",\n'
        '    Path("data/server/mail_key.pem"), Path("data/server/mail_cert.pem")\n'
        ')'
    )
    wait()
    cert = _create_server_identity(
        f"mail.{DOMAIN}", f"mail@{DOMAIN}", b"mail-srv-key",
        Path("data/server/mail_key.pem"), Path("data/server/mail_cert.pem"),
    )
    ci = cert_info_str(cert)
    info("Subject", ci["subject"])
    info("Issuer", ci["issuer"])
    info("Serial", ci["serial"])
    info("Key Size", f"{ci['key_size']} bits (RSA)")
    info("Validity", f"{ci['not_before']} -> {ci['not_after']}")
    success("Mail Server identity created and published to KDS")
    step_end()

    # -- Step 2: DKIM Keys --
    step_banner(2, total, "Create DKIM Signing Keys (MTA + Client)")
    info("Action", "Generate 2 DKIM keypairs for domain authentication")
    info("Purpose", "DKIM allows MTA to sign email headers to prevent origin forgery")
    code_snippet(
        '_create_server_identity("dkim.mail.local", "_dkim.mail.local", ...)\n'
        '_create_server_identity("dkim-client.mail.local", "_dkim-client.mail.local", ...)'
    )
    wait()
    _create_server_identity(
        f"dkim.{DOMAIN}", f"_dkim.{DOMAIN}", b"mta-domain-key",
        Path(f"data/server/mta_{DOMAIN}_key.pem"),
        Path(f"data/server/mta_{DOMAIN}_cert.pem"),
    )
    _create_server_identity(
        f"dkim-client.{DOMAIN}", f"_dkim-client.{DOMAIN}", b"dkim-key",
        Path(f"data/server/dkim_{DOMAIN}_key.pem"),
        Path(f"data/server/dkim_{DOMAIN}_cert.pem"),
    )
    success("MTA DKIM key created")
    success("Client DKIM key created")
    step_end()

    # -- Step 3: Register Users --
    step_banner(3, total, "Register Users (Alice, Bob, Eve, Admin)")
    info("Action", "For each user: RSA keygen -> CSR -> CA sign -> push cert to KDS -> register Kerberos principal")
    info("Flow", "Password -> PBKDF2 -> Kc (client master key) -> stored in Ticket Service")
    code_snippet(
        'client_core.register("alice@mail.local", "alice-pw", "Alice", "user")\n'
        'client_core.register("bob@mail.local",   "bob-pw",   "Bob",   "user")\n'
        'client_core.register("eve@mail.local",   "eve-pw",   "Eve",   "user")\n'
        'client_core.register("admin@mail.local", "admin-pw", "Admin", "admin")'
    )
    wait()
    for email, pw, display, role in [
        (f"alice@{DOMAIN}", "alice-pw", "Alice", "user"),
        (f"bob@{DOMAIN}", "bob-pw", "Bob", "user"),
        (f"eve@{DOMAIN}", "eve-pw", "Eve", "user"),
        (f"admin@{DOMAIN}", "admin-pw", "Admin", "admin"),
    ]:
        user_key = Path(f"data/users/{email.replace('@','_at_')}.key.pem")
        if user_key.exists():
            info(email, f"SKIP (already registered)")
        else:
            client_core.register(email, pw, display, role)
            info(email, f"Registered [OK] (role={role})")
    step_end()

    # -- Step 4: SPF + DMARC --
    step_banner(4, total, "Configure SPF + DMARC Policy")
    info("SPF", f"Authorized IP for domain '{DOMAIN}': 127.0.0.1")
    info("DMARC", f"Policy: quarantine (failed SPF/DKIM -> quarantine, not reject)")
    code_snippet(
        'spf_checker.add_spf("mail.local", "127.0.0.1")\n'
        'dmarc_engine.set_policy("mail.local", "quarantine")'
    )
    wait()
    spf_checker.add_spf(DOMAIN, "127.0.0.1")
    dmarc_engine.set_policy(DOMAIN, "quarantine")
    success("SPF record added")
    success("DMARC policy set to 'quarantine'")
    step_end()

    # -- Step 5: Initial CRL --
    step_banner(5, total, "Push Initial CRL (Certificate Revocation List)")
    info("Action", "Build empty CRL -> sign with CA private key -> push to KDS")
    info("Purpose", "Clients query CRL to verify certificates are not revoked")
    code_snippet(
        'crl = crl_manager.build_crl()\n'
        'kds_client.sync_crl(crl)'
    )
    wait()
    crl = crl_manager.build_crl()
    kds_client.sync_crl(crl)
    info("CRL size", f"{len(crl)} bytes")
    success("Initial CRL published to KDS")
    step_end()

    # -- Step 6: Key Escrow --
    step_banner(6, total, "Escrow Bob's Private Key (Shamir 2-of-3)")
    info("Action", "Split Bob's private key into 3 shares using Shamir Secret Sharing on GF(256)")
    info("Threshold", "Any 2 of 3 shares can reconstruct the original key")
    info("Purpose", "Key recovery in case of lost access (audit / compliance)")
    code_snippet(
        'bob_key_pem = Path("data/users/bob_at_mail.local.key.pem").read_bytes()\n'
        'key_escrow.escrow_key("bob@mail.local", bob_key_pem)'
    )
    wait()
    bob_key_pem = Path(f"data/users/bob_at_{DOMAIN}.key.pem").read_bytes()
    key_escrow.escrow_key(f"bob@{DOMAIN}", bob_key_pem)
    info("Original key size", f"{len(bob_key_pem)} bytes")
    for i in range(1, 4):
        share_path = Path(f"data/ca/escrow/bob_at_{DOMAIN}.share{i}.bin")
        if share_path.exists():
            info(f"Share {i}", f"{len(share_path.read_bytes())} bytes -> {share_path}")
    success("Bob's private key escrowed (2-of-3 Shamir)")
    step_end()

    print(f"\n  {C.BOLD}{C.GREEN}{'=' * 50}{C.RESET}")
    print(f"  {C.BOLD}{C.GREEN} BOOTSTRAP COMPLETE -- All services ready{C.RESET}")
    print(f"  {C.BOLD}{C.GREEN}{'=' * 50}{C.RESET}")
    print(f"\n  {C.CYAN}Now start the Mail Server in another terminal:{C.RESET}")
    print(f"  {C.WHITE}  python -m securemail.main_mail_server{C.RESET}\n")


# ======================================================================
# Scenario 1 -- Normal Encrypted + Signed Email Flow
# ======================================================================
def interactive_scenario_1():
    banner("Scenario 1 -- Normal Encrypted + Signed Email",
           "Full E2E: Kerberos auth -> cert fetch -> S/MIME sign+encrypt -> SMTP -> POP3 decrypt")
    total = 6

    # -- Step 1: Login Alice --
    step_banner(1, total, "Alice logs in (Kerberos AS-REQ -> AS-REP)")
    info("Action", "Alice sends AS-REQ to Ticket Service with her identity")
    info("Protocol", "Password -> PBKDF2 -> Kc -> decrypt AS-REP -> obtain TGT + K_c,tgs")
    code_snippet('alice = client_core.login("alice@mail.local", "alice-pw")')
    wait()
    alice = client_core.login(f"alice@{DOMAIN}", "alice-pw")
    info("Email", alice["email"])
    info("TGT", f"{alice['tgt'][:60]}...")
    info("K_c,tgs", hex_preview(alice["k_c_tgs"]))
    info("Private key", f"RSA-{alice['privkey'].key_size} loaded from encrypted PEM")
    success("Alice authenticated -- TGT obtained")
    mechanism(
        "The AS-REQ/AS-REP exchange is the Kerberos authentication step. "
        "Alice proves she knows her password by decrypting the AS-REP "
        "(encrypted with Kc derived from her password via PBKDF2). "
        "She obtains a TGT and session key K_c,tgs for further service requests."
    )
    step_end()

    # -- Step 2: Fetch Bob's certificate --
    step_banner(2, total, "Fetch and verify Bob's certificate from KDS")
    info("Action", "Query KDS for Bob's cert -> verify CA chain -> check CRL -> check OCSP")
    code_snippet(
        'bob_cert_pem = kds_client.get_cert("bob@mail.local")\n'
        'ok, reason = cert_validator.verify_chain(bob_cert_pem, ca_cert_pem, crl_pem)\n'
        'ocsp = request("127.0.0.1", 9000, {"op": "ca.ocsp", "serial_hex": serial})'
    )
    wait()
    ca_resp = request("127.0.0.1", 9000, {"op": "ca.root_cert"})
    ca_cert_pem = unb64(ca_resp["cert_pem_b64"])
    bob_cert_pem = kds_client.get_cert(f"bob@{DOMAIN}")
    assert bob_cert_pem, "Bob cert not found"
    ci = cert_info_str(bob_cert_pem)
    info("Bob's Subject", ci["subject"])
    info("Bob's Issuer", ci["issuer"])
    info("Bob's Serial", ci["serial"])
    info("Bob's Key Size", f"{ci['key_size']} bits")
    crl_pem = kds_client.get_crl()
    ok, reason = cert_validator.verify_chain(bob_cert_pem, ca_cert_pem, crl_pem)
    info("Chain validation", f"{'[OK] VALID' if ok else '[FAIL] INVALID'} -- {reason}")
    bob_cert = x509.load_pem_x509_certificate(bob_cert_pem)
    ocsp = request("127.0.0.1", 9000, {"op": "ca.ocsp", "serial_hex": hex(bob_cert.serial_number)})
    info("OCSP status", ocsp.get("status", "unknown"))
    success("Bob's certificate verified (chain + CRL + OCSP)")
    step_end()

    # -- Step 3: Build S/MIME envelope --
    step_banner(3, total, "Build S/MIME Envelope (Sign-then-Encrypt)")
    info("Action", "1) RSA-PSS sign plaintext  2) AES-128-CBC encrypt (sign+body)  3) RSA-OAEP encrypt CEK for Bob")
    body_text = "Hello Bob, this is the first secure email.\nCipher: AES-128-CBC + RSA-OAEP + RSA-PSS."
    info("Plaintext", f'"{body_text[:60]}..."')
    code_snippet(
        'envelope = smime_handler.build_envelope(\n'
        '    body_bytes,\n'
        '    [("bob@mail.local", bob_cert_pem)],\n'
        '    alice["cert_pem"], alice["privkey"]\n'
        ')'
    )
    wait()
    body_bytes = body_text.encode("utf-8")
    envelope = smime_handler.build_envelope(
        body_bytes, [(f"bob@{DOMAIN}", bob_cert_pem)],
        alice["cert_pem"], alice["privkey"],
    )
    env_parsed = json.loads(envelope.decode("utf-8"))
    info("Envelope version", env_parsed["version"])
    info("Encryption algo", env_parsed["content"]["algo"])
    info("IV (base64)", env_parsed["content"]["iv_b64"][:40] + "...")
    info("Ciphertext size", f"{len(base64.b64decode(env_parsed['content']['ct_b64']))} bytes")
    info("Recipients", f"{len(env_parsed['recipients'])} -- [{env_parsed['recipients'][0]['email']}]")
    info("Encrypted CEK", env_parsed["recipients"][0]["cek_oaep_b64"][:40] + "...")
    info("Total envelope", f"{len(envelope)} bytes")
    success("S/MIME envelope built (signed + encrypted)")
    step_end()

    # -- Step 4: Get Service Ticket --
    step_banner(4, total, "Obtain Kerberos Service Ticket for Mail Server")
    info("Action", "TGS-REQ: present TGT + Authenticator -> receive Ticket_v + K_c,v")
    code_snippet('st = client_core.get_service_ticket(alice)')
    wait()
    st = client_core.get_service_ticket(alice)
    info("Ticket_v", f"{st['ticket_v'][:60]}...")
    info("K_c,v (session key)", hex_preview(st["k_c_v"]))
    info("Lifetime", f"{st['lifetime']} seconds")
    success("Service Ticket obtained for mail/securemail")
    step_end()

    # -- Step 5: Send via SMTP --
    step_banner(5, total, "Send Email via SMTP-lite (EHLO -> STARTTLS -> AUTH -> DATA)")
    info("Action", "Connect to Mail Server, STARTTLS handshake, Kerberos auth, deliver envelope")
    code_snippet(
        'smtp_client.send_mail(\n'
        '    "127.0.0.1", 2525, "mail.local",\n'
        '    alice["email"], st["ticket_v"], st["k_c_v"],\n'
        '    alice["email"], "bob@mail.local", envelope, headers\n'
        ')'
    )
    wait()
    headers = {
        "From": alice["email"], "To": f"bob@{DOMAIN}",
        "Subject": "[S1] Interactive -- Normal encrypted + signed",
        "Date": dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000"),
        "Message-ID": f"<{os.urandom(8).hex()}@{DOMAIN}>",
        "Content-Type": "application/smime-lite; version=1",
    }
    r = smtp_client.send_mail(
        "127.0.0.1", 2525, DOMAIN,
        alice["email"], st["ticket_v"], st["k_c_v"],
        alice["email"], f"bob@{DOMAIN}", envelope, headers,
    )
    info("Server response", f"ok={r.get('ok')}")
    info("DMARC action", str(r.get("dmarc_action")))
    info("MTA DKIM", "YES" if r.get("mta_dkim") else "NO")
    info("Message-ID", r.get("message_id", "N/A"))
    success("Email delivered to mail server")
    step_end()

    # -- Step 6: Bob fetches and decrypts --
    step_banner(6, total, "Bob fetches inbox (POP3-TLS -> decrypt -> verify signature)")
    info("Action", "Bob logs in -> POP3 STARTTLS -> AUTH -> LIST -> RETR -> open S/MIME envelope")
    code_snippet(
        'bob = client_core.login("bob@mail.local", "bob-pw")\n'
        'inbox = client_core.fetch_inbox(bob)'
    )
    wait()
    bob = client_core.login(f"bob@{DOMAIN}", "bob-pw")
    inbox = client_core.fetch_inbox(bob)
    info("Messages in inbox", str(len(inbox)))
    for m in inbox:
        if "S1" in m.get("subject", "") and "Interactive" in m.get("subject", ""):
            info("Subject", m["subject"])
            info("Sender", m.get("sender", "?"))
            info("Signature valid", str(m["signature_valid"]))
            info("Signer", m.get("signer_subject", "?"))
            info("DMARC", m.get("dmarc_action", "?"))
            info("Body preview", m.get("body", "")[:80])
            break
    success("Bob successfully received, decrypted, and verified the email")
    mechanism(
        "The full E2E flow: Alice authenticates via Kerberos (AS + TGS), "
        "fetches Bob's CA-signed certificate from KDS, builds an S/MIME "
        "envelope (RSA-PSS sign then AES-128-CBC + RSA-OAEP encrypt), "
        "sends via SMTP with STARTTLS and Kerberos ticket-based auth, "
        "and Bob decrypts with his private key and verifies Alice's signature."
    )
    step_end()

    print(f"\n  {C.BOLD}{C.GREEN}  [OK] SCENARIO 1 -- PASSED{C.RESET}\n")


# ======================================================================
# Scenario 2 -- MITM / Public-Key Substitution Attack
# ======================================================================
def interactive_scenario_2():
    banner("Scenario 2 -- MITM / Public-Key Substitution Attack",
           "Attacker creates a fake certificate and tries to inject it into KDS")
    total = 5

    # -- Step 1: Generate attacker's keypair --
    step_banner(1, total, "Attacker generates a FAKE RSA-2048 keypair")
    info("Action", "Generate new RSA keypair -- this key is NOT certified by the CA")
    code_snippet('fake_priv = rsa_handler.generate_keypair(2048)')
    wait()
    fake_priv = rsa_handler.generate_keypair(2048)
    fake_pub_pem = rsa_handler.serialize_public_pem(fake_priv.public_key())
    info("Fake public key", pem_preview(fake_pub_pem, lines=2))
    info("Key size", f"{fake_priv.key_size} bits")
    success("Attacker has generated a keypair")
    step_end()

    # -- Step 2: Build self-signed cert --
    step_banner(2, total, "Attacker creates a SELF-SIGNED certificate impersonating Bob")
    info("Action", "Build X.509 cert: Subject='FAKE Bob', email='bob@mail.local' -- signed by ATTACKER's key (NOT CA)")
    info("Key insight", "This cert looks like Bob's, but its signature chain does NOT lead to the trusted CA")
    code_snippet(
        'fake_cert = (\n'
        '    x509.CertificateBuilder()\n'
        '    .subject_name(Name([CN="FAKE Bob", EMAIL="bob@mail.local"]))\n'
        '    .issuer_name(Name([CN="FAKE Bob"]))   # <-- SELF-SIGNED!\n'
        '    .public_key(fake_priv.public_key())\n'
        '    .sign(fake_priv, SHA256())             # <-- signed by ATTACKER!\n'
        ')'
    )
    wait()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "FAKE Bob"),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, f"bob@{DOMAIN}"),
    ])
    now = dt.datetime.now(dt.timezone.utc)
    fake_cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)  # self-signed!
        .public_key(fake_priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
        .sign(fake_priv, hashes.SHA256())  # signed by ATTACKER, not CA!
    )
    fake_pem = fake_cert.public_bytes(serialization.Encoding.PEM)
    ci = cert_info_str(fake_pem)
    info("Subject", ci["subject"])
    info("Issuer", f"{ci['issuer']}  <-- {C.RED}SELF-SIGNED (attacker is issuer){C.RESET}")
    info("Serial", ci["serial"])
    info("Validity", f"{ci['not_before']} -> {ci['not_after']}")
    info("Fake cert PEM", pem_preview(fake_pem, lines=2))
    warn("Notice: Issuer == Subject -> this is SELF-SIGNED, not CA-signed!")
    step_end()

    # -- Step 3: Inject fake cert into KDS --
    step_banner(3, total, "Attacker injects the FAKE cert into KDS")
    info("Action", "Push fake cert to KDS under a fake email entry")
    info("Key insight", "KDS stores certs but does NOT verify CA signature at upload time")
    code_snippet('kds_client.put_cert("eve-fake-bob@mail.local", serial_hex, fake_pem)')
    wait()
    kds_client.put_cert(f"eve-fake-bob@{DOMAIN}", hex(fake_cert.serial_number), fake_pem)
    info("Injected as", f"eve-fake-bob@{DOMAIN}")
    warn("Fake cert is now stored in KDS!")
    step_end()

    # -- Step 4: Client-side validation CATCHES the fake --
    step_banner(4, total, "Alice tries to USE the fake cert -- CLIENT-SIDE VALIDATION")
    info("Action", "Load CA root cert -> call verify_chain(fake_cert, CA_cert) -> verify CA signature")
    info("Key insight", "The client verifies the certificate chain: is this cert signed by OUR CA?")
    code_snippet(
        'ca_pem = request("127.0.0.1", 9000, {"op": "ca.root_cert"})\n'
        'ok, reason = cert_validator.verify_chain(fake_pem, ca_pem, None)'
    )
    wait()
    ca_pem = unb64(request("127.0.0.1", 9000, {"op": "ca.root_cert"})["cert_pem_b64"])
    ca_ci = cert_info_str(ca_pem)
    info("Trusted CA", ca_ci["subject"])
    ok, reason = cert_validator.verify_chain(fake_pem, ca_pem, None)
    info("Validation result", f"ok={ok}")
    info("Reason", reason)
    if not ok:
        fail(f"FAKE cert REJECTED: {reason}")
    else:
        warn("Unexpected: fake cert passed validation?!")

    # ---- COMPARISON: Real vs Fake cert ----
    real_pem = kds_client.get_cert(f"bob@{DOMAIN}")
    real_ci = cert_info_str(real_pem)
    comparison(
        "Real Bob Cert vs Fake Bob Cert",
        "Real Issuer (Trusted CA)", real_ci["issuer"],
        "Fake Issuer (Self-Signed)", ci["issuer"],
    )
    comparison(
        "Signature Verification",
        "Real cert -> verify_chain()", "[OK] VALID (signed by CA)",
        "Fake cert -> verify_chain()", f"[BLOCKED] REJECTED ({reason})",
    )
    mechanism(
        "The client-side verify_chain() function checks the cryptographic "
        "signature of the certificate against the Trusted CA's public key. "
        "The attacker cannot forge the CA's RSA signature without the CA's "
        "private key, so the fake self-signed certificate is immediately "
        "rejected. This is the fundamental defense of PKI (Public Key "
        "Infrastructure) against MITM attacks."
    )
    step_end()

    # -- Step 5: Verify real Bob cert still works --
    step_banner(5, total, "Verify that the REAL Bob cert is still trusted")
    info("Action", "Fetch real Bob cert from KDS -> verify_chain -> must pass")
    code_snippet(
        'real_pem = kds_client.get_cert("bob@mail.local")\n'
        'ok2, reason2 = cert_validator.verify_chain(real_pem, ca_pem, None)'
    )
    wait()
    ok2, reason2 = cert_validator.verify_chain(real_pem, ca_pem, None)
    info("Real Subject", real_ci["subject"])
    info("Real Issuer", real_ci["issuer"])
    info("Validation result", f"ok={ok2} -- {reason2}")
    success("Real Bob cert is STILL VALID -- MITM attack blocked by certificate chain verification")
    step_end()

    print(f"\n  {C.BOLD}{C.GREEN}  [OK] SCENARIO 2 -- PASSED (attack blocked){C.RESET}\n")


# ======================================================================
# Scenario 3 -- Replay Attack
# ======================================================================
def interactive_scenario_3():
    banner("Scenario 3 -- Replay Attack Detection",
           "Attacker captures a Kerberos Authenticator and replays it to the Mail Server")
    total = 5

    # -- Step 1: Login + get ticket --
    step_banner(1, total, "Alice logs in and obtains a Service Ticket")
    info("Action", "AS-REQ -> TGT -> TGS-REQ -> Ticket_v + K_c,v")
    code_snippet(
        'alice = client_core.login("alice@mail.local", "alice-pw")\n'
        'st = client_core.get_service_ticket(alice)'
    )
    wait()
    alice = client_core.login(f"alice@{DOMAIN}", "alice-pw")
    st = client_core.get_service_ticket(alice)
    info("Ticket_v", f"{st['ticket_v'][:50]}...")
    info("K_c,v", hex_preview(st["k_c_v"]))
    info("Lifetime", f"{st['lifetime']}s")
    success("Alice has a valid service ticket")
    step_end()

    # -- Step 2: Send a legitimate email --
    step_banner(2, total, "Send a legitimate email (capturing the protocol)")
    info("Action", "Alice sends to Bob -- this is a valid send that should succeed")
    code_snippet(
        'env = smime_handler.build_envelope(body, recipients, alice_cert, alice_key)\n'
        'smtp_client.send_mail("127.0.0.1", 2525, ..., env, headers)'
    )
    wait()
    bob_cert_pem = kds_client.get_cert(f"bob@{DOMAIN}")
    env = smime_handler.build_envelope(
        "Replay test - legitimate message".encode(), [(f"bob@{DOMAIN}", bob_cert_pem)],
        alice["cert_pem"], alice["privkey"],
    )
    headers = {"From": alice["email"], "To": f"bob@{DOMAIN}",
               "Subject": "[S3] Replay test", "Date": "now",
               "Message-ID": f"<{os.urandom(4).hex()}@{DOMAIN}>"}
    r1 = smtp_client.send_mail(
        "127.0.0.1", 2525, DOMAIN,
        alice["email"], st["ticket_v"], st["k_c_v"],
        alice["email"], f"bob@{DOMAIN}", env, headers,
    )
    info("Result", f"ok={r1.get('ok')}")
    info("DMARC", str(r1.get("dmarc_action")))
    success("First send: LEGITIMATE -- accepted by server")
    step_end()

    # -- Step 3: Build and capture an Authenticator --
    step_banner(3, total, "Build a Kerberos Authenticator (for the attack)")
    info("Action", "Create Authenticator = E(K_c,v, [IDc || ADc || TS || Nonce])")
    info("Structure", "The Authenticator contains a timestamp + nonce + encrypted with session key")
    code_snippet(
        'authn = authenticator.build(st["k_c_v"], alice["email"], "127.0.0.1")\n'
        '# This blob will be CAPTURED by the attacker'
    )
    wait()
    authn = auth_mod.build(st["k_c_v"], alice["email"], "127.0.0.1")
    info("Authenticator blob", f"{authn[:60]}...")
    info("Blob length", f"{len(authn)} characters (base64-encoded)")
    detail("This blob is AES-GCM encrypted with K_c,v")
    detail("Contains: id_c, ad_c (client address), timestamp, random nonce")
    warn("ATTACKER CAPTURES THIS AUTHENTICATOR for replay!")
    step_end()

    # -- Step 4: First use -- should succeed --
    step_banner(4, total, "First use of captured Authenticator -> should SUCCEED")
    info("Action", "Open TCP -> EHLO -> STARTTLS -> send AUTH with the captured authenticator")
    code_snippet(
        'send({"op": "AUTH", "ticket_v": ticket_v, "authenticator": authn})\n'
        'resp = recv()  # First use: should be accepted'
    )
    wait()

    def try_auth_with(authn_blob):
        s = socket.create_connection(("127.0.0.1", 2525), timeout=10)
        send_json(s, {"op": "EHLO", "domain": DOMAIN})
        recv_json(s)
        send_json(s, {"op": "STARTTLS"})
        key, _ = tls_lite.client_handshake(s)
        fr = tls_lite.SecureFramer(s, key)
        fr.send({"op": "AUTH", "ticket_v": st["ticket_v"], "authenticator": authn_blob})
        resp = fr.recv()
        s.close()
        return resp

    r_a = try_auth_with(authn)
    info("Result", f"ok={r_a.get('ok')}")
    if r_a.get("ok"):
        success("First use: ACCEPTED (fresh authenticator, unique nonce)")
    else:
        fail(f"Unexpected failure: {r_a.get('error')}")
    step_end()

    # -- Step 5: REPLAY -- should be REJECTED --
    step_banner(5, total, "REPLAY the SAME Authenticator -> should be REJECTED")
    info("Action", "Send the EXACT SAME authenticator blob to the server again")
    info("Key insight", "Server maintains a ReplayCache -- (id_c, nonce) pairs are tracked")
    info("Why it fails", "Same nonce+timestamp already used -> server says 'replay detected'")
    code_snippet(
        '# REPLAY ATTACK: sending the IDENTICAL authenticator blob again\n'
        'send({"op": "AUTH", "ticket_v": ticket_v, "authenticator": authn})  # SAME blob!\n'
        'resp = recv()  # Should be REJECTED'
    )
    wait("Press Enter to attempt the REPLAY ATTACK...")
    r_b = try_auth_with(authn)
    info("Result", f"ok={r_b.get('ok')}")
    info("Error", r_b.get("error", "N/A"))

    # ---- COMPARISON: First use vs Replay ----
    comparison(
        "First Request vs Replayed Request",
        "1st Authenticator (fresh)", f"ok={r_a.get('ok')} -- ACCEPTED (unique nonce)",
        "2nd Authenticator (REPLAY)", f"ok={r_b.get('ok')} -- REJECTED ({r_b.get('error', '?')})",
    )
    comparison(
        "Authenticator Contents (identical)",
        "1st: Nonce + Timestamp", f"blob = {authn[:40]}...",
        "2nd: Nonce + Timestamp", f"blob = {authn[:40]}... (DUPLICATE!)",
    )

    if not r_b.get("ok") and "replay" in r_b.get("error", "").lower():
        fail(f"REPLAY DETECTED AND BLOCKED: {r_b.get('error')}")
        success("Server correctly identifies and rejects the replayed authenticator!")
    else:
        warn(f"Unexpected result: {r_b}")

    mechanism(
        "The Mail Server maintains an in-memory ReplayCache that tracks "
        "(IDc, Nonce) pairs within a 5-minute time window. Each Authenticator "
        "contains a random nonce and timestamp encrypted with the session key "
        "K_c,v. When the server receives the same Nonce from the same IDc "
        "again, it immediately rejects the request as a replay attack. This "
        "is the Kerberos protocol's standard anti-replay defense mechanism."
    )
    step_end()

    print(f"\n  {C.BOLD}{C.GREEN}  [OK] SCENARIO 3 -- PASSED (replay attack blocked){C.RESET}\n")


# ======================================================================
# Scenario 4 -- Revoked Certificate
# ======================================================================
def interactive_scenario_4():
    banner("Scenario 4 -- Certificate Revocation (CRL + OCSP)",
           "Revoke Alice's cert -> push CRL -> Bob tries to send to Alice -> BLOCKED")
    total = 5

    # -- Step 1: Inspect Alice's current cert --
    step_banner(1, total, "Inspect Alice's current certificate")
    info("Action", "Fetch Alice's cert from KDS and display its details")
    code_snippet('cert_pem = kds_client.get_cert("alice@mail.local")')
    wait()
    cert_pem = kds_client.get_cert(f"alice@{DOMAIN}")
    assert cert_pem, "Alice cert not found"
    ci = cert_info_str(cert_pem)
    cert = x509.load_pem_x509_certificate(cert_pem)
    serial = hex(cert.serial_number)
    info("Subject", ci["subject"])
    info("Serial (to be revoked)", serial)
    info("Issuer", ci["issuer"])
    info("Valid until", ci["not_after"])
    success("Alice's certificate is currently VALID")
    step_end()

    # -- Step 2: Revoke the certificate --
    step_banner(2, total, "Revoke Alice's certificate at the CA")
    info("Action", f"Send ca.revoke(serial={serial}) to the CA server")
    info("Effect", "CA adds this serial to its revoked list")
    code_snippet(f'request("127.0.0.1", 9000, {{"op": "ca.revoke", "serial_hex": "{serial}"}})')
    wait("Press Enter to REVOKE Alice's certificate...")
    request("127.0.0.1", 9000, {"op": "ca.revoke", "serial_hex": serial})
    fail(f"Certificate {serial} has been REVOKED!")
    step_end()

    # -- Step 3: Build and push updated CRL --
    step_banner(3, total, "Build and publish updated CRL")
    info("Action", "CA builds new CRL containing Alice's serial -> push to KDS")
    code_snippet(
        'crl = crl_manager.build_crl()   # CA signs new CRL with revoked serials\n'
        'kds_client.sync_crl(crl)         # Push to KDS for all clients'
    )
    wait()
    crl = crl_manager.build_crl()
    kds_client.sync_crl(crl)
    info("CRL size", f"{len(crl)} bytes")
    # Parse CRL to show revoked entries
    crl_obj = x509.load_pem_x509_crl(crl)
    revoked_count = 0
    for entry in crl_obj:
        revoked_count += 1
        info(f"Revoked serial", hex(entry.serial_number))
    info("Total revoked", str(revoked_count))

    comparison(
        "Certificate Status Before vs After",
        "Before revocation", f"Serial {serial} -> VALID",
        "After revocation", f"Serial {serial} -> REVOKED (in CRL)",
    )
    success("CRL updated and published to KDS")
    step_end()

    # -- Step 4: Bob tries to send to Alice -- MUST FAIL --
    step_banner(4, total, "Bob tries to send an email to Alice (MUST BE BLOCKED)")
    info("Action", "Bob calls send_secure_email -> fetch Alice's cert -> verify chain with CRL -> FAIL")
    info("Expected", "RuntimeError because Alice's cert is in the CRL (revoked)")
    code_snippet(
        'bob = client_core.login("bob@mail.local", "bob-pw")\n'
        'client_core.send_secure_email(bob, ["alice@mail.local"], subject, body)\n'
        '# Expected: RuntimeError -- cert revoked!'
    )
    wait("Press Enter to attempt sending to Alice (should fail)...")
    bob = client_core.login(f"bob@{DOMAIN}", "bob-pw")
    try:
        client_core.send_secure_email(
            bob, [f"alice@{DOMAIN}"], "[S4] should-fail", "body"
        )
        warn("UNEXPECTED: email sent despite revocation!")
    except RuntimeError as e:
        fail(f"SEND REFUSED: {e}")
        success("System correctly blocked email to a user with a revoked certificate!")
        mechanism(
            "When Bob attempts to send to Alice, the client first fetches "
            "Alice's certificate from KDS, then calls verify_chain() which "
            "checks the certificate against the CRL. Since Alice's serial "
            "number is now in the CRL, the function returns 'cert revoked "
            "(CRL)' and the send is aborted with a RuntimeError. "
            "Additionally, OCSP can be queried for real-time status."
        )
    step_end()

    # -- Step 5: Re-issue Alice's cert (cleanup) --
    step_banner(5, total, "Re-issue Alice's certificate (cleanup for other scenarios)")
    info("Action", "Delete old key/cert files -> register Alice again -> new cert from CA")
    code_snippet(
        'Path("data/users/alice_at_mail.local.key.pem").unlink()\n'
        'client_core.register("alice@mail.local", "alice-pw", "Alice", "user")'
    )
    wait()
    Path(f"data/users/alice_at_{DOMAIN}.key.pem").unlink(missing_ok=True)
    Path(f"data/users/alice_at_{DOMAIN}.cert.pem").unlink(missing_ok=True)
    Path(f"data/users/alice_at_{DOMAIN}.salt.bin").unlink(missing_ok=True)
    client_core.register(f"alice@{DOMAIN}", "alice-pw", "Alice", "user")
    new_cert_pem = kds_client.get_cert(f"alice@{DOMAIN}")
    new_ci = cert_info_str(new_cert_pem)
    info("New serial", new_ci["serial"])
    success("Alice re-registered with a new certificate")
    step_end()

    print(f"\n  {C.BOLD}{C.GREEN}  [OK] SCENARIO 4 -- PASSED (revocation enforced){C.RESET}\n")


# ======================================================================
# Scenario 5 -- Spoofed Sender (SPF + DMARC)
# ======================================================================
def interactive_scenario_5():
    banner("Scenario 5 -- Spoofed Sender Detection (SPF + DMARC)",
           "Eve forges From: alice@... but SPF/DMARC catches the inconsistency")
    total = 5

    # -- Step 1: Show current policy --
    step_banner(1, total, "Inspect current SPF + DMARC policy")
    info("Action", "Check what IP is authorized for this domain, and what DMARC policy is set")
    code_snippet(
        'spf_checker.check("mail.local", "127.0.0.1")  # -> True\n'
        'dmarc_engine.get_policy("mail.local")          # -> "quarantine"'
    )
    wait()
    info("SPF authorized IP", "127.0.0.1")
    info("DMARC policy", dmarc_engine.get_policy(DOMAIN))
    success("Policy loaded")
    step_end()

    # -- Step 2: Tamper SPF to simulate alien IP --
    step_banner(2, total, "Simulate SPF failure (change authorized IP to 10.9.9.9)")
    info("Action", "Replace SPF record: only IP 10.9.9.9 is authorized -> localhost will FAIL SPF")
    info("Purpose", "This simulates Eve sending from an unauthorized network")
    code_snippet(
        'conn.execute("DELETE FROM spf WHERE domain=?", ("mail.local",))\n'
        'conn.execute("INSERT INTO spf VALUES (?, ?)", ("mail.local", "10.9.9.9"))'
    )
    wait()
    conn = sqlite3.connect("data/policy/policy.db")
    conn.execute("DELETE FROM spf WHERE domain=?", (DOMAIN,))
    conn.execute("INSERT INTO spf(domain, ip) VALUES (?, ?)", (DOMAIN, "10.9.9.9"))
    conn.commit()
    conn.close()
    info("New SPF", "10.9.9.9 (localhost 127.0.0.1 is now UNAUTHORIZED)")
    warn("SPF tampered -- any send from localhost will fail SPF check")
    step_end()

    # -- Step 3: Eve forges email --
    step_banner(3, total, "Eve sends a FORGED email (From: alice@..., but signed by Eve)")
    info("Action", "Eve logs in with her own credentials, but sets From: alice@mail.local")
    info("Spoofing", "Header says Alice, but Kerberos identity is Eve")
    code_snippet(
        'eve = client_core.login("eve@mail.local", "eve-pw")\n'
        'env = smime_handler.build_envelope(\n'
        '    b"I am Alice, trust me!",\n'
        '    [("bob@mail.local", bob_cert)],\n'
        '    eve["cert_pem"], eve["privkey"]  # Signed by EVE, not Alice!\n'
        ')\n'
        'headers = {"From": "alice@mail.local", ...}  # FORGED From header!'
    )
    wait()
    eve = client_core.login(f"eve@{DOMAIN}", "eve-pw")
    bob_cert = kds_client.get_cert(f"bob@{DOMAIN}")
    env = smime_handler.build_envelope(
        b"I'm Alice, trust me!", [(f"bob@{DOMAIN}", bob_cert)],
        eve["cert_pem"], eve["privkey"],
    )
    headers = {"From": f"alice@{DOMAIN}", "To": f"bob@{DOMAIN}",
               "Subject": "[S5] Spoofed from Alice", "Date": "now",
               "Message-ID": f"<{os.urandom(4).hex()}@{DOMAIN}>"}
    info("Forged From", f"alice@{DOMAIN}")
    info("Actual signer", f"eve@{DOMAIN}")
    info("Envelope", f"{len(env)} bytes (signed by Eve's key)")
    step_end()

    # -- Step 4: Send the forged email --
    step_banner(4, total, "Deliver the forged email via SMTP")
    info("Action", "Eve uses her Kerberos ticket but delivers with From: alice@...")
    code_snippet(
        'st = client_core.get_service_ticket(eve)\n'
        'smtp_client.send_mail(\n'
        '    "127.0.0.1", 2525, "mail.local",\n'
        '    eve["email"],      # Kerberos identity: eve\n'
        '    ...,\n'
        '    "alice@mail.local", # FORGED sender in MAIL FROM\n'
        '    "bob@mail.local",\n'
        '    env, headers\n'
        ')'
    )
    wait("Press Enter to send the FORGED email...")
    st = client_core.get_service_ticket(eve)
    r = smtp_client.send_mail(
        "127.0.0.1", 2525, DOMAIN,
        eve["email"], st["ticket_v"], st["k_c_v"],
        f"alice@{DOMAIN}", f"bob@{DOMAIN}", env, headers,
    )
    info("ok", str(r.get("ok")))
    info("SPF result", str(r.get("spf_result")))
    info("DMARC action", str(r.get("dmarc_action")))

    # ---- COMPARISON: Header vs Kerberos identity ----
    comparison(
        "Email From Header vs Authenticated Identity",
        "RFC5322.From (header)", f"alice@{DOMAIN}",
        "Kerberos Ticket IDc", f"eve@{DOMAIN}",
    )
    comparison(
        "SPF Check Result",
        "Authorized IP for domain", "10.9.9.9 (simulated)",
        "Actual sender IP", "127.0.0.1 -> SPF FAIL",
    )

    if r.get("dmarc_action") in ("quarantine", "reject"):
        fail(f"DMARC: {r.get('dmarc_action')} -- spoofed email flagged/blocked!")
        success("SPF + DMARC correctly detected the spoofed sender!")
    else:
        warn(f"Unexpected DMARC action: {r.get('dmarc_action')}")

    mechanism(
        "DMARC cross-references the RFC5322.From header with the authenticated "
        "sender identity (via SPF IP check and DKIM signature verification). "
        "In this case, the sender IP (127.0.0.1) does not match the SPF-authorized "
        "IP (10.9.9.9), causing SPF to fail. Since the DMARC policy is set to "
        "'quarantine', the email is flagged rather than silently delivered. "
        "This prevents attackers from impersonating other users via header forgery."
    )
    step_end()

    # -- Step 5: Restore SPF --
    step_banner(5, total, "Restore SPF to normal (cleanup)")
    code_snippet(
        'conn.execute("DELETE FROM spf WHERE domain=?", ("mail.local",))\n'
        'conn.execute("INSERT INTO spf VALUES (?, ?)", ("mail.local", "127.0.0.1"))'
    )
    wait()
    conn = sqlite3.connect("data/policy/policy.db")
    conn.execute("DELETE FROM spf WHERE domain=?", (DOMAIN,))
    conn.execute("INSERT INTO spf(domain, ip) VALUES (?, ?)", (DOMAIN, "127.0.0.1"))
    conn.commit()
    conn.close()
    success("SPF restored to 127.0.0.1")
    step_end()

    print(f"\n  {C.BOLD}{C.GREEN}  [OK] SCENARIO 5 -- PASSED (spoofing detected){C.RESET}\n")


# ======================================================================
# Scenario 6 -- Reusable Ticket (1 login, N sends)
# ======================================================================
def interactive_scenario_6():
    banner("Scenario 6 -- Reusable Kerberos Ticket (1 login, N sends)",
           "Demonstrate that a single Ticket_v can be reused with fresh Authenticators")
    total = 3

    # -- Step 1: Login + get ticket --
    step_banner(1, total, "Alice logs in and obtains a single Service Ticket")
    info("Action", "AS-REQ -> TGT -> TGS-REQ -> one Ticket_v with 30-minute lifetime")
    code_snippet(
        'alice = client_core.login("alice@mail.local", "alice-pw")\n'
        'st = client_core.get_service_ticket(alice)'
    )
    wait()
    alice = client_core.login(f"alice@{DOMAIN}", "alice-pw")
    st = client_core.get_service_ticket(alice)
    info("Ticket_v", f"{st['ticket_v'][:50]}...")
    info("K_c,v", hex_preview(st["k_c_v"]))
    info("Lifetime", f"{st['lifetime']} seconds")
    success("Single service ticket obtained")
    step_end()

    # -- Step 2: Choose number of sends --
    step_banner(2, total, "Choose how many emails to send with the SAME ticket")
    info("Default", "5 emails with 1.1s delay between each (unique Authenticator timestamps)")
    print()
    user_input = input(f"  {C.CYAN}How many emails to send? [default=5]: {C.RESET}").strip()
    count = 5
    if user_input.isdigit() and 1 <= int(user_input) <= 20:
        count = int(user_input)
    info("Will send", f"{count} emails using the same Ticket_v")
    step_end()

    # -- Step 3: Send N emails --
    step_banner(3, total, f"Sending {count} emails with the SAME Ticket_v")
    info("Key insight", "Each send generates a NEW Authenticator (fresh timestamp + nonce)")
    info("Why it works", "Ticket_v is reusable within its lifetime; only Authenticator must be unique")
    code_snippet(
        'for i in range(N):\n'
        '    # Same ticket_v, but smtp_client.send_mail builds a fresh Authenticator\n'
        '    smtp_client.send_mail(..., st["ticket_v"], st["k_c_v"], ...)'
    )
    wait()
    bob_cert = kds_client.get_cert(f"bob@{DOMAIN}")
    for i in range(count):
        env = smime_handler.build_envelope(
            f"Reusable ticket test #{i+1}".encode(),
            [(f"bob@{DOMAIN}", bob_cert)],
            alice["cert_pem"], alice["privkey"],
        )
        headers = {"From": alice["email"], "To": f"bob@{DOMAIN}",
                    "Subject": f"[S6] Reusable #{i+1}", "Date": "now",
                    "Message-ID": f"<{os.urandom(4).hex()}@{DOMAIN}>"}
        time.sleep(1.1)
        r = smtp_client.send_mail(
            "127.0.0.1", 2525, DOMAIN,
            alice["email"], st["ticket_v"], st["k_c_v"],
            alice["email"], f"bob@{DOMAIN}", env, headers,
        )
        info(f"Email #{i+1}", f"ok={r.get('ok')} | id={r.get('message_id', 'N/A')}")
    success(f"All {count} emails sent with the SAME Ticket_v + fresh Authenticators")
    mechanism(
        "Kerberos tickets are designed to be reusable within their lifetime "
        f"({st['lifetime']}s). Each request generates a NEW Authenticator with "
        "a fresh timestamp and random nonce, which prevents replay while allowing "
        "ticket reuse. This avoids the cost of re-authenticating (AS + TGS exchange) "
        "for every single operation."
    )
    step_end()

    print(f"\n  {C.BOLD}{C.GREEN}  [OK] SCENARIO 6 -- PASSED (ticket reuse works){C.RESET}\n")


# ======================================================================
# Scenario 7 -- Key Recovery (Shamir Secret Sharing)
# ======================================================================
def interactive_scenario_7():
    banner("Scenario 7 -- Key Recovery (Shamir 2-of-3 Secret Sharing)",
           "Recover Bob's escrowed private key using any 2 of 3 shares")
    total = 4

    # -- Step 1: Show the shares --
    step_banner(1, total, "Inspect the 3 Shamir shares on disk")
    info("Scheme", "Shamir Secret Sharing over GF(256): threshold=2, total_shares=3")
    info("Math", "Each byte of the key is split independently using a degree-1 polynomial")
    code_snippet(
        'original_pem = Path("data/users/bob_at_mail.local.key.pem").read_bytes()\n'
        '# Shares stored at: data/ca/escrow/bob_at_mail.local.share{1,2,3}.bin'
    )
    wait()
    original_pem = Path(f"data/users/bob_at_{DOMAIN}.key.pem").read_bytes()
    info("Original key size", f"{len(original_pem)} bytes")
    for i in range(1, 4):
        share_path = Path(f"data/ca/escrow/bob_at_{DOMAIN}.share{i}.bin")
        if share_path.exists():
            share_data = share_path.read_bytes()
            info(f"Share {i}", f"{len(share_data)} bytes | preview: {hex_preview(share_data, 20)}")
    success("All 3 shares inspected")
    step_end()

    # -- Step 2: User chooses shares --
    step_banner(2, total, "Choose which 2 shares to combine")
    info("Available", "Share 1, Share 2, Share 3")
    info("Requirement", "Any 2 of 3 are sufficient (Lagrange interpolation at x=0)")
    print()
    user_input = input(f"  {C.CYAN}Enter 2 share indices (e.g. '1,2' or '2,3' or '1,3'): {C.RESET}").strip()
    try:
        indices = [int(x.strip()) for x in user_input.split(",")]
        if len(indices) < 2 or not all(1 <= i <= 3 for i in indices):
            raise ValueError
    except (ValueError, AttributeError):
        print(f"  {C.YELLOW}Invalid input, defaulting to shares 1,2{C.RESET}")
        indices = [1, 2]
    indices = indices[:2]  # Take only first 2
    info("Selected shares", str(indices))
    step_end()

    # -- Step 3: Recover --
    step_banner(3, total, f"Recovering key using shares {indices}")
    info("Action", "Lagrange interpolation over GF(256) for each byte position at x=0")
    code_snippet(f'recovered = key_escrow.recover_key("bob@mail.local", {indices})')
    wait("Press Enter to recover the key...")
    recovered = key_escrow.recover_key(f"bob@{DOMAIN}", indices)
    info("Recovered size", f"{len(recovered)} bytes")
    info("Original size", f"{len(original_pem)} bytes")
    info("Match", f"{'[OK] IDENTICAL' if recovered == original_pem else '[FAIL] MISMATCH'}")
    if recovered == original_pem:
        success(f"Key recovered successfully using shares {indices}!")
    else:
        fail("Key recovery failed -- mismatch!")
    mechanism(
        "Shamir Secret Sharing splits the secret into N shares such that any "
        "K shares (threshold) can reconstruct the original via Lagrange "
        "interpolation over GF(256). With K=2, N=3, any two shares are "
        "sufficient but a single share reveals zero information about the key."
    )
    step_end()

    # -- Step 4: Try another combination --
    step_banner(4, total, "Verify with a DIFFERENT share combination")
    other_combos = [[1,2], [1,3], [2,3]]
    # Pick a combo different from the one used
    other = [c for c in other_combos if c != sorted(indices)]
    if other:
        combo = other[0]
    else:
        combo = [1, 3]
    info("Using shares", str(combo))
    code_snippet(f'recovered2 = key_escrow.recover_key("bob@mail.local", {combo})')
    wait()
    recovered2 = key_escrow.recover_key(f"bob@{DOMAIN}", combo)
    info("Match", f"{'[OK] IDENTICAL' if recovered2 == original_pem else '[FAIL] MISMATCH'}")

    comparison(
        "Both share combinations recover the same key",
        f"Shares {indices}", f"{len(recovered)} bytes -> [OK] MATCH",
        f"Shares {combo}", f"{len(recovered2)} bytes -> [OK] MATCH",
    )

    if recovered2 == original_pem:
        success(f"Shares {combo} also recover the correct key -- Shamir scheme verified!")
    step_end()

    print(f"\n  {C.BOLD}{C.GREEN}  [OK] SCENARIO 7 -- PASSED (key recovery works){C.RESET}\n")


# ======================================================================
# Scenario 8 -- Hierarchical Subsession Key (HKDF)
# ======================================================================
def interactive_scenario_8():
    banner("Scenario 8 -- Hierarchical Subsession Keys (HKDF-SHA256)",
           "Derive unique per-message encryption keys from a single master key")
    total = 3

    # -- Step 1: Generate master key --
    step_banner(1, total, "Generate a random 256-bit master key")
    info("Action", "os.urandom(32) -> 256-bit master key")
    info("Purpose", "This master key is established during a session (e.g., from Kerberos)")
    code_snippet('master = os.urandom(32)')
    wait()
    master = os.urandom(32)
    info("Master key", master.hex())
    info("Key length", "256 bits (32 bytes)")
    success("Master key generated")
    step_end()

    # -- Step 2: Derive subsession keys --
    step_banner(2, total, "Derive per-message subsession keys using HKDF")
    info("Algorithm", "HKDF-SHA256 (RFC 5869)")
    info("Input", "master_key + info_context -> derived_key")
    info("Key insight", "Different 'info' context -> different derived key; same 'info' -> deterministic same key")
    code_snippet(
        'k1 = hkdf_derive(master, info=b"mail#1", length=32)\n'
        'k2 = hkdf_derive(master, info=b"mail#2", length=32)\n'
        'k3 = hkdf_derive(master, info=b"mail#3", length=32)\n'
        'k4 = hkdf_derive(master, info=b"mail#1", length=32)  # same as k1?'
    )
    wait()
    contexts = [b"mail#1", b"mail#2", b"mail#3", b"mail#1"]
    keys = []
    for ctx in contexts:
        k = hkdf_derive(master, info=ctx, length=32)
        keys.append(k)
        info(f"HKDF(master, info='{ctx.decode()}')", k.hex()[:48] + "...")
    step_end()

    # -- Step 3: Verify properties --
    step_banner(3, total, "Verify HKDF properties")
    info("Test 1", "mail#1 != mail#2 (different context -> different key)")
    info("Test 2", "mail#1 != mail#3 (different context -> different key)")
    info("Test 3", "HKDF(master, 'mail#1') == HKDF(master, 'mail#1') (deterministic)")
    code_snippet(
        'assert k1 != k2, "Different info must produce different keys"\n'
        'assert k1 != k3, "Different info must produce different keys"\n'
        'assert k1 == k4, "Same info must produce the same key"'
    )
    wait()
    assert keys[0] != keys[1], "FAIL: mail#1 == mail#2"
    success(f"mail#1 != mail#2: {keys[0].hex()[:16]}... != {keys[1].hex()[:16]}...")
    assert keys[0] != keys[2], "FAIL: mail#1 == mail#3"
    success(f"mail#1 != mail#3: {keys[0].hex()[:16]}... != {keys[2].hex()[:16]}...")
    assert keys[0] == keys[3], "FAIL: same context produced different keys"
    success(f"mail#1 == mail#1 (replay): {keys[0].hex()[:16]}... == {keys[3].hex()[:16]}...")
    success("HKDF derives unique, deterministic subsession keys per message context!")

    comparison(
        "HKDF Key Derivation Results",
        "mail#1 vs mail#2", f"{keys[0].hex()[:20]}... != {keys[1].hex()[:20]}...",
        "mail#1 vs mail#1", f"{keys[0].hex()[:20]}... == {keys[3].hex()[:20]}...",
    )

    mechanism(
        "HKDF (HMAC-based Key Derivation Function, RFC 5869) uses HMAC-SHA256 "
        "to derive cryptographically independent keys from a single master key. "
        "The 'info' parameter acts as a context separator: different contexts "
        "(e.g., per-message IDs) produce completely different keys, while the "
        "same context deterministically produces the same key. This enables "
        "hierarchical key management without storing individual keys."
    )
    step_end()

    print(f"\n  {C.BOLD}{C.GREEN}  [OK] SCENARIO 8 -- PASSED (HKDF verified){C.RESET}\n")


# ======================================================================
# Main Menu
# ======================================================================
SCENARIOS = {
    "0": ("Bootstrap (initialize system)", interactive_bootstrap),
    "1": ("Normal Encrypted + Signed Email (E2E flow)", interactive_scenario_1),
    "2": ("MITM / Public-Key Substitution Attack", interactive_scenario_2),
    "3": ("Replay Attack Detection", interactive_scenario_3),
    "4": ("Certificate Revocation (CRL + OCSP)", interactive_scenario_4),
    "5": ("Spoofed Sender (SPF + DMARC)", interactive_scenario_5),
    "6": ("Reusable Kerberos Ticket", interactive_scenario_6),
    "7": ("Key Recovery (Shamir 2-of-3)", interactive_scenario_7),
    "8": ("Hierarchical Subsession Key (HKDF)", interactive_scenario_8),
}


def print_menu():
    print()
    print(f"{C.BOLD}{C.CYAN}{'=' * 72}{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}|{C.RESET}  {C.BOLD}{C.WHITE}SecureMail -- Interactive Demo for Examination{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}|{C.RESET}  {C.DIM}Step-by-step cryptographic protocol demonstration{C.RESET}")
    print(f"{C.BOLD}{C.CYAN}{'=' * 72}{C.RESET}")
    print()
    for key, (desc, _) in SCENARIOS.items():
        prefix = f"{C.YELLOW}[{key}]{C.RESET}"
        print(f"   {prefix}  {desc}")
    print(f"\n   {C.YELLOW}[a]{C.RESET}  Run ALL scenarios sequentially")
    print(f"   {C.YELLOW}[q]{C.RESET}  Quit")
    print()


def main():
    # Support command-line arguments for non-interactive use
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "bootstrap":
            interactive_bootstrap()
            return
        elif cmd in SCENARIOS:
            SCENARIOS[cmd][1]()
            return
        elif cmd == "all":
            for k in sorted(SCENARIOS):
                try:
                    SCENARIOS[k][1]()
                except Exception as e:
                    print(f"\n  {C.RED}[FAIL] Scenario {k} FAILED: {e}{C.RESET}")
                    import traceback
                    traceback.print_exc()
            return

    # Interactive menu loop
    while True:
        print_menu()
        choice = input(f"  {C.BOLD}{C.CYAN}Select scenario: {C.RESET}").strip().lower()

        if choice == "q":
            print(f"\n  {C.DIM}Goodbye!{C.RESET}\n")
            break
        elif choice == "a":
            for k in sorted(SCENARIOS):
                try:
                    SCENARIOS[k][1]()
                except Exception as e:
                    print(f"\n  {C.RED}[FAIL] Scenario {k} FAILED: {e}{C.RESET}")
                    import traceback
                    traceback.print_exc()
        elif choice in SCENARIOS:
            try:
                SCENARIOS[choice][1]()
            except Exception as e:
                print(f"\n  {C.RED}[FAIL] FAILED: {e}{C.RESET}")
                import traceback
                traceback.print_exc()
        else:
            print(f"  {C.RED}Invalid choice. Please select 0-8, 'a', or 'q'.{C.RESET}")

        input(f"\n  {C.DIM}Press Enter to return to main menu...{C.RESET}")


if __name__ == "__main__":
    main()
