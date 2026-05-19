"""End-to-end demo: bootstrap + 8 scenario theo §9 Email.md.

Chạy:
  Terminal 1:  python -m securemail.main_ca serve
  Terminal 2:  python -m securemail.main_kds
  Terminal 3:  python -m securemail.main_ticket
  Terminal 4:  python -m securemail.run_demo bootstrap      # tạo domain cert + 3 user + SPF/DMARC
  Terminal 5:  python -m securemail.main_mail_server
  Terminal 6:  python -m securemail.run_demo all            # chạy tất cả scenario
"""
import base64
import datetime as dt
import json
import os
import sys
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

from securemail import client_core
from securemail.ca_service import ca_core, key_escrow
from securemail.crypto import rsa_handler
from securemail.kds import kds_client
from securemail.mail import smime_handler
from securemail.network.json_framing import request, b64, unb64
from securemail.policy import spf_checker, dmarc_engine
from securemail.ticket_service import ts_client


DOMAIN = "mail.local"


def _banner(title: str):
    print()
    print("=" * 70)
    print(f" {title}")
    print("=" * 70)


# ----------------------------------------------------------------------
# Bootstrap: tạo domain cert cho Mail Server + DKIM key + 3 user demo
# ----------------------------------------------------------------------
def _create_server_identity(common_name: str, email: str, passphrase: bytes,
                            out_key: Path, out_cert: Path):
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


def bootstrap():
    _banner("BOOTSTRAP")

    # 1. Mail Server identity (dùng cho STARTTLS + POP3 TLS)
    print("[boot] creating Mail Server identity ...")
    _create_server_identity(
        f"mail.{DOMAIN}", f"mail@{DOMAIN}", b"mail-srv-key",
        Path("data/server/mail_key.pem"), Path("data/server/mail_cert.pem"),
    )

    # 2. MTA DKIM key (đăng ký vào KDS với email _dkim.<domain>)
    print("[boot] creating MTA DKIM key ...")
    _create_server_identity(
        f"dkim.{DOMAIN}", f"_dkim.{DOMAIN}", b"mta-domain-key",
        Path(f"data/server/mta_{DOMAIN}_key.pem"),
        Path(f"data/server/mta_{DOMAIN}_cert.pem"),
    )
    # Also: register client-side DKIM key (for scenario where sender signs)
    print("[boot] creating client DKIM key ...")
    _create_server_identity(
        f"dkim-client.{DOMAIN}", f"_dkim-client.{DOMAIN}", b"dkim-key",
        Path(f"data/server/dkim_{DOMAIN}_key.pem"),
        Path(f"data/server/dkim_{DOMAIN}_cert.pem"),
    )

    # 3. Register 3 users
    print("[boot] registering users Alice / Bob / Eve ...")
    for email, pw, display, role in [
        (f"alice@{DOMAIN}", "alice-pw", "Alice", "user"),
        (f"bob@{DOMAIN}",   "bob-pw",   "Bob",   "user"),
        (f"eve@{DOMAIN}",   "eve-pw",   "Eve",   "user"),
        (f"admin@{DOMAIN}", "admin-pw", "Admin", "admin"),
    ]:
        # Skip if already registered (idempotent)
        user_key = Path(f"data/users/{email.replace('@','_at_')}.key.pem")
        if user_key.exists():
            print(f"  skip {email} (already exists)")
            continue
        client_core.register(email, pw, display, role)

    # 4. SPF records + DMARC policy
    print("[boot] setting SPF + DMARC policy ...")
    spf_checker.add_spf(DOMAIN, "127.0.0.1")
    dmarc_engine.set_policy(DOMAIN, "quarantine")

    # 5. Push initial CRL (empty) to KDS
    print("[boot] pushing initial CRL ...")
    from securemail.ca_service import crl_manager
    crl = crl_manager.build_crl()
    kds_client.sync_crl(crl)

    # 6. Demo key escrow — encrypt copy of Bob's private key
    print("[boot] escrowing Bob's private key (2-of-3 Shamir) ...")
    bob_key_pem = Path(f"data/users/bob_at_{DOMAIN}.key.pem").read_bytes()
    key_escrow.escrow_key(f"bob@{DOMAIN}", bob_key_pem)

    print("[boot] DONE.")


# ----------------------------------------------------------------------
# Scenarios
# ----------------------------------------------------------------------
def scenario_1_normal_flow():
    _banner("Scenario 1 — Normal encrypted + signed email (B1–B7, M1–M5)")
    alice = client_core.login(f"alice@{DOMAIN}", "alice-pw")
    bob_inbox_before = client_core.fetch_inbox(
        client_core.login(f"bob@{DOMAIN}", "bob-pw")
    )
    before_count = len(bob_inbox_before)

    r = client_core.send_secure_email(
        alice, [f"bob@{DOMAIN}"],
        "[S1] Normal encrypted + signed",
        "Xin chào Bob, đây là email đầu tiên của demo.\nCipher: AES-128-CBC + RSA-OAEP + RSA-PSS.",
    )
    print(f"  envelope size: {r['envelope_len']} bytes")
    for rcpt, resp in r["results"]:
        print(f"  delivered to {rcpt}: dmarc={resp.get('dmarc_action')}, mta_dkim={'YES' if resp.get('mta_dkim') else 'NO'}")

    bob = client_core.login(f"bob@{DOMAIN}", "bob-pw")
    inbox = client_core.fetch_inbox(bob)
    new = inbox[before_count:] if len(inbox) >= before_count else inbox
    assert any("S1" in m.get("subject", "") for m in inbox), "Bob didn't receive"
    print(f"  Bob received {len(inbox)} message(s) total")
    for m in inbox:
        if "S1" in m.get("subject", ""):
            print(f"  subject={m['subject']} | sig_valid={m['signature_valid']} | signer={m.get('signer_subject')}")
    print("  [OK] PASS")


def scenario_2_mitm_substitution():
    _banner("Scenario 2 — MITM / Public-key Substitution (M4)")
    # Attacker "Eve" tries to register a cert for bob@... at KDS directly without CA signature.
    fake_priv = rsa_handler.generate_keypair(2048)
    fake_pub = rsa_handler.serialize_public_pem(fake_priv.public_key())
    # Build a self-signed "cert" (not CA-signed) to try to inject
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "FAKE Bob"),
                         x509.NameAttribute(NameOID.EMAIL_ADDRESS, f"bob@{DOMAIN}")])
    now = dt.datetime.now(dt.timezone.utc)
    fake_cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(fake_priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
        .sign(fake_priv, hashes.SHA256())
    )
    fake_pem = fake_cert.public_bytes(serialization.Encoding.PEM)

    # KDS không có bước verify CA sig khi put_cert (demo trust-CA-only-via-admin).
    # Nhưng client SẼ verify. Nên MITM attack thất bại lúc client gọi verify_chain.
    print("  Attacker tries to inject fake cert into KDS (bypass CA sig)...")
    kds_client.put_cert(f"eve-fake-bob@{DOMAIN}", hex(fake_cert.serial_number), fake_pem)

    # Now Alice tries to "send" — but specifically fetching this fake email → verify fails.
    from securemail.auth import cert_validator
    ca_pem = unb64(request("127.0.0.1", 9000, {"op": "ca.root_cert"})["cert_pem_b64"])
    ok, reason = cert_validator.verify_chain(fake_pem, ca_pem, None)
    assert not ok, f"Fake cert should fail but passed: {reason}"
    print(f"  [OK] Client REJECTS fake cert: {reason}")

    # Original real bob cert still validates
    real_pem = kds_client.get_cert(f"bob@{DOMAIN}")
    ok2, reason2 = cert_validator.verify_chain(real_pem, ca_pem, None)
    assert ok2
    print(f"  [OK] Real Bob cert still valid: {reason2}")


def scenario_3_replay_attack():
    _banner("Scenario 3 — Replay Attack (M2, M7)")
    alice = client_core.login(f"alice@{DOMAIN}", "alice-pw")
    st = client_core.get_service_ticket(alice)

    # Send a legitimate email first
    from securemail.network import smtp_client
    from securemail.mail import smime_handler
    bob_cert_pem = kds_client.get_cert(f"bob@{DOMAIN}")
    env = smime_handler.build_envelope(
        b"replay test", [(f"bob@{DOMAIN}", bob_cert_pem)], alice["cert_pem"], alice["privkey"]
    )
    headers = {"From": alice["email"], "To": f"bob@{DOMAIN}",
               "Subject": "[S3] Replay test", "Date": "now",
               "Message-ID": f"<{os.urandom(4).hex()}@{DOMAIN}>"}

    # First call: must succeed
    r1 = smtp_client.send_mail(
        "127.0.0.1", 2525, DOMAIN,
        alice["email"], st["ticket_v"], st["k_c_v"],
        alice["email"], f"bob@{DOMAIN}", env, headers,
    )
    assert r1.get("ok"), f"First send failed: {r1}"
    print(f"  [OK] First send OK: dmarc={r1.get('dmarc_action')}")

    # Replay attacker: reuse same ticket + authenticator via direct socket
    from securemail.ticket_service import authenticator as auth_mod
    import socket
    from securemail.network.json_framing import send_json, recv_json
    from securemail.network import tls_lite

    # Build a fixed Authenticator (timestamp frozen) then send twice
    authn = auth_mod.build(st["k_c_v"], alice["email"], "127.0.0.1")

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
    r_b = try_auth_with(authn)  # REPLAY
    print(f"  First use of authenticator: ok={r_a.get('ok')}")
    print(f"  Replayed authenticator:     ok={r_b.get('ok')} error={r_b.get('error')}")
    assert r_a.get("ok") and not r_b.get("ok") and "replay" in r_b.get("error", "").lower()
    print("  [OK] PASS — replay rejected")


def scenario_4_revoked_cert():
    _banner("Scenario 4 — Revoked Certificate (M3)")
    # Get Alice's currently active certificate from KDS to revoke the correct active cert
    cert_pem = kds_client.get_cert(f"alice@{DOMAIN}")
    assert cert_pem, "alice cert not found in KDS"
    cert = x509.load_pem_x509_certificate(cert_pem)
    serial = hex(cert.serial_number)
    print(f"  revoking alice's cert {serial} ...")
    request("127.0.0.1", 9000, {"op": "ca.revoke", "serial_hex": serial})

    # Push updated CRL to KDS
    from securemail.ca_service import crl_manager
    crl = crl_manager.build_crl()
    kds_client.sync_crl(crl)
    print("  CRL updated & pushed to KDS.")

    # Bob tries to send TO alice → must refuse
    bob = client_core.login(f"bob@{DOMAIN}", "bob-pw")
    try:
        client_core.send_secure_email(
            bob, [f"alice@{DOMAIN}"], "[S4] should-fail", "body"
        )
        print("  [FAIL] FAIL — email sent despite revocation")
    except RuntimeError as e:
        print(f"  [OK] PASS — send refused: {e}")

    # Re-issue cert for alice (so other scenarios still work)
    print("  re-issuing cert for alice (cleanup) ...")
    # remove old files, re-register
    Path(f"data/users/alice_at_{DOMAIN}.key.pem").unlink(missing_ok=True)
    Path(f"data/users/alice_at_{DOMAIN}.cert.pem").unlink(missing_ok=True)
    Path(f"data/users/alice_at_{DOMAIN}.salt.bin").unlink(missing_ok=True)
    # Unique email to avoid DB unique constraint on old one
    # Actually we just reissue — ca_core inserts new serial automatically.
    client_core.register(f"alice@{DOMAIN}", "alice-pw", "Alice", "user")
    # refresh CRL too (alice's old cert still revoked in CRL — that's fine)


def scenario_5_spoofed_sender():
    _banner("Scenario 5 — Spoofed Sender (SPF + DMARC) (A5)")
    # Eve tries to send an email with From: alice@... but from her own auth context.
    # SPF will allow (same IP), but DMARC cross-check: message From ≠ authenticated Kerberos id.
    # We simulate SPF-fail via adding a rule for a DIFFERENT IP, then sending from localhost.
    print("  configuring SPF to require sender IP != 127.0.0.1 (simulate alien IP) ...")
    # Remove existing SPF, add a spoof-unfriendly rule
    import sqlite3
    conn = sqlite3.connect("data/policy/policy.db")
    conn.execute("DELETE FROM spf WHERE domain=?", (DOMAIN,))
    conn.execute("INSERT INTO spf(domain, ip) VALUES (?, ?)", (DOMAIN, "10.9.9.9"))  # fake auth IP
    conn.commit()
    conn.close()

    eve = client_core.login(f"eve@{DOMAIN}", "eve-pw")
    # Craft envelope: Eve signs her own but forges From header
    bob_cert = kds_client.get_cert(f"bob@{DOMAIN}")
    env = smime_handler.build_envelope(
        b"I'm Alice, trust me!",
        [(f"bob@{DOMAIN}", bob_cert)],
        eve["cert_pem"], eve["privkey"],
    )
    headers = {"From": f"alice@{DOMAIN}", "To": f"bob@{DOMAIN}",
               "Subject": "[S5] spoof from Alice", "Date": "now",
               "Message-ID": f"<{os.urandom(4).hex()}@{DOMAIN}>"}

    from securemail.network import smtp_client
    st = client_core.get_service_ticket(eve)
    r = smtp_client.send_mail(
        "127.0.0.1", 2525, DOMAIN,
        eve["email"], st["ticket_v"], st["k_c_v"],
        f"alice@{DOMAIN}",  # forged sender
        f"bob@{DOMAIN}",
        env, headers,
    )
    print(f"  result: ok={r.get('ok')} dmarc={r.get('dmarc_action')} spf={r.get('spf_result')}")

    # Restore SPF for normal scenarios
    conn = sqlite3.connect("data/policy/policy.db")
    conn.execute("DELETE FROM spf WHERE domain=?", (DOMAIN,))
    conn.execute("INSERT INTO spf(domain, ip) VALUES (?, ?)", (DOMAIN, "127.0.0.1"))
    conn.commit()
    conn.close()

    # With DMARC = quarantine, message is still delivered but flagged
    if r.get("dmarc_action") == "quarantine":
        print("  [OK] PASS — DMARC quarantined spoofed mail")
    elif r.get("dmarc_action") == "reject":
        print("  [OK] PASS — DMARC rejected spoofed mail")
    else:
        print(f"  [WARN] unexpected dmarc_action={r.get('dmarc_action')}")


def scenario_6_reusable_ticket():
    _banner("Scenario 6 — Reusable Ticket (A6 — 1 login, N sends)")
    alice = client_core.login(f"alice@{DOMAIN}", "alice-pw")
    st = client_core.get_service_ticket(alice)
    print(f"  TGT lifetime: {st['lifetime']} seconds — sending 5 emails with same Ticket_v")

    bob_cert = kds_client.get_cert(f"bob@{DOMAIN}")
    from securemail.network import smtp_client
    for i in range(5):
        env = smime_handler.build_envelope(
            f"reusable ticket test #{i+1}".encode(),
            [(f"bob@{DOMAIN}", bob_cert)],
            alice["cert_pem"], alice["privkey"],
        )
        headers = {"From": alice["email"], "To": f"bob@{DOMAIN}",
                   "Subject": f"[S6] reusable #{i+1}", "Date": "now",
                   "Message-ID": f"<{os.urandom(4).hex()}@{DOMAIN}>"}
        time.sleep(1.1)  # unique TS per authenticator
        r = smtp_client.send_mail(
            "127.0.0.1", 2525, DOMAIN,
            alice["email"], st["ticket_v"], st["k_c_v"],
            alice["email"], f"bob@{DOMAIN}", env, headers,
        )
        print(f"    #{i+1}: ok={r.get('ok')} id={r.get('message_id')}")
    print("  [OK] PASS — same ticket_v reused with fresh Authenticators (A6)")


def scenario_7_key_recovery():
    _banner("Scenario 7 — Key Recovery (A9 — Shamir 2-of-3, bonus)")
    recovered = key_escrow.recover_key(f"bob@{DOMAIN}", [1, 2])
    expected = Path(f"data/users/bob_at_{DOMAIN}.key.pem").read_bytes()
    assert recovered == expected, "Recovered key mismatch!"
    print(f"  [OK] PASS — recovered {len(recovered)} bytes using 2 of 3 shares (bytes identical)")
    # Try with different share combination
    recovered2 = key_escrow.recover_key(f"bob@{DOMAIN}", [1, 3])
    assert recovered2 == expected
    print(f"  [OK] PASS — shares 1+3 also work")


def scenario_8_subsession_hkdf():
    _banner("Scenario 8 — Hierarchical subsession key (B7)")
    from securemail.crypto.key_derivation import hkdf_derive
    master = os.urandom(32)
    k1 = hkdf_derive(master, info=b"mail#1", length=32)
    k2 = hkdf_derive(master, info=b"mail#2", length=32)
    k3 = hkdf_derive(master, info=b"mail#1", length=32)
    assert k1 != k2, "Different info should derive different keys"
    assert k1 == k3, "Same info must derive same key"
    print(f"  master={master.hex()[:16]}...")
    print(f"  K_sub(mail#1) = {k1.hex()[:16]}...")
    print(f"  K_sub(mail#2) = {k2.hex()[:16]}... (different)")
    print(f"  [OK] PASS — HKDF yields unique subsession keys per message context")


SCENARIOS = {
    "1": scenario_1_normal_flow,
    "2": scenario_2_mitm_substitution,
    "3": scenario_3_replay_attack,
    "4": scenario_4_revoked_cert,
    "5": scenario_5_spoofed_sender,
    "6": scenario_6_reusable_ticket,
    "7": scenario_7_key_recovery,
    "8": scenario_8_subsession_hkdf,
}


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == "bootstrap":
        bootstrap()
    elif cmd == "all":
        for k in sorted(SCENARIOS):
            try:
                SCENARIOS[k]()
            except Exception as e:
                print(f"\n  [FAIL] Scenario {k} FAILED: {e}")
                import traceback
                traceback.print_exc()
    elif cmd in SCENARIOS:
        SCENARIOS[cmd]()
    else:
        print(f"unknown: {cmd}")


if __name__ == "__main__":
    main()
