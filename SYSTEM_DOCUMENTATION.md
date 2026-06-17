# SecureMail — Complete System Documentation (v2.1)

> **Architecture: Dual Key Pair | S/MIME-lite | Kerberos-lite | PKI X.509v3**

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture Diagram](#2-architecture-diagram)
3. [Dual Key Pair Design](#3-dual-key-pair-design)
4. [Key Security Guarantees](#4-key-security-guarantees)
5. [User Registration Flow](#5-user-registration-flow)
6. [Login Flow](#6-login-flow)
7. [Send Email Flow](#7-send-email-flow)
8. [Receive Email Flow](#8-receive-email-flow)
9. [Key Recovery Flow](#9-key-recovery-flow)
10. [Kerberos-lite Authentication](#10-kerberos-lite-authentication)
11. [PKI / CA Service](#11-pki--ca-service)
12. [Key Distribution Server (KDS)](#12-key-distribution-server-kds)
13. [S/MIME Envelope Format](#13-smime-envelope-format)
14. [DKIM / SPF / DMARC](#14-dkim--spf--dmarc)
15. [Database Schema](#15-database-schema)
16. [Local File Structure](#16-local-file-structure)
17. [Cryptographic Algorithms](#17-cryptographic-algorithms)
18. [Security Properties](#18-security-properties)
19. [Threat Model](#19-threat-model)
20. [Limitations & Known Issues](#20-limitations--known-issues)
21. [Service Ports Reference](#21-service-ports-reference)

---

## 1. Overview

SecureMail is an internal mail system demonstrating enterprise-grade
cryptographic email security. It implements:

- **PKI X.509v3** — Root CA, CSR signing, CRL, OCSP-lite, key escrow
- **Dual Key Pairs** — Separate signing and encryption certificates per user
- **Kerberos-lite** — AS + TGS + Service ticket exchange with replay protection
- **S/MIME-lite** — EnvelopedData (AES-128-CBC + RSA-OAEP) + SignedData (RSA-PSS)
- **DKIM / SPF / DMARC** — Email authentication policy
- **STARTTLS-lite** — RSA-OAEP session key + AES-256-GCM framing
- **Shamir 2-of-3 Key Escrow** — Disaster recovery for encryption keys only

---

## 2. Architecture Diagram

```
┌────────────────────────────────────────────────────────────┐
│                    CA Service  (:9000)                     │
│  Root CA · sign CSR (sign|enc) · CRL · OCSP · Escrow      │
│  KeyUsage: sign={digitalSig,nonRepud}  enc={keyEnciph}     │
└─────────────────────┬──────────────────────────────────────┘
                      │ CA-signed certs pushed
                      ▼
┌──────────────────────────────────────────────────┐
│            Key Distribution Server  (:9001)      │
│  kds.certs table: (email, cert_type) composite PK│
│  cert_type ∈ {'sign', 'enc'}                     │
│  Ops: get_sign_cert / get_enc_cert / bulk / CRL  │
└───────────┬──────────────────────────────────────┘
            │ fetch enc_cert for CEK wrap
            │ fetch sign_cert for verify
            ▼
┌──────────────────────┐         ┌──────────────────────────┐
│  Ticket Service      │◄───────►│    Mail Client           │
│  (:9002)             │  AS+TGS │  sign_privkey → sign      │
│  AS: password→TGT    │  flow   │  enc_privkey  → decrypt   │
│  TGS: TGT→ST         │         │  sign_cert_pem → embed    │
│  Authenticator cache │         │  enc_cert_pem → fetch     │
└──────────────────────┘         └───────────┬──────────────┘
                                             │ SMTP (2525)
                                             ▼
                              ┌─────────────────────────────┐
                              │   Mail Server  (:2525/:1100) │
                              │  STARTTLS · S/MIME envelopes │
                              │  DKIM sign · SPF · DMARC     │
                              │  Mailbox: inbox / sent        │
                              └─────────────────────────────┘
```

---

## 3. Dual Key Pair Design

### Background

The previous single-keypair design violated a fundamental PKI principle:

- **Non-repudiation** requires that the signing key NEVER leave the device
  and NEVER be escrowed (otherwise, the CA or admin could forge signatures)
- **Key Recovery** requires that the encryption key CAN be escrowed
  (otherwise, loss of the local key = permanent loss of all old mail)

### Solution

Each user has **two RSA-2048 keypairs** with distinct X.509 KeyUsage extensions:

| Keypair | KeyUsage Extension | Escrowed? | Auto-recover? |
|---|---|---|---|
| **Signing** | `digitalSignature, contentCommitment` | ❌ Never | ❌ No — stays on device |
| **Encryption** | `keyEncipherment, dataEncipherment` | ✅ Shamir 2-of-3 | ✅ On login |

### Non-repudiation Guarantee

Because the signing key is generated locally and never exported to any server,
the CA and all administrators are cryptographically incapable of forging a
user's digital signature. This is the standard definition of non-repudiation
per RFC 5280.

### Key Recovery Capability

Because the encryption key is split into 3 Shamir shares stored in SQL Server,
it can be recovered by any authorized party using 2 of 3 shares. This allows:
- Disaster recovery (user lost their device)
- Compliance / legal hold requirements
- Cross-device login (user logs in from a new machine)

---

## 4. Key Security Guarantees

| Property | Mechanism | Strength |
|---|---|---|
| Confidentiality | AES-128-CBC + RSA-OAEP (CEK wrap) | 128-bit symmetric, 2048-bit RSA |
| Integrity | AES-CBC detects tampering via signature | MAC-then-Encrypt |
| Authenticity | RSA-PSS/SHA-256 signature on plaintext | Provably secure |
| Non-repudiation | Sign key never leaves device, never escrowed | RFC 5280 compliant |
| Key recovery | Shamir 2-of-3 escrow (enc key only) | Threshold secret sharing |
| Replay protection | Kerberos Authenticator nonce + 5-min window | 128-bit nonce |
| Cert revocation | CRL checked before every send | OCSP-lite via CA |
| Channel security | STARTTLS RSA-OAEP + AES-256-GCM | Ephemeral session key |
| Password storage | PBKDF2-HMAC-SHA256 (200k iterations) | NIST recommendation |
| Key derivation | HKDF-SHA256 for subsession keys | RFC 5869 |

---

## 5. User Registration Flow

```
Client                          CA (:9000)      KDS (:9001)    Ticket (:9002)
  │                               │                │               │
  │ 1. Generate sign_priv (RSA-2048)               │               │
  │ 2. Generate enc_priv  (RSA-2048)               │               │
  │ 3. Build CSR_sign                              │               │
  │ 4. Build CSR_enc                               │               │
  │                               │                │               │
  │──── ca.sign_csr(CSR_sign, key_usage='sign') ──►│               │
  │◄─── cert_pem (KeyUsage: digitalSig, nonRepud) ─┤               │
  │                               │                │               │
  │──── ca.sign_csr(CSR_enc, key_usage='enc') ────►│               │
  │◄─── cert_pem (KeyUsage: keyEncipherment) ───────┤               │
  │                               │                │               │
  │──── kds.put_cert(sign_cert, cert_type='sign') ─────────────►   │
  │──── kds.put_cert(enc_cert, cert_type='enc') ───────────────►   │
  │                               │                │               │
  │──── register principal (Kc from password) ─────────────────────►
  │                               │                │               │
  │ Save locally:                 │                │               │
  │   {email}.sign_key.pem  (password-encrypted)                   │
  │   {email}.sign_cert.pem                                        │
  │   {email}.enc_key.pem   (password-encrypted)                   │
  │   {email}.enc_cert.pem                                         │
  │   {email}.salt.bin                                             │
  │                               │                │               │
  │ Escrow enc_key ONLY:                                           │
  │   key_escrow.escrow_key(email, enc_priv_pem)                   │
  │   → 3 Shamir shares → ca.escrow_shares (SQL Server)            │
```

---

## 6. Login Flow

```
Client                         Ticket (:9002)   KDS (:9001)    Escrow (SQL)
  │                               │                │               │
  │──── AS-REQ (email, Kc) ───────►               │               │
  │◄─── TGT, K_c_tgs ─────────────┤               │               │
  │                               │                │               │
  │──── kds.get_sign_cert(email) ──────────────────►               │
  │◄─── sign_cert_pem ─────────────────────────────┤               │
  │──── kds.get_enc_cert(email) ───────────────────►               │
  │◄─── enc_cert_pem ──────────────────────────────┤               │
  │                               │                │               │
  │ Load sign_key from sign_key.pem                                 │
  │   If missing → key_status='sign_key_missing'                    │
  │   (NO auto-recovery — non-repudiation)                         │
  │                               │                │               │
  │ Load enc_key from enc_key.pem                                   │
  │   If missing or mismatch vs enc_cert → auto-recover:            │
  │──── recover_key(email, [1,2]) ─────────────────────────────────►
  │◄─── enc_priv_pem ──────────────────────────────────────────────┤
  │   Write recovered enc_key to enc_key.pem                        │
  │                               │                │               │
  │ Return ctx = {                                                  │
  │   sign_privkey, enc_privkey,                                    │
  │   sign_cert_pem, enc_cert_pem,                                  │
  │   privkey (alias), cert_pem (alias),                            │
  │   tgt, k_c_tgs, key_status                                      │
  │ }                                                               │
```

---

## 7. Send Email Flow

```
Sender Client                   KDS (:9001)  Ticket (:9002)  Mail (:2525)
    │                               │              │               │
    │ 1. Get recipient enc_cert                    │               │
    │──── kds.get_enc_cert(bob) ─────►             │               │
    │◄─── enc_cert_pem ──────────────┤             │               │
    │                               │              │               │
    │ 2. Validate cert chain (CA root + CRL)                       │
    │ 3. OCSP check (CA :9000)                                     │
    │                               │              │               │
    │ 4. Build S/MIME envelope:                                    │
    │    a. RSA-PSS sign plaintext with sign_privkey                │
    │    b. CEK = random AES-128 key                               │
    │    c. inner = JSON{body, sig, sign_cert}                     │
    │    d. (IV, CT) = AES-128-CBC(CEK, inner)                     │
    │    e. cek_enc = RSA-OAEP(bob.enc_pub, CEK)                   │
    │                               │              │               │
    │ 5. Build sender copy envelope with own enc_pub               │
    │                               │              │               │
    │ 6. Get Service Ticket                                        │
    │──── TGS-REQ (TGT, mail_srv) ──────────────►  │               │
    │◄─── ST (ticket_v, K_c_v) ─────────────────┤  │               │
    │                               │              │               │
    │ 7. SMTP send with STARTTLS                                   │
    │──── EHLO + STARTTLS ──────────────────────────────────────►  │
    │◄─── session key ─────────────────────────────────────────── │
    │──── AUTH (ticket_v, Authenticator) ──────────────────────►   │
    │──── DATA (envelope, sender_copy, headers) ────────────────►  │
    │◄─── ok + message_id ─────────────────────────────────────── │
```

---

## 8. Receive Email Flow

```
Recipient Client                               Mail (:1100)
    │                                               │
    │──── POP3 LIST + RETR (with Kerberos auth) ──►  │
    │◄─── encrypted envelope bytes ─────────────── │
    │                                               │
    │ 1. Find recipient block in envelope.recipients[]
    │ 2. CEK = RSA-OAEP decrypt(enc_privkey, cek_enc)
    │ 3. inner = AES-128-CBC decrypt(CEK, IV, CT)
    │ 4. body = inner['body_b64']
    │ 5. sig  = inner['sig_b64']
    │ 6. signer_cert = inner['signer_sign_cert_b64']  ← signing cert
    │ 7. RSA-PSS verify(signer_cert.pubkey, sig, body)
    │    → ok → SECURE label
    │    → fail → DANGEROUS label
    │                                               │
    │ 8. Display: body, from, security classification
```

---

## 9. Key Recovery Flow

```
Admin / User Client                           CA / Escrow (SQL Server)
    │                                               │
    │ Manual: Security tab → "Recover Encryption Key"
    │    OR   Automatic: login detects enc_key mismatch
    │                                               │
    │──── recover_key(email, shares=[1,2]) ────────►│
    │     (Lagrange interpolation over GF(256))      │
    │◄─── enc_priv_pem ────────────────────────────  │
    │                                               │
    │ Verify: enc_priv.pubkey == enc_cert.pubkey    │
    │   → write enc_key.pem to disk                 │
    │   → key_status = 'ok'                         │
    │                                               │
    │ Note: sign_key recovery is NOT supported       │
    │   sign_key missing → must re-register account  │
    │   (non-repudiation cannot be preserved after   │
    │    signing key exposure)                        │
```

---

## 10. Kerberos-lite Authentication

### AS Exchange (Authentication Service)

```
Client → AS:  {email, Kc}
AS     → Client: {
    TGT = {email, lifetime, K_c_tgs} encrypted with K_tgs,
    K_c_tgs encrypted with Kc
}
Kc = PBKDF2-HMAC-SHA256(password, salt, 200_000_iterations, 32_bytes)
```

### TGS Exchange (Ticket Granting Service)

```
Client → TGS: {TGT, Authenticator, service_id}
Authenticator = {email, timestamp, nonce_128} encrypted with K_c_tgs
TGS verifies: timestamp within ±5min, nonce not in replay cache
TGS → Client: {
    ST = {email, lifetime, K_c_v} encrypted with K_v (service key),
    K_c_v encrypted with K_c_tgs
}
```

### Service Exchange (Mail Server)

```
Client → Mail: {ST, Authenticator_2}
Authenticator_2 = {email, timestamp, nonce_128} encrypted with K_c_v
Mail verifies: nonce not in replay cache (per-service)
Mail → Client: {K_c_v XOR (TS+1)} for mutual auth
```

---

## 11. PKI / CA Service

### Certificate Hierarchy

```
Root CA (self-signed)
  ├── alice@mail.local [sign] — digitalSignature, contentCommitment
  ├── alice@mail.local [enc]  — keyEncipherment, dataEncipherment
  ├── bob@mail.local   [sign]
  ├── bob@mail.local   [enc]
  └── _dkim.mail.local        — DKIM server identity
```

### X.509 Extensions per Cert Type

**Signing Certificate (cert_type='sign'):**
```
KeyUsage (critical):
  digitalSignature = TRUE
  contentCommitment = TRUE    ← non-repudiation
  keyEncipherment = FALSE
  dataEncipherment = FALSE
ExtendedKeyUsage: emailProtection
SubjectAlternativeName: RFC822Name=email
```

**Encryption Certificate (cert_type='enc'):**
```
KeyUsage (critical):
  digitalSignature = FALSE
  contentCommitment = FALSE
  keyEncipherment = TRUE
  dataEncipherment = TRUE
ExtendedKeyUsage: emailProtection
SubjectAlternativeName: RFC822Name=email
```

### OCSP Check

Before every send, the client queries CA:
```
op: 'ca.ocsp', serial_hex: '0xABCD...'
→ {status: 'good' | 'revoked' | 'unknown'}
```

---

## 12. Key Distribution Server (KDS)

### Database Table

```sql
kds.certs (
  email     VARCHAR(256)  NOT NULL,
  cert_type VARCHAR(10)   NOT NULL,  -- 'sign' or 'enc'
  serial    VARCHAR(64)   NOT NULL,
  cert_pem  VARBINARY(MAX) NOT NULL,
  registered_at DATETIMEOFFSET,
  CONSTRAINT PK_kds_certs PRIMARY KEY (email, cert_type),
  CONSTRAINT CK_kds_certs_cert_type CHECK (cert_type IN ('sign', 'enc'))
)
```

### API

| Operation | Request | Response |
|---|---|---|
| `kds.put_cert` | email, cert_type, serial_hex, cert_pem_b64 | ok |
| `kds.get_sign_cert` | email | cert_pem_b64, serial |
| `kds.get_enc_cert` | email | cert_pem_b64, serial |
| `kds.get_cert` | email | cert_pem_b64 (backward compat → sign cert) |
| `kds.bulk` | emails[] | {email: {sign: b64, enc: b64}} |
| `kds.sync_crl` | crl_pem_b64 | ok |
| `kds.get_crl` | — | crl_pem_b64 |
| `kds.list_emails` | — | emails[] |

---

## 13. S/MIME Envelope Format

**Version 2 (Dual Key Pair):**

```json
{
  "version": "smime-lite/2",
  "recipients": [
    {
      "email": "bob@mail.local",
      "enc_serial": "0xABCDE...",
      "cek_oaep_b64": "<RSA-OAEP(bob.enc_pub, CEK) base64>"
    }
  ],
  "content": {
    "algo": "AES-128-CBC",
    "iv_b64":  "<16 random bytes base64>",
    "ct_b64":  "<ciphertext base64>"
  }
}
```

**Inner plaintext (before AES encryption):**

```json
{
  "body_b64":           "<email body base64>",
  "sig_b64":            "<RSA-PSS signature base64>",
  "signer_sign_cert_b64": "<sender's SIGNING cert PEM base64>"
}
```

**Why the signature is inside the ciphertext:**

- Sign-then-Encrypt: signature is computed on plaintext before encryption
- The signing cert is embedded inside the encrypted payload, not exposed in headers
- Recipients who cannot decrypt (wrong key) also cannot see the signature or signer identity

---

## 14. DKIM / SPF / DMARC

### DKIM (Domain Keys Identified Mail)

- Signing algorithm: RSA-2048 / SHA-256
- Canonicalization: relaxed/relaxed
- Headers signed: From, To, Subject, Date, Message-ID
- Signature stored: DKIM-Signature header
- Verification: KDS lookup of `_dkim.{domain}` cert

### SPF (Sender Policy Framework)

- Policy table: `policy.spf (domain, ip)`
- Check: does SMTP client IP match any allowed IP for sender domain?
- Result: `pass` | `fail` | `none`

### DMARC

- Policy table: `policy.dmarc (domain, policy)`
- Policy values: `none` | `quarantine` | `reject`
- Alignment check: `From` header domain == authenticated Kerberos email domain
- Actions:
  - `quarantine` → deliver with warning label
  - `reject` → block delivery

---

## 15. Database Schema

### SQL Server Database: `SecureMail`

```
ca schema:
  ca.issued         — All issued certificates (serial, email, cert_pem, status)
  ca.escrow_shares  — Shamir shares (email, share_index, share_data)
  ca.audit_log      — CA operation log

kds schema:
  kds.certs         — Public cert registry (email, cert_type, serial, cert_pem)
  kds.crl_cache     — Cached CRL (id=1, crl_pem)
  kds.audit_log     — KDS operation log

ticket schema:
  ticket.principals    — Kerberos principals (id_c, salt, kc, role)
  ticket.service_keys  — Service symmetric keys (id_v, kv)
  ticket.revoked_tgts  — TGT revocation list
  ticket.audit_log     — Ticket operation log

policy schema:
  policy.spf    — SPF authorized IPs (domain, ip)
  policy.dmarc  — DMARC policies (domain, policy)

mail schema:
  mail.mailbox    — Stored messages (recipient, envelope, headers_json, folder)
  mail.server_log — Mail server log
```

---

## 16. Local File Structure

```
data/
  server/
    mail_key.pem            — Mail server private key (STARTTLS)
    mail_cert.pem           — Mail server certificate
    mta_mail.local_key.pem  — MTA DKIM signing key
    mta_mail.local_cert.pem — MTA DKIM certificate

  users/
    alice_at_mail.local.sign_key.pem    — Signing private key (never escrowed)
    alice_at_mail.local.sign_cert.pem   — Signing certificate
    alice_at_mail.local.enc_key.pem     — Encryption private key (escrowed)
    alice_at_mail.local.enc_cert.pem    — Encryption certificate
    alice_at_mail.local.salt.bin        — Kerberos password salt
    (similar files for bob, eve, admin)

  active_session.json                   — Stateful CLI session
```

---

## 17. Cryptographic Algorithms

| Use Case | Algorithm | Key Size | Notes |
|---|---|---|---|
| RSA key generation | RSA | 2048-bit | Per keypair (sign + enc) |
| Digital signature | RSA-PSS / SHA-256 | 2048-bit | Provably secure |
| CEK encryption | RSA-OAEP / SHA-256 | 2048-bit | No Bleichenbacher |
| Message encryption | AES-128-CBC | 128-bit | Per-message CEK |
| Session framing | AES-256-GCM | 256-bit | STARTTLS sessions |
| Password → Kc | PBKDF2-HMAC-SHA256 | 256-bit | 200,000 iterations |
| Key derivation | HKDF-SHA256 | 256-bit | RFC 5869 |
| Ticket encryption | AES-256-GCM | 256-bit | Kerberos tickets |
| Secret sharing | Shamir over GF(256) | — | threshold=2, shares=3 |
| DKIM signing | RSA-PKCS1v15 / SHA-256 | 2048-bit | RFC 6376 |

---

## 18. Security Properties

### Achieved

1. **Confidentiality**: Only the intended recipient can decrypt the message body
   (RSA-OAEP protects the CEK; only holder of enc_privkey can unwrap it).

2. **Integrity + Authenticity**: RSA-PSS signature on plaintext; any tampering
   with the ciphertext will produce an invalid decryption or a signature failure.

3. **Non-repudiation**: The signing private key is generated locally and never
   exported to any server. No third party can forge a user's signature.

4. **Key Recovery**: Encryption private keys are recoverable via Shamir 2-of-3
   shares in SQL Server. This allows disaster recovery without compromising
   non-repudiation.

5. **Replay Protection**: Every Kerberos Authenticator uses a fresh 128-bit nonce.
   Used nonces are cached server-side within a 5-minute window.

6. **Certificate Revocation**: CRL is checked before every outbound message.
   OCSP-lite is checked per recipient.

7. **Channel Security**: SMTP and POP3 use STARTTLS (RSA-OAEP ephemeral session
   key + AES-256-GCM framing).

8. **Password Security**: PBKDF2-HMAC-SHA256 with 200,000 iterations. Raw
   passwords never leave the client.

---

## 19. Threat Model

### Threats Mitigated

| Threat | Mitigation |
|---|---|
| Network eavesdropping | STARTTLS + S/MIME end-to-end encryption |
| MITM certificate substitution | CA certificate chain verification |
| Replay attack | Kerberos Authenticator nonce cache |
| Compromised server | Encryption done client-side; server only stores ciphertext |
| Lost local device (enc key) | Shamir escrow recovery (enc key only) |
| Escrow server compromise | Only encryption key exposed; signatures still unforgeable |
| Spoofed sender | SPF + DMARC cross-checks authenticated identity |
| Revoked certificate abuse | CRL + OCSP check before every send |
| Weak password | PBKDF2 with 200k iterations |
| Dictionary attack on stored keys | Private keys are password-encrypted (AES-256-CBC) |

### Threats NOT Mitigated (Demo Limitations)

| Threat | Status |
|---|---|
| Compromised CA private key | CA key stored in flat file (use HSM in production) |
| Honest KDS assumption | KDS not mutually authenticated to CA in this demo |
| Forward secrecy on STARTTLS | Static RSA handshake (not ECDHE; bonus A8 partial) |
| Denial of service | No rate limiting on any service |
| Side-channel attacks | Python RSA not constant-time |

---

## 20. Limitations & Known Issues

1. **Single-machine demo**: All services run on localhost. A real deployment
   would need TLS certificates for inter-service communication.

2. **Password for private keys**: The same password used for Kerberos (Kc) is
   also used to encrypt the local private key files. In production, these should
   be separate secrets (e.g., hardware token PIN vs. account password).

3. **AES-128-CBC**: Used for backward compatibility with the course requirement.
   Production should use AES-256-GCM or ChaCha20-Poly1305.

4. **Legacy accounts**: Users registered with the old single-keypair system will
   have `.key.pem` and `.cert.pem` files. They must re-register to use the dual
   keypair system. The code handles this gracefully with fallback aliases.

---

## 21. Service Ports Reference

| Port | Service | Protocol | Description |
|---|---|---|---|
| 9000 | CA Service | JSON/TCP | CSR signing, CRL, OCSP, revocation, escrow |
| 9001 | KDS | JSON/TCP | Public cert registry, CRL distribution |
| 9002 | Ticket Service | JSON/TCP | Kerberos AS + TGS |
| 2525 | Mail Server SMTP | Custom/TCP | SMTP-lite with STARTTLS |
| 1100 | Mail Server POP3 | Custom/TCP | POP3-lite with STARTTLS |

---

*Document generated: 2026-06-17 | SecureMail v2.1.0 — Dual Key Pair Architecture*
