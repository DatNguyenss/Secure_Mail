# ĐỒ ÁN 2 SecureMail — Hệ thống Email Bảo Mật Nội Bộ (S/MIME + DKIM Lite + Kerberos-lite)

> Môn học Bảo mật Mạng Máy Tính — Ngôn ngữ Python 3.11+ — Nhóm 4 người — Thời gian 6 tuần
> Giáo trình tham chiếu: **Stallings, *Cryptography and Network Security*, Ch 14 / 15 / 19**

---

## 1. Tổng Quan

Xây dựng hệ thống email nội bộ (không cần Internet thật) bao gồm **Mail Server**, **Mail Client (CLI)**, **CA Admin Tool**, **Key Distribution Server (KDS)** và **Ticket Service (Kerberos-lite)** chạy độc lập. Hệ thống triển khai các cơ chế bảo mật lấy cảm hứng từ S/MIME, DKIM, SPF, DMARC (Ch.19) với **PKI X.509 đầy đủ** (Ch.14) và **xác thực kiểu Kerberos với TGT + Service Ticket** (Ch.15). Tất cả email truyền qua TCP socket giả lập SMTP.

**Thư viện Python chính**
- `cryptography` — AES-GCM, RSA-OAEP/PSS, X.509, HMAC, HKDF (thay thế hoàn toàn OpenSSL thủ công)
- `socket` / `threading` — TCP server/client
- `sqlite3` — lưu trữ mail, cert, CRL, SPF record, ticket cache
- `argparse` / `cmd` — giao diện CLI

---

## 2. Kiến Trúc Hệ Thống

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        CA Admin Tool (PKI Root)                             │
│   Root CA key pair → ký Cert → xuất CRL → OCSP-lite (cổng 9000)            │
└─────────────┬───────────────────────────────────────┬───────────────────────┘
              │ phát hành cert / push revocation      │ verify cert + CRL
              ▼                                       ▼
┌───────────────────────┐        ┌──────────────────────┐        ┌────────────────────────┐
│ Key Distribution      │        │ Ticket Service       │        │    Mail Server (MTA)    │
│ Server (KDS) 9001     │◄──────►│ (AS + TGS) 9002      │◄──────►│  SMTP-lite 2525          │
│  - Cert registry      │        │  Kerberos-lite       │        │  POP3-lite 1100          │
│  - Tra cứu cert/email │        │  - AS: cấp TGT       │        │  DKIM / SPF / DMARC     │
│  - CRL cache          │        │  - TGS: cấp Service  │        │  Message Store (SQLite) │
└───────────┬───────────┘        │         Ticket       │        └──────────────┬───────────┘
            │                    │  - Subsession key    │                       ▲
            │                    └──────────┬───────────┘                       │
            │                               │                                   │
            │  tra cứu pub-key              │ TGT / ST / Authenticator          │ SMTP / POP3
            ▼                               ▼                                   │
 ┌──────────────────┐                 ┌───────────────┐             ┌───────────┴────────┐
 │ Mail Client A    │────── SMTP ────►│  Mail Server  │◄──── POP3 ──│ Mail Client B      │
 │ (Alice) — CLI    │                 │               │             │ (Bob) — CLI        │
 └──────────────────┘                 └───────────────┘             └────────────────────┘
```

### Luồng gửi email mã hóa (tóm tắt)

```
[Alice đã có TGT từ AS]

  Alice                       TGS                  KDS              Mail Server (MTA)
    │                          │                    │                      │
    │── TGT + "want mail_svc" ►│                    │                      │
    │◄── Ticket_v + Ks(sub) ───│                    │                      │
    │                                                                      │
    │── GET cert?email=bob ────────────────────────►│                      │
    │◄── Bob's X.509 Cert ──────────────────────────│                      │
    │  (verify CA signature + CRL)                                         │
    │                                                                      │
    │  sinh CEK ngẫu nhiên → AES-128-CBC encrypt body                      │
    │  RSA-OAEP encrypt CEK bằng public key Bob                            │
    │  RSA-PSS sign (hash toàn bộ) bằng private key Alice                  │
    │                                                                      │
    │── SMTP AUTH (Ticket_v + Authenticator) ─────────────────────────────►│
    │── DATA (S/MIME envelope) ───────────────────────────────────────────►│
```

---

## 3. Yêu Cầu Theo Cấp Độ (có map giáo trình)

### Cơ Bản

| # | Tính năng | Mô tả kỹ thuật | Giáo trình |
|---|---|---|---|
| B1 | Mô hình khóa rõ ràng | Mỗi user có RSA-2048 key pair. Public key nằm trong **X.509v3 Certificate** do CA ký. Private key lưu local dạng PEM, mã hóa bằng passphrase (PKCS#8 encrypted). | Ch 14.3, 14.4 |
| B2 | Symmetric Encryption (body) | Email body mã hóa AES-128-CBC với **Content-Encryption Key (CEK)** ngẫu nhiên mỗi email — mô hình **S/MIME EnvelopedData**. | Ch 19.4 (S/MIME EnvelopedData), Ch 14.2 |
| B3 | Phân phối Public Key qua KDS | Client không cache cứng. Trước mỗi lần gửi, tra cứu **KDS (Key Distribution Server)** độc lập để lấy cert mới nhất. | Ch 14.3 (Publicly Available Directory + Public-Key Authority) |
| B4 | Xác thực người dùng cơ bản | Đăng nhập username + `HMAC-SHA256(password ∥ salt)`. Salt lưu server-side. Không truyền plaintext password. | Ch 15.2 (password-based auth) |
| B5 | Quản lý khóa (one-time CEK) | CEK 128-bit từ `os.urandom`, unique mỗi email, RSA-OAEP encrypt bằng public key của từng recipient → đính kèm `RecipientInfo`. | Ch 19.4 (RecipientInfo), Ch 14.2 |
| B6 | Session key lifetime | Sau khi authenticate, server cấp session token có **TTL 30 phút**. Hết hạn → re-auth. | Ch 14.1 (Session Key Lifetime) |
| **B7** | **Hierarchical key + subsession (HKDF)** | Từ **master session key** Ks, dẫn xuất **subsession key** `K_sub = HKDF-SHA256(Ks, info="mail-submit" ∥ msg_seq)` cho từng email → compromise 1 email không lộ toàn session. | Ch 14.1 (Hierarchy of Keys) |

### Trên Trung Bình

| # | Tính năng | Mô tả kỹ thuật | Giáo trình |
|---|---|---|---|
| M1 | Mutual Authentication | Cả client và server trình Cert + ký challenge bằng private key. Verify chéo chain. Giao thức kiểu **Denning/Woo-Lam**. | Ch 15.4 (Mutual Auth with Asymmetric Encryption) |
| M2 | Chống Replay | Server gửi nonce 32-byte ngẫu nhiên mỗi session. Client ký `nonce ∥ timestamp`. Từ chối (a) nonce đã dùng, (b) timestamp lệch > 5 phút. | Ch 14.1 (nonce N1, N2 trong KDC scenario), Ch 15.3 |
| M3 | Certificate Validation | Client verify chain `UserCert → CA`. Kiểm `NotBefore/NotAfter`, chữ ký CA, **CRL** (tải qua `/crl`). | Ch 14.4, 14.5 |
| M4 | Chống MITM / Public-key Substitution | KDS chỉ trả cert có chữ ký CA hợp lệ. Client verify CA signature trước khi dùng pub-key. Cert giả bị từ chối. | Ch 14.3 (Public-Key Authority) |
| M5 | Digital Signature (S/MIME SignedData) | Người gửi ký `header + body` bằng **RSA-PSS + SHA-256**. Receiver verify → toàn vẹn + non-repudiation. | Ch 19.4 (SignedData), Ch 13 |
| M6 | Access Control / Authorization | Role-based: `user` (gửi/nhận), `admin` (log, user mgmt), `mailing_list_manager`. Enforce tại SMTP layer. | Ch 15.5 (Identity Management), Ch 4 (Access Control) |
| **M7** | **Kerberos Authenticator** | Mỗi request đến TGS hoặc Mail Server đính kèm `Authenticator = E(K_cv, IDc ∥ ADc ∥ TSn)`. Server kiểm `TSn` nằm trong cửa sổ 5' → chống replay ticket trong lifetime. | Ch 15.3 (Version 4 Authenticator) |
| **M8** | **STARTTLS-lite cho SMTP** | Trước khi gửi SMTP plain, client issue `STARTTLS` → TLS-like handshake (RSA cert + AES-GCM) bảo vệ metadata (From, To, Subject). S/MIME bảo vệ body, STARTTLS bảo vệ envelope. | Ch 19.3 (STARTTLS), Ch 17.2 (TLS) |

### Nâng Cao

| # | Tính năng | Mô tả kỹ thuật | Giáo trình |
|---|---|---|---|
| A1 | X.509v3 Cert + extensions | Dùng `cryptography.x509`: Subject/Issuer DN, SerialNumber, Validity, SubjectPublicKeyInfo, **BasicConstraints, KeyUsage, SubjectAltName (email), AuthorityKeyIdentifier, CRLDistributionPoints**. CA ký RSA-SHA256. | Ch 14.4 (X.509 Version 3) |
| A2 | PKI Admin Tool (CA Service) | Service cổng 9000: (1) tạo Root CA, (2) nhận/ký CSR, (3) xuất CRL cập nhật, (4) **OCSP-lite** (`good/revoked/unknown`). Giao diện CLI + JSON API. | Ch 14.5 (PKIX Management Functions) |
| A3 | Key Distribution Server (KDS) độc lập | Service cổng 9001: đăng ký cert, tra cứu theo email, cache CRL từ CA, **bulk key fetch** cho mailing list. SQLite backend. | Ch 14.3 (Publicly Available Directory) |
| A4 | DKIM-lite Signing | Mail Server ký domain hash `(canonicalized headers + body)` bằng SHA-256, chèn `DKIM-Signature`. Receiving MTA verify qua KDS (thay DNS TXT). Chỉ hỗ trợ canonicalization `relaxed/relaxed`. | Ch 19.9 (DomainKeys Identified Mail) |
| A5 | SPF-lite + DMARC-lite | SPF check sender IP ↔ domain từ SQLite record. DMARC admin cấu hình policy `none/quarantine/reject` áp dụng khi SPF hoặc DKIM fail. Có log/report. | Ch 19.8 (SPF), 19.10 (DMARC) |
| A6 | **Full Kerberos-lite (AS + TGS + Service)** | 3 exchange đầy đủ theo Kerberos v4: **(1) AS Exchange** client gửi `IDc ∥ IDtgs ∥ TS1` → AS trả `E(Kc, [Kc,tgs ∥ IDtgs ∥ TS2 ∥ Lifetime2 ∥ Tickettgs])`. **(2) TGS Exchange** client gửi `IDv ∥ Tickettgs ∥ Authenticatorc` → TGS trả `E(Kc,tgs, [Kc,v ∥ IDv ∥ TS4 ∥ Ticketv])`. **(3) Service Exchange** client gửi `Ticketv ∥ Authenticatorc` đến Mail Server. Ticket reusable trong lifetime. | Ch 15.3 (Kerberos Version 4 Message Exchanges) |
| A7 | Mutual auth server→client (TS+1) | Sau khi nhận ticket hợp lệ, Mail Server reply `E(Kc,v, [TS5 + 1])` để chứng minh nó đọc được ticket → chống false-server attack. | Ch 15.3 Table 15.1 (c) |
| A8 | Forward Secrecy (ECDH ephemeral) | **Đề xuất thêm**: Mỗi email dùng cặp ECDH ephemeral (X25519). CEK = `HKDF(ECDH(priv_a_eph, pub_b))`. Lộ private key dài hạn không giải mã được email cũ. | Ch 10 (Diffie-Hellman), bổ sung ngoài Stallings |
| A9 | Key Recovery / Escrow (admin) | CA lưu **backup encryption key** (không phải signing key) trong HSM giả lập (file mã hóa AES-256). Admin cần 2-of-3 threshold secret sharing (Shamir) để khôi phục. Signing key KHÔNG escrow → giữ non-repudiation. | Ch 14.5 (PKIX Management — Key Pair Recovery) |

---

## 4. Chi Tiết KDS + Ticket Service

### 4.1 KDS API (cổng 9001, JSON-over-TCP)

```
GET  /key?email=alice@mail.local         → Certificate PEM
POST /key/register                       → đăng ký cert mới (yêu cầu CA-signed)
GET  /crl                                → Certificate Revocation List hiện tại
GET  /ocsp?serial=<hex>                  → trạng thái 1 cert
GET  /keys/bulk?emails=a,b,c             → nhiều cert cùng lúc (mailing list)
POST /key/revoke                         → thu hồi (chỉ CA-authenticated)
```

### 4.2 Ticket Service API (cổng 9002, Kerberos-lite)

```
POST /as-req          { IDc, IDtgs, TS1, nonce }                  → AS-REP (E(Kc, [Kc,tgs ∥ ...]))
POST /tgs-req         { IDv, Tickettgs, Authenticatorc }          → TGS-REP (E(Kc,tgs, [Kc,v ∥ Ticketv]))
POST /ticket/renew    { Tickettgs, Authenticatorc }               → TGT mới (sliding window)
POST /ticket/revoke   { Tickettgs }                               → đánh dấu revoked (blacklist)
```

**Cấu trúc Ticket** (theo Ch 15.3):
```
Tickettgs = E(Ktgs, [Kc,tgs ∥ IDc ∥ ADc ∥ IDtgs ∥ TS2 ∥ Lifetime2])
Ticketv   = E(Kv,   [Kc,v   ∥ IDc ∥ ADc ∥ IDv   ∥ TS4 ∥ Lifetime4])
Authc     = E(Kc,x, [IDc ∥ ADc ∥ TSn ∥ (optional) subkey])
```

Triển khai Python: `AES-256-GCM` thay cho DES trong giáo trình (DES lỗi thời).

### 4.3 Luồng đăng ký user mới

```
  User                 CA (9000)              KDS (9001)            Ticket Service (9002)
   │                       │                      │                        │
   │── tạo RSA keypair     │                      │                        │
   │── gửi CSR ───────────►│                      │                        │
   │                       │── ký cert ──────────►│ (CA push)              │
   │◄── cert ──────────────│                      │                        │
   │                       │── push master key ──────────────────────────►│
   │                                                                       │
   │── AS-REQ (lần đầu đăng nhập) ────────────────────────────────────────►│
   │◄── TGT ──────────────────────────────────────────────────────────────│
```

---

## 5. Kerberos-lite Protocol Flow (chi tiết A6 + A7)

```
───────────────────────── (1) AS Exchange — 1 lần mỗi logon session ─────────────────────────
Client → AS       :   IDc ∥ IDtgs ∥ TS1
AS → Client       :   E(Kc, [Kc,tgs ∥ IDtgs ∥ TS2 ∥ Lifetime2 ∥ Tickettgs])
                      Tickettgs = E(Ktgs, [Kc,tgs ∥ IDc ∥ ADc ∥ IDtgs ∥ TS2 ∥ Lifetime2])

# Kc = HKDF(password ∥ salt); chỉ đúng password mới decrypt được AS-REP
# → password KHÔNG bao giờ truyền qua mạng

───────────────────────── (2) TGS Exchange — 1 lần mỗi service ──────────────────────────────
Client → TGS      :   IDv ∥ Tickettgs ∥ Authenticatorc
                      Authenticatorc = E(Kc,tgs, [IDc ∥ ADc ∥ TS3])
TGS → Client      :   E(Kc,tgs, [Kc,v ∥ IDv ∥ TS4 ∥ Ticketv])
                      Ticketv = E(Kv, [Kc,v ∥ IDc ∥ ADc ∥ IDv ∥ TS4 ∥ Lifetime4])

───────────────────────── (3) Client/Server — mỗi lần gửi mail ──────────────────────────────
Client → MailSrv  :   Ticketv ∥ Authenticatorc
                      Authenticatorc = E(Kc,v, [IDc ∥ ADc ∥ TS5])
MailSrv → Client  :   E(Kc,v, [TS5 + 1])          ← A7 mutual auth
                      (sau đó dùng Kc,v làm session key cho phiên SMTP)

# Subsession key (B7):
#   K_sub(i) = HKDF-SHA256(Kc,v, info="mail#" ∥ seq_i)
#   → mỗi email dùng 1 key riêng, lộ 1 email không ảnh hưởng email khác
```

---

## 6. Phân Công & Kế Hoạch 6 Tuần

| Tuần | Công việc | Người |
|------|-----------|-------|
| 1 | Setup môi trường Python + `cryptography`. SMTP-lite + POP3-lite (socket + threading). Cấu trúc dữ liệu email, SQLite schema mail store. | TV1 + TV2 |
| 2 | CA Service 9000 (RSA gen, X.509v3, CRL, OCSP-lite). KDS 9001 (đăng ký + tra cứu cert). | TV3 + TV4 |
| 3 | S/MIME EnvelopedData (CEK + AES-128-CBC + RSA-OAEP + RecipientInfo). SignedData (RSA-PSS + SHA-256). MIME parser. | TV1 + TV3 |
| 4 | **Ticket Service 9002 (AS + TGS)**. TGT/ST + Authenticator + mutual auth TS+1. **HKDF subsession**. STARTTLS-lite. | TV2 + TV4 |
| 5 | DKIM-lite sign/verify qua KDS. SPF-lite + DMARC-lite policy engine. **ECDH ephemeral forward secrecy (A8)**. Key recovery escrow (A9). | TV1 + TV2 |
| 6 | Integration test end-to-end, **6 demo scenarios** (§9), viết báo cáo + slide + video demo. | Cả nhóm |

---

## 7. Cấu Trúc Module Code

```
securemail/
├── ca_service/
│   ├── ca_server.py          ← JSON API cổng 9000
│   ├── ca_core.py            ← Root CA, CSR ký, revoke
│   ├── crl_manager.py        ← CRL generate/update
│   ├── ocsp_responder.py     ← OCSP-lite
│   └── key_escrow.py         ← A9 (Shamir 2-of-3)
│
├── kds/
│   ├── kds_server.py         ← Key Distribution Server 9001
│   ├── key_store.py          ← SQLite CRUD certificates
│   └── kds_client.py         ← Client lib
│
├── ticket_service/                       ← MỚI (Kerberos-lite)
│   ├── as_server.py          ← AS Exchange (cổng 9002)
│   ├── tgs_server.py         ← TGS Exchange
│   ├── ticket.py             ← TGT/ST struct + AES-256-GCM seal
│   └── authenticator.py      ← Authenticator gen/verify + replay cache
│
├── crypto/
│   ├── aes_handler.py        ← AES-128-CBC + AES-256-GCM
│   ├── rsa_handler.py        ← RSA-2048 keygen, sign (PSS), OAEP
│   ├── ecdh_handler.py       ← X25519 ephemeral (A8)
│   ├── hmac_utils.py         ← HMAC-SHA256, password hashing
│   └── key_derivation.py     ← HKDF-SHA256 cho subsession (B7)
│
├── mail/
│   ├── mime_lite.py          ← Build/parse MIME
│   ├── smime_handler.py      ← EnvelopedData + SignedData (clear + opaque)
│   └── dkim_signer.py        ← DKIM-lite sign/verify
│
├── network/
│   ├── smtp_server.py        ← SMTP-lite + STARTTLS (M8)
│   ├── smtp_client.py
│   ├── pop3_server.py
│   └── tls_lite.py           ← TLS-lite handshake (RSA + AES-GCM)
│
├── auth/
│   ├── authenticator.py      ← Login, nonce/replay check, ticket verify
│   └── access_control.py     ← RBAC (M6)
│
├── policy/
│   ├── spf_checker.py
│   └── dmarc_engine.py
│
└── main_server.py / main_client.py / main_ca_admin.py
```

---

## 8. Điểm Khó & Rủi Ro

| Rủi ro | Mức độ | Phương án xử lý |
|--------|--------|-----------------|
| Thiết kế JSON-over-TCP protocol | TB | `json.dumps` + length-prefix framing; không cần HTTP framework |
| X.509v3 với `cryptography` | Thấp | API rõ: `x509.CertificateBuilder()`, `.sign()`, `.public_bytes()` |
| Multi-threaded TCP server | Thấp | `threading.Thread` mỗi client; `threading.Lock` cho SQLite write |
| DKIM canonicalization | Cao | Chỉ `relaxed/relaxed`; ghi rõ giới hạn trong báo cáo |
| Đồng bộ clock cho Kerberos timestamp | Cao | Cho phép drift ±5 phút; dùng NTP-lite nội bộ (hoặc server phát time) |
| Replay cache Authenticator scale | TB | SQLite index trên `(IDc, TSn)` với TTL = Lifetime; GC định kỳ |
| Shamir secret sharing (A9) | TB | Dùng `secretsharing` lib hoặc tự cài; chỉ 2-of-3, không cần threshold lớn |
| Scope quá rộng (9 module A1–A9) | Cao | **A8 (ECDH forward secrecy) và A9 (key recovery)** là tính năng "đề xuất thêm" — cắt được nếu thiếu thời gian |

---

## 9. Demo Scenarios (6 kịch bản)

1. **Normal encrypted + signed email**: Alice tra KDS → cert Bob → S/MIME envelope (sign-then-encrypt) → SMTP → Bob decrypt + verify.
2. **MITM / Public-key Substitution**: Attacker inject cert giả vào KDS → KDS từ chối (thiếu CA sig) → client không dùng key giả.
3. **Replay Attack**: Attacker capture `Ticketv + Authenticator` cũ → Mail Server từ chối (TS đã dùng trong replay cache).
4. **Revoked Certificate**: Alice thu hồi cert qua CA → CA push CRL → KDS cache → Bob tra cứu → nhận cảnh báo `revoked` → từ chối email.
5. **Spoofed Sender (SPF + DMARC)**: Email giả mạo `From: alice@mail.local` từ IP lạ → SPF fail → DMARC `quarantine` → vào spam + DMARC report tới admin.
6. **Reusable Ticket**: Alice login 1 lần (AS exchange) → gửi 5 email liên tiếp dùng cùng Ticketv nhưng **Authenticator mới mỗi lần** → ticket expire → renew TGT → tiếp tục.
7. **(Optional) Forward Secrecy demo**: Compromise private key Bob SAU khi nhận email → email cũ vẫn không giải mã được (ECDH ephemeral đã bị xóa).
8. **(Optional) Key Recovery**: Admin mất laptop → 2-of-3 admin hợp thành khôi phục encryption key của user; signing key vẫn mất vĩnh viễn → chứng minh tách biệt 2 loại key.

---

## 10. Bảng Map Chương Giáo Trình → Tính Năng

| Chương Stallings | Mục | Tính năng đồ án |
|---|---|---|
| Ch 14.1 | Symmetric Key Distribution | B6, B7, M2 |
| Ch 14.2 | Symmetric via Asymmetric | B2, B5 |
| Ch 14.3 | Distribution of Public Keys | B3, A3, M4 |
| Ch 14.4 | X.509 Certificates | B1, M3, A1 |
| Ch 14.5 | PKI | A2, A9 |
| Ch 15.2 | Password-based Auth | B4 |
| Ch 15.3 | **Kerberos v4** | **M7, A6, A7** |
| Ch 15.4 | Mutual Auth (Asymmetric) | M1 |
| Ch 15.5 | Identity Management | M6 |
| Ch 17.2 | TLS | M8 |
| Ch 19.3 | STARTTLS | M8 |
| Ch 19.4 | **S/MIME** (Enveloped/Signed) | **B2, B5, M5** |
| Ch 19.8 | SPF | A5 |
| Ch 19.9 | DKIM | A4 |
| Ch 19.10 | DMARC | A5 |
| Ch 10 (bổ sung) | Diffie-Hellman | A8 |

---

## 11. Tiêu Chí Đánh Giá Nội Bộ (self-check)

- [ ] Cơ bản B1–B7: 7/7
- [ ] Trên TB M1–M8: 8/8
- [ ] Nâng cao A1–A7: bắt buộc 7/7; A8, A9: bonus
- [ ] 6 demo scenario chạy end-to-end không lỗi
- [ ] Báo cáo trích dẫn chương giáo trình cho mỗi tính năng (xem §10)
- [ ] Code có unit test cho `crypto/`, `ticket_service/`, `smime_handler.py`
- [ ] README + hướng dẫn chạy 3 service (CA, KDS, Ticket) + Mail Server + Client
