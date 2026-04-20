# SecureMail — Hệ thống Email Bảo Mật Nội Bộ

Đồ án 2 môn Bảo mật Mạng Máy Tính. Python 3.11+. Lib duy nhất: `cryptography>=42`.

Triển khai:
- **PKI X.509v3 đầy đủ** (Root CA, CSR sign, CRL, OCSP-lite, key escrow Shamir 2-of-3)
- **Key Distribution Server** độc lập phân phối public cert
- **Kerberos-lite** 3-exchange (AS + TGS + Service) với TGT/ST reusable + Authenticator chống replay + mutual auth `TS+1`
- **S/MIME-lite** EnvelopedData (AES-128-CBC + RSA-OAEP) + SignedData (RSA-PSS + SHA-256)
- **DKIM-lite** (relaxed/relaxed), **SPF-lite**, **DMARC-lite** engine
- **STARTTLS-lite** cho SMTP + POP3 (RSA-OAEP handshake → AES-256-GCM)
- **HKDF subsession key** cho hierarchical key control
- **RBAC 3 role** (user / admin / mailing_list_manager)

## Cài đặt

```bash
pip install -r requirements.txt
```

## Chạy

Mở **5 terminal** (hoặc chạy background trên Linux/WSL), ở cùng thư mục `e:\datxinhzai\MHUD`:

| # | Terminal | Lệnh | Cổng |
|---|----------|------|------|
| 1 | CA Service | `python -m securemail.main_ca serve` | 9000 |
| 2 | Key Distribution Server | `python -m securemail.main_kds` | 9001 |
| 3 | Ticket Service (Kerberos AS+TGS) | `python -m securemail.main_ticket` | 9002 |
| 4 | Bootstrap (1 lần) | `python -m securemail.run_demo bootstrap` | — |
| 5 | Mail Server (SMTP + POP3) | `python -m securemail.main_mail_server` | 2525, 1100 |
| 6 | Demo hoặc CLI | xem bên dưới | — |

### Chạy toàn bộ 8 scenario tự động

```bash
python -m securemail.run_demo all
```

### CLI người dùng (sau khi bootstrap)

```bash
# Đăng ký user mới (auto tạo keypair, ký CSR, push KDS, đăng ký Kerberos principal)
python -m securemail.main_client register carol@mail.local carol-pw "Carol"

# Đăng nhập test (AS-REQ / AS-REP)
python -m securemail.main_client login alice@mail.local alice-pw

# Gửi email có mã hóa + ký
echo "Hello Bob" | python -m securemail.main_client send alice@mail.local alice-pw bob@mail.local "Test subject"

# Lấy inbox (POP3 + decrypt + verify)
python -m securemail.main_client fetch bob@mail.local bob-pw
```

### CLI CA admin

```bash
# Liệt kê cert đã cấp
python -m securemail.main_ca list

# Thu hồi cert (sau đó cần rebuild CRL via KDS hoặc scenario demo)
python -m securemail.main_ca revoke 0x1234...

# Khôi phục private key từ escrow (2-of-3 Shamir share)
python -m securemail.main_ca escrow bob@mail.local
```

## Kiến trúc

```
┌─────────── CA (9000) ───────────┐   ┌────── KDS (9001) ──────┐
│ Root CA + sign CSR              │──►│ Cert registry          │
│ CRL + OCSP-lite + Key escrow    │   │ CRL cache + bulk lookup│
└─────────────────────────────────┘   └────────────────────────┘
                                                ▲
┌───── Ticket Service (9002) ────┐               │
│ AS exchange  → TGT              │               │
│ TGS exchange → Service Ticket   │               │
│ Authenticator + replay cache    │               │
│ Subsession key (HKDF)           │               │
└─────────────────────────────────┘               │
             ▲                                    │
             │ TGT / ST / Authenticator           │ fetch cert
             │                                    │
   ┌─────────┴───────────┐       ┌────────────────┴─────────────┐
   │ Mail Client CLI     │──────►│ Mail Server (2525 / 1100)    │
   │ (alice / bob / eve) │ SMTP  │ STARTTLS + S/MIME + DKIM     │
   └─────────────────────┘       │ SPF + DMARC + Message Store  │
                                 └──────────────────────────────┘
```

## Thư mục

```
securemail/
  crypto/        AES, RSA, HMAC, HKDF, ECDH (X25519)
  ca_service/    Root CA + CSR sign + CRL + OCSP + Shamir escrow
  kds/           Key Distribution Server
  ticket_service/ Kerberos-lite AS + TGS + Ticket + Authenticator
  mail/          MIME-lite + S/MIME (Enveloped/SignedData) + DKIM-lite
  network/       SMTP-lite + POP3-lite + TLS-lite (STARTTLS) + JSON framing
  auth/          RBAC + Certificate chain validator
  policy/        SPF + DMARC engine
  main_ca.py       # entry CA
  main_kds.py      # entry KDS
  main_ticket.py   # entry Ticket Service
  main_mail_server.py  # SMTP + POP3
  main_client.py   # user CLI
  client_core.py   # client library (register, login, send, fetch)
  run_demo.py      # bootstrap + 8 scenario automated demo
data/              Runtime: SQLite DBs, cert PEM, logs (auto-created)
```

## 8 Scenario tự động

| # | Scenario | Tính năng được chứng minh |
|---|----------|---------------------------|
| 1 | Normal encrypted + signed email | B1–B7, M1, M3, M5 — full happy path |
| 2 | MITM / Public-key substitution | M4 — cert không ký CA bị từ chối khi verify chain |
| 3 | Replay Attack | M2, M7 — Authenticator tái sử dụng bị reject |
| 4 | Revoked Certificate | M3 — CRL cập nhật ngăn gửi tới cert bị thu hồi |
| 5 | Spoofed Sender | A5 — SPF fail + DMARC quarantine |
| 6 | Reusable Ticket (1 login, N sends) | A6 — Service Ticket reuse với Authenticator mới mỗi lần |
| 7 | Key Recovery (Shamir 2-of-3) | A9 — recover private key từ 2 trong 3 share |
| 8 | HKDF subsession key | B7 — key hierarchy, unique per message context |

## Map chương giáo trình (Stallings)

Xem chi tiết trong `../Email.md` §10.

## Thiết kế an toàn & giới hạn

**Đã làm đúng:**
- RSA-OAEP (không phải PKCS#1 v1.5) cho key transport → không bị Bleichenbacher
- RSA-PSS (không phải PKCS#1 v1.5) cho chữ ký → provably secure
- AES-GCM cho ticket, STARTTLS, subsession → AEAD chống padding oracle
- HKDF-SHA256 cho dẫn xuất subkey
- PBKDF2-HMAC-SHA256 200k iteration cho password → Kc
- Replay cache với nonce 128-bit + timestamp window 5 phút
- CRL verify trước mỗi lần gửi
- Certificate chain verify (user → CA) với chữ ký PKCS1v15 của CA
- Shamir secret sharing trên GF(256) cho key escrow

**Giới hạn demo:**
- KDS tin cậy CA qua "đường phụ" (admin), không xác thực lại chữ ký CA lên cert được push. Client làm việc xác thực chính.
- Clock sync giữa các service giả định trong phạm vi LAN (window ±5 phút đủ)
- DKIM chỉ cài canonicalization `relaxed/relaxed`
- STARTTLS-lite không có forward secrecy đầy đủ như TLS 1.3 (tuỳ phần bonus A8)
- Passphrase cho private key CA hardcoded trong file — production dùng HSM

## Troubleshooting

- **Port đã dùng**: `taskkill /F /IM python.exe` (Windows) / `pkill -f securemail` (Linux) rồi chạy lại.
- **`Missing mail_key.pem`**: chạy `run_demo.py bootstrap` trước khi start Mail Server.
- **`ticket expired`**: TGT 8h, Service Ticket 30 phút — login lại với `client_core.login`.
- **Unicode error trên Windows**: đã thay `✓` bằng `[OK]`; nếu vẫn lỗi, đặt `PYTHONIOENCODING=utf-8`.
