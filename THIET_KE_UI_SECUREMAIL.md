# THIẾT KẾ UI CHI TIẾT CHO SECUREMAIL

> Tài liệu này phân tích hệ thống SecureMail hiện tại và đề xuất thiết kế giao diện người dùng theo hướng phục vụ demo, bảo vệ đồ án và có thể triển khai trực tiếp lên code Python hiện có.

---

## 1. Tóm tắt hệ thống hiện tại

SecureMail là hệ thống email bảo mật nội bộ, hiện triển khai chủ yếu bằng CLI và các microservice chạy cục bộ. Hệ thống không chỉ gửi/nhận email mà còn chứng minh nhiều cơ chế bảo mật ứng dụng:

- PKI/X.509v3: CA cấp chứng chỉ, CRL, OCSP-lite, key escrow.
- KDS: phân phối public certificate cho người dùng.
- Kerberos-lite: AS/TGS, TGT, Service Ticket, Authenticator chống replay.
- S/MIME-lite: ký số RSA-PSS, mã hóa nội dung bằng AES-CBC, bọc CEK bằng RSA-OAEP.
- SMTP/POP3-lite: STARTTLS-lite, AUTH bằng Service Ticket.
- SPF/DKIM/DMARC-lite: phát hiện spoofing/phishing.
- Shamir 2-of-3: khôi phục khóa private key.
- HKDF: dẫn xuất subsession key.

Các entry point chính:

| Nhóm | File | Vai trò |
|---|---|---|
| CA | `securemail/main_ca.py` | Chạy CA Service trên port 9000 |
| KDS | `securemail/main_kds.py` | Chạy Key Distribution Server trên port 9001 |
| Ticket | `securemail/main_ticket.py` | Chạy Kerberos-lite AS/TGS trên port 9002 |
| Mail Server | `securemail/main_mail_server.py` | Chạy SMTP 2525 và POP3 1100 |
| Client | `securemail/main_client.py` | CLI register, login, send, list, read, recover |
| Client core | `securemail/client_core.py` | Thư viện lõi để GUI có thể gọi trực tiếp |
| Scenario | `securemail/run_demo.py` | Bootstrap và 8 kịch bản bảo mật |
| Log viewer | `view_logs.py` | Đọc audit log từ SQL Server |

Nguồn dữ liệu chính:

| Schema/Table | Dữ liệu | Dùng cho UI |
|---|---|---|
| `ca.issued` | Cert đã cấp, trạng thái revoked/good | Certificate screen, dashboard CA |
| `ca.escrow_shares` | Shamir shares | Key recovery UI |
| `ca.audit_log` | Sự kiện CA | Monitoring event stream |
| `kds.certs` | Registry chứng chỉ public | KDS status, certificate lookup |
| `kds.crl_cache` | CRL cache | Revocation status |
| `kds.audit_log` | Sự kiện KDS | Monitoring event stream |
| `ticket.principals` | User/service principal, role | User management, login status |
| `ticket.service_keys` | Khóa dịch vụ | Dashboard Ticket Service |
| `ticket.revoked_tgts` | TGT bị revoke | Security dashboard |
| `ticket.audit_log` | Sự kiện AS/TGS | Monitoring event stream |
| `mail.mailbox` | Inbox/Sent encrypted envelope | Mailbox, counters |
| `mail.server_log` | SMTP/POP3 event | Monitoring event stream |
| `policy.spf` | SPF records | Policy screen |
| `policy.dmarc` | DMARC policy | Policy screen |

---

## 2. Định hướng UI tổng thể

Không nên chỉ làm một giao diện "bấm chạy scenario". Với SecureMail, giao diện tốt nhất nên có 3 mode:

| Mode | Mục tiêu | Người dùng chính |
|---|---|---|
| User App | Người dùng thao tác như một hệ thống mail thật: đăng ký, đăng nhập, gửi, nhận, đọc mail | Alice, Bob, user thường |
| Monitoring Dashboard | Quan sát backend, log, service status, alert bảo mật, timeline phiên gửi mail | Người thuyết trình, admin |
| Scenario Lab | Chạy nhanh 8 kịch bản kiểm thử để chứng minh hệ thống chống tấn công | Giảng viên, nhóm demo |

Lý do chia 3 mode:

- User App cho thấy tầng nghiệp vụ: email thật, hộp thư thật, thao tác thật.
- Monitoring Dashboard cho thấy tầng bảo mật: cert, ticket, encryption, signature, replay cache, SPF/DKIM/DMARC.
- Scenario Lab giữ lại sức mạnh kiểm thử hiện tại: bấm một lần chạy MITM, Replay, Revoked Certificate, Spoofed Sender.

---

## 3. Kiến trúc UI đề xuất

### 3.1. Khuyến nghị công nghệ

Vì project hiện là Python local app và chưa có frontend framework, có 2 hướng khả thi:

| Hướng | Ưu điểm | Nhược điểm | Phù hợp |
|---|---|---|---|
| Python Desktop GUI bằng Tkinter/CustomTkinter | Dễ gọi trực tiếp `client_core.py`, dễ demo offline | Giao diện không đẹp bằng web nếu không chăm CSS/theme | Làm nhanh, ít thay đổi kiến trúc |
| Web UI local bằng FastAPI + HTML/JS | Đẹp, dễ làm dashboard realtime | Cần thêm backend HTTP và frontend | Demo chuyên nghiệp hơn |

Khuyến nghị cho đồ án này:

- Giai đoạn 1: làm Python Desktop GUI để tận dụng code hiện có.
- Giai đoạn 2: nếu còn thời gian, nâng cấp Monitoring Dashboard thành web realtime.

### 3.2. Các lớp code nên tách khi triển khai GUI

```text
securemail/
  gui/
    app.py
    theme.py
    state.py
    controllers/
      auth_controller.py
      mail_controller.py
      cert_controller.py
      monitor_controller.py
      scenario_controller.py
    views/
      login_view.py
      register_view.py
      mailbox_view.py
      compose_view.py
      mail_detail_view.py
      security_view.py
      monitor_view.py
      scenario_lab_view.py
```

Vai trò đề xuất:

| File | Vai trò |
|---|---|
| `gui/app.py` | Khởi tạo app, navigation 3 mode |
| `gui/state.py` | Lưu current user, session context, cached inbox/sent, selected message |
| `auth_controller.py` | Bọc `client_core.register`, `login`, `save_session`, `load_session`, `clear_session` |
| `mail_controller.py` | Bọc `send_secure_email`, `fetch_inbox`, `fetch_sent`, `fetch_message` |
| `cert_controller.py` | Query CA/KDS, xem cert, CRL, OCSP |
| `monitor_controller.py` | Đọc service status, audit logs, mail counters |
| `scenario_controller.py` | Gọi `run_demo.py` theo từng scenario hoặc subprocess |

---

## 4. Information Architecture

### 4.1. Navigation cấp cao

```text
SecureMail
├── User App
│   ├── Login
│   ├── Register
│   ├── Inbox
│   ├── Sent
│   ├── Compose
│   └── Security / Certificates
├── Monitoring Dashboard
│   ├── Service Overview
│   ├── Event Stream
│   ├── Security Metrics
│   ├── Alerts
│   └── Session Timeline
└── Scenario Lab
    ├── Scenario List
    ├── Run Console
    ├── Result Summary
    └── Evidence Viewer
```

### 4.2. Bố cục ứng dụng

Layout tổng thể:

```text
┌──────────────────────────────────────────────────────────────┐
│ Header: SecureMail | Current User | Ticket | Service Status   │
├──────────────┬───────────────────────────────────┬───────────┤
│ Left Nav     │ Main Workspace                    │ Right Bar │
│ User App     │ Màn hình hiện tại                 │ Security  │
│ Monitor      │ Inbox / Compose / Dashboard       │ Flow Log  │
│ Scenario Lab │                                   │ Context   │
└──────────────┴───────────────────────────────────┴───────────┘
```

Header nên luôn hiển thị:

- User hiện tại: `alice@mail.local` hoặc `Not logged in`.
- TGT status: `No TGT`, `TGT Active`, `Expired`.
- Service Ticket status: `No ST`, `ST Active`, `Expires in 24m`.
- Service indicators: CA, KDS, Ticket, SMTP, POP3.

Right Bar thay đổi theo màn hình:

- Login/Register: hiển thị authentication flow.
- Compose: hiển thị security flow gửi mail.
- Mail Detail: hiển thị verify/decrypt result.
- Monitoring: hiển thị selected event detail.
- Scenario: hiển thị mô tả cơ chế bảo mật đang chứng minh.

---

## 5. Design System

### 5.1. Tông giao diện

SecureMail là công cụ bảo mật nội bộ, nên giao diện cần:

- Rõ ràng, chuyên nghiệp, thiên về dashboard vận hành.
- Không dùng landing page hoặc hero marketing.
- Không dùng quá nhiều màu trang trí.
- Ưu tiên bảng, status badge, timeline, log stream.
- Tất cả trạng thái bảo mật phải dễ nhìn trong lúc thuyết trình.

### 5.2. Màu sắc đề xuất

| Token | Màu | Dùng cho |
|---|---|---|
| Background | `#F7F8FA` | Nền chính |
| Surface | `#FFFFFF` | Panel, table, form |
| Text Primary | `#17202A` | Nội dung chính |
| Text Muted | `#697386` | Mô tả phụ |
| Border | `#D8DEE8` | Đường chia |
| Primary | `#2563EB` | Nút chính, selected nav |
| Success | `#15803D` | Verified, active, pass |
| Warning | `#B45309` | Quarantine, warning |
| Danger | `#B91C1C` | Revoked, invalid, replay blocked |
| Info | `#0E7490` | Encryption, ticket issued |

### 5.3. Badge bảo mật

| Badge | Màu | Ý nghĩa |
|---|---|---|
| `SIGNED` | Info | Email có chữ ký S/MIME |
| `ENCRYPTED` | Info | Nội dung được mã hóa |
| `VERIFIED` | Success | Signature valid, cert chain good |
| `SECURE` | Success | Phân loại an toàn tổng hợp |
| `WARNING` | Warning | DMARC quarantine, SPF/DKIM anomaly |
| `DANGEROUS` | Danger | Signature invalid, reject, decrypt error |
| `REVOKED` | Danger | Certificate đã bị thu hồi |
| `TGT ACTIVE` | Success | Đăng nhập Kerberos thành công |
| `ST ACTIVE` | Success | Có Service Ticket hợp lệ |
| `REPLAY BLOCKED` | Danger | Authenticator bị dùng lại |

### 5.4. Thành phần UI dùng lặp lại

| Component | Mô tả |
|---|---|
| `StatusPill` | Badge nhỏ cho service/ticket/cert |
| `SecurityBadge` | Badge `SECURE/WARNING/DANGEROUS` |
| `MetricCard` | Số mail, số encrypted, số signed, số revoked |
| `EventRow` | Một dòng log có timestamp, service, event, details |
| `TimelineStep` | Một bước trong flow gửi mail/login |
| `CertSummary` | Subject, issuer, serial, validity, revoked/good |
| `MailTable` | Inbox/Sent table |
| `OperationLogPanel` | Log riêng theo thao tác hiện tại |
| `ScenarioCard` | Mô tả và trạng thái một scenario |

---

## 6. User App

## 6.1. Màn hình Login

### Mục tiêu

Cho người dùng đăng nhập như mail client thật, đồng thời cho người xem thấy Kerberos-lite đang hoạt động.

### Layout

```text
┌──────────────────────── Login ────────────────────────┬───────────────┐
│ Email / Username                                      │ Auth Status    │
│ Password                                              │ Cert: Found    │
│ [ Login ] [ Register ]                               │ TGT: None      │
│                                                       │ ST: None       │
│ Error/success message                                 │               │
└───────────────────────────────────────────────────────┴───────────────┘
```

### Thành phần

| Thành phần | Loại | Hành vi |
|---|---|---|
| Email input | Text input | Nhập `alice@mail.local` |
| Password input | Password | Không hiển thị plaintext |
| Login button | Primary button | Gọi `client_core.login(email, password)` |
| Register button | Secondary button | Chuyển sang Register |
| Remember session | Checkbox | Nếu bật, gọi `client_core.save_session(ctx)` |
| Certificate status | StatusPill | Kiểm tra `data/users/<email>.cert.pem` |
| Local key status | StatusPill | Kiểm tra `data/users/<email>.key.pem` |
| TGT status | StatusPill | Sau login hiển thị TGT length và active |

### Mapping code

| UI action | Code hiện có |
|---|---|
| Login | `client_core.login(email, password)` |
| Save session | `client_core.save_session(ctx)` |
| Load session | `client_core.load_session()` |
| Logout | `client_core.clear_session()` |

### Flow hiển thị khi login thành công

```text
1. Đọc private key local
2. Gửi AS-REQ đến Ticket Service
3. Nhận AS-REP
4. Dẫn xuất Kc từ password
5. Giải mã AS-REP
6. Nhận TGT + K_c_tgs
7. Session ready
```

### Trạng thái lỗi cần hiển thị

| Lỗi | Thông báo UI |
|---|---|
| Không có key/cert local | `Local certificate/private key not found. Please register first.` |
| Sai password | `Login failed: cannot decrypt private key or AS-REP.` |
| Ticket Service down | `Ticket Service is offline or unreachable.` |
| Session file lỗi | `Saved session is corrupted. Please login again.` |

---

## 6.2. Màn hình Register

### Mục tiêu

Cho thấy toàn bộ register flow: tạo keypair, gửi CSR lên CA, nhận cert, publish KDS, đăng ký Kerberos principal.

### Layout

```text
┌────────────────────── Register Account ───────────────────────┐
│ Full name                                                      │
│ Email                                                          │
│ Password                                                       │
│ Role: user / admin / mailing_list_manager                      │
│ [ Generate Keypair + Register ]                                │
├────────────────────── Progress ────────────────────────────────┤
│ [ ] Generate RSA-2048 keypair                                  │
│ [ ] Build CSR                                                  │
│ [ ] CA signs certificate                                       │
│ [ ] Publish cert to KDS                                        │
│ [ ] Register principal at Ticket Service                       │
│ [ ] Save local key/cert                                        │
└────────────────────────────────────────────────────────────────┘
```

### Mapping code

| Bước | Code hiện có |
|---|---|
| Generate RSA keypair | `rsa_handler.generate_keypair(2048)` trong `client_core.register` |
| Build CSR | `x509.CertificateSigningRequestBuilder` trong `client_core.register` |
| CA sign CSR | RPC `ca.sign_csr` qua `request("127.0.0.1", 9000, ...)` |
| Publish cert | `kds_client.put_cert(email, serial_hex, cert_pem)` |
| Register principal | `ts_client.register(email, salt, kc, role)` |
| Save local files | `data/users/*.key.pem`, `*.cert.pem`, `*.salt.bin` |

### Output sau khi register

Hiển thị:

- Email đã đăng ký.
- Serial certificate.
- Certificate status: `GOOD`.
- KDS publish: `DONE`.
- Kerberos principal: `DONE`.
- Local files: key/cert/salt.

### Điểm demo nên nhấn mạnh

Màn này rất đáng đưa vào demo vì nó chứng minh hệ thống không chỉ có tài khoản/mật khẩu, mà có identity mật mã đầy đủ:

- RSA private key nằm local.
- Public cert được CA ký.
- KDS chỉ phân phối cert, client vẫn verify chain.
- Ticket Service không lưu password plaintext, chỉ lưu key dẫn xuất.

---

## 6.3. Màn hình Inbox

### Mục tiêu

Hiển thị mailbox như email client thật, có nhãn bảo mật rõ ràng.

### Layout

```text
┌ Sidebar ──────┬──────────────────── Inbox ────────────────────┬ Security ┐
│ Inbox         │ Search: [                    ] Filter: All     │ Summary  │
│ Sent          │                                                │ SECURE   │
│ Compose       │ ID | Status | From | Subject | Date            │ Signed   │
│ Security      │ 12 | SECURE | alice | ...    | ...             │ Encrypted│
│               │ 13 | WARNING| eve   | ...    | ...             │ DMARC    │
└───────────────┴────────────────────────────────────────────────┴──────────┘
```

### Cột trong danh sách mail

| Cột | Nguồn dữ liệu |
|---|---|
| ID | `msg["id"]` |
| Status | `client_core.classify_security(msg)` |
| From | `msg["sender"]` |
| Subject | `msg["subject"]` |
| Date | `msg["date"]` |
| Signature | `msg["signature_valid"]` |
| SPF | `msg["spf_result"]` |
| DKIM | `msg["dkim_result"]` |
| DMARC | `msg["dmarc_action"]` |

### Mapping code

| UI action | Code hiện có |
|---|---|
| Refresh inbox | `client_core.fetch_inbox(ctx)` |
| Read message | `client_core.fetch_message(ctx, msg_id)` |
| Classify security | `client_core.classify_security(msg)` |

### Bộ lọc nên có

| Filter | Logic |
|---|---|
| All | Hiện tất cả |
| Secure | `classify_security == SECURE` |
| Warning | `classify_security == WARNING` |
| Dangerous | `classify_security == DANGEROUS` |
| Signed | `signature_valid is True` |
| Failed | Có `error` hoặc `signature_valid is False` |
| Quarantine | `dmarc_action == quarantine` |

---

## 6.4. Màn hình Sent

### Mục tiêu

Hiển thị thư đã gửi, chứng minh tính năng dual encryption cho Sent Mail: sender cũng có envelope riêng để đọc lại.

### Layout

```text
┌ Sidebar ──────┬──────────────────── Sent ─────────────────────┬ Security ┐
│ Inbox         │ ID | To | Subject | Date | Envelope            │ Sender   │
│ Sent          │ 21 | bob | ...    | ...  | sender_copy         │ copy OK  │
│ Compose       │                                                │          │
└───────────────┴────────────────────────────────────────────────┴──────────┘
```

### Mapping code

| UI action | Code hiện có |
|---|---|
| Refresh sent | `client_core.fetch_sent(ctx)` |
| Read sent message | `client_core.fetch_sent_message(ctx, msg_id)` |

### Thông điệp demo

Mail server không lưu plaintext. Thư ở Sent cũng được mã hóa riêng bằng public key của người gửi, nên người gửi đọc lại được mà server vẫn không đọc được nội dung.

---

## 6.5. Màn hình Mail Detail

### Mục tiêu

Khi mở một email, người dùng thấy nội dung đã giải mã và các bằng chứng bảo mật.

### Layout

```text
┌──────────────────────── Message Detail ────────────────────────┐
│ From: alice@mail.local              Status: SECURE             │
│ To: bob@mail.local                                             │
│ Subject: [S1] Normal encrypted + signed                        │
│ Date: ...                                                      │
├────────────────────── Security Verification ───────────────────┤
│ S/MIME Signature: VALID                                        │
│ Signer Cert: GOOD                                              │
│ SPF: pass | DKIM: pass/none | DMARC: accept                    │
│ Decryption: SUCCESS                                            │
├──────────────────────── Body ──────────────────────────────────┤
│ Xin chào Bob...                                                │
└────────────────────────────────────────────────────────────────┘
```

### Thông tin bảo mật phải hiển thị

| Field | Ý nghĩa |
|---|---|
| Decryption | POP3 tải envelope, client giải mã CEK bằng private key |
| Signature | `signature_valid=True/False` |
| Signer | Subject trong cert người gửi |
| Cert status | Good / Revoked / Invalid chain |
| SPF | pass/fail/none |
| DKIM | pass/fail/none |
| DMARC | accept/quarantine/reject |
| Classification | SECURE/WARNING/DANGEROUS |

### Khi lỗi

| Lỗi | UI nên hiển thị |
|---|---|
| Không giải mã được | Badge `DANGEROUS`, message `Decryption failed` |
| Signature invalid | Badge `DANGEROUS`, message `S/MIME signature is invalid` |
| DMARC quarantine | Badge `WARNING`, message `Sender identity requires attention` |
| Cert revoked | Badge `DANGEROUS`, message `Sender certificate was revoked` |

---

## 6.6. Màn hình Compose

### Mục tiêu

Đây là màn hình quan trọng nhất khi thuyết trình. Người dùng gửi mail như bình thường, còn panel bên phải hiển thị từng bước bảo vệ email.

### Layout

```text
┌──────────────────────── Compose ───────────────────────┬ Security Flow ┐
│ To: [bob@mail.local                         ]          │ 1 KDS lookup  │
│ Subject: [Secret report                      ]          │ 2 Verify cert │
│                                                        │ 3 Sign body   │
│ [x] Sign email     [x] Encrypt email                   │ 4 Create CEK  │
│ [x] Request/Reuse service ticket                       │ 5 Encrypt     │
│                                                        │ 6 STARTTLS    │
│ Body                                                   │ 7 AUTH ST     │
│ ┌────────────────────────────────────────────────────┐ │ 8 SMTP DATA   │
│ │ ...                                                │ │               │
│ └────────────────────────────────────────────────────┘ │               │
│ [ Fetch recipient cert ] [ Send Secure Mail ]          │               │
└────────────────────────────────────────────────────────┴───────────────┘
```

### Thành phần

| Thành phần | Loại | Ghi chú |
|---|---|---|
| To | Text input/token input | Hỗ trợ 1 hoặc nhiều recipient |
| Subject | Text input | Bắt buộc |
| Body | Multiline editor | Bắt buộc |
| Sign email | Checkbox | Mặc định bật, vì hệ thống hiện build envelope có ký |
| Encrypt email | Checkbox | Mặc định bật, vì hệ thống hiện build envelope có mã hóa |
| Fetch recipient cert | Button | Kiểm tra KDS/CA trước khi gửi |
| Send Secure Mail | Primary button | Gọi send |
| Security Flow | Timeline panel | Update từng bước |

### Mapping code

| Bước UI | Code hiện có |
|---|---|
| Fetch recipient cert | `kds_client.bulk_get(recipient_emails)` |
| Get CA root | `request("127.0.0.1", 9000, {"op": "ca.root_cert"})` |
| Get CRL | `kds_client.get_crl()` |
| Verify cert | `cert_validator.verify_chain(cert_pem, ca_cert_pem, crl_pem)` |
| OCSP check | RPC `ca.ocsp` |
| Build S/MIME | `smime_handler.build_envelope(...)` |
| Get Service Ticket | `client_core.get_service_ticket(ctx)` |
| Send SMTP | `smtp_client.send_mail(...)` |
| Full send | `client_core.send_secure_email(ctx, recipients, subject, body)` |

### Security Flow chi tiết

```text
[KDS] Lookup cert for bob@mail.local
[CA] Load Root CA cert
[CRL] Download CRL from KDS
[VERIFY] Bob cert chain valid
[OCSP] Bob cert status = good
[S/MIME] Sign body with Alice private key
[S/MIME] Generate CEK
[S/MIME] Encrypt body with AES-128-CBC
[S/MIME] Encrypt CEK with Bob RSA-OAEP public key
[KERBEROS] Request/reuse Service Ticket for mail/securemail
[TLS] STARTTLS-lite handshake
[SMTP] AUTH with Service Ticket + Authenticator
[SMTP] MAIL FROM / RCPT TO / DATA
[POLICY] SPF/DKIM/DMARC result
[STORE] Encrypted envelope stored
```

### Kết quả gửi thành công

Hiển thị modal hoặc toast:

```text
Mail sent securely.
Recipient envelope: 2154 bytes
Sender copy envelope: 2154 bytes
DMARC: accept
MTA DKIM: YES
```

### Kết quả gửi thất bại

| Case | UI |
|---|---|
| Không có cert người nhận | `Cannot send: recipient certificate not found in KDS.` |
| Cert invalid | `Cannot send: certificate chain invalid.` |
| Cert revoked | `Cannot send: recipient certificate is revoked.` |
| Service Ticket lỗi | `Cannot authenticate to Mail Server. Please login again.` |
| SMTP offline | `SMTP service is offline.` |

---

## 6.7. Màn hình Security / Certificates

### Mục tiêu

Tập trung các thông tin định danh mật mã của user hiện tại.

### Layout

```text
┌──────────────────── Security / Certificates ───────────────────┐
│ Current User: alice@mail.local                                  │
│ Role: user                                                      │
├──────────────────── Certificate ────────────────────────────────┤
│ Subject | Issuer | Serial | Valid From | Valid To | Status      │
├──────────────────── Kerberos Session ───────────────────────────┤
│ TGT: active | TGT length | K_c_tgs present                      │
│ Service Ticket: mail/securemail | expires in ...                │
├──────────────────── Key Recovery ───────────────────────────────┤
│ [ Recover private key using shares 1 + 2 ]                      │
└────────────────────────────────────────────────────────────────┘
```

### Mapping code

| UI action | Code hiện có |
|---|---|
| Show local cert | Đọc `data/users/<email>.cert.pem` |
| Show cert from KDS | `kds_client.get_cert(email)` |
| OCSP check | RPC `ca.ocsp` |
| Recover key | `client_core.recover_user_key(email, [1, 2])` |
| Show current session | `client_core.load_session()` hoặc app state ctx |

### Cảnh báo cần có

- Local cert khác KDS cert.
- Cert hết hạn hoặc revoked.
- Không có private key local.
- TGT/ST hết hạn.
- Recover key sẽ ghi đè private key local.

---

## 7. Monitoring / Admin Dashboard

## 7.1. Mục tiêu

Dashboard giúp người xem thấy backend đang làm gì và hệ thống phát hiện tấn công như thế nào. Đây là phần biến một CLI demo thành hệ thống có tính quan sát.

### Layout tổng thể

```text
┌──────────────────────── Monitoring Dashboard ─────────────────────────┐
│ CA: ON | KDS: ON | Ticket: ON | SMTP: ON | POP3: ON                    │
├──────────────────── Metrics ──────────────────────────────────────────┤
│ Mails: 42 | Encrypted: 42 | Signed: 42 | Active Tickets: 3             │
│ Revoked Certs: 1 | Replay Blocked: 2 | Spoof Quarantine: 1             │
├──────────────────── Event Stream ───────────────┬ Alerts ─────────────┤
│ 10:20 CA      CERT_ISSUED alice@mail.local      │ Replay blocked      │
│ 10:21 TICKET  TGT_ISSUED alice@mail.local       │ Cert revoked        │
│ 10:22 KDS     CERT_LOOKUP bob@mail.local        │ DMARC quarantine    │
│ 10:23 MAIL    SMTP_ACCEPT ...                   │                     │
├──────────────────── Session Timeline ─────────────────────────────────┤
│ Alice login -> TGT -> ST -> KDS lookup -> Sign -> Encrypt -> SMTP      │
└───────────────────────────────────────────────────────────────────────┘
```

---

## 7.2. Service Overview

### Service cards

| Card | Check |
|---|---|
| CA | TCP connect `127.0.0.1:9000` hoặc RPC `ca.root_cert` |
| KDS | TCP connect `127.0.0.1:9001` hoặc `kds_client.get_crl()` |
| Ticket Service | TCP connect `127.0.0.1:9002` |
| SMTP | TCP connect `127.0.0.1:2525` |
| POP3 | TCP connect `127.0.0.1:1100` |
| SQL Server | Gọi `get_conn()` và query nhẹ |

### Trạng thái

| Status | UI |
|---|---|
| ON | Green pill |
| OFF | Red pill |
| DEGRADED | Yellow pill, có lỗi chi tiết |
| UNKNOWN | Gray pill |

---

## 7.3. Event Stream

### Nguồn log

Hiện project đã có `view_logs.py` đọc:

- `ca.audit_log`
- `ticket.audit_log`
- `kds.audit_log`
- `mail.server_log`

### Cột bảng log

| Cột | Nguồn |
|---|---|
| Time | `ts` |
| Service | CA/TICKET/KDS/MAIL |
| Event | `event` |
| Details | `details` |
| Severity | Suy luận từ event/details |

### Filter

| Filter | Ý nghĩa |
|---|---|
| All | Tất cả event |
| CA | Chỉ CA |
| Ticket | Chỉ AS/TGS |
| KDS | Chỉ certificate lookup/publish |
| Mail | SMTP/POP3 |
| Security only | Replay, revoke, spoof, invalid signature |
| Errors | Event lỗi |

### Ví dụ event hiển thị

```text
[LOGIN] alice@mail.local đăng nhập thành công
[KDC] cấp TGT cho alice@mail.local
[TGS] cấp Service Ticket cho alice@mail.local -> mail/securemail
[KDS] alice truy vấn cert của bob@mail.local
[SMTP] mail gửi từ alice@mail.local tới bob@mail.local
[POP3] bob@mail.local tải mail
[VERIFY] signature_valid=True
[ALERT] replay authenticator rejected
```

---

## 7.4. Security Metrics

### Metric cards

| Metric | Cách tính |
|---|---|
| Total mails | `COUNT(*) FROM mail.mailbox` |
| Encrypted mails | Vì envelope là S/MIME, có thể tính bằng total mails hoặc parse envelope |
| Signed mails | Count mail mở được và `signature_valid=True`, hoặc suy ra từ S/MIME flow |
| DMARC accept | `COUNT(*) WHERE dmarc_action='accept'` |
| DMARC quarantine | `COUNT(*) WHERE dmarc_action='quarantine'` |
| SPF fail | `COUNT(*) WHERE spf_result='fail'` |
| DKIM fail | `COUNT(*) WHERE dkim_result='fail'` |
| Revoked certs | `COUNT(*) FROM ca.issued WHERE status='revoked'` |
| Active principals | `COUNT(*) FROM ticket.principals` |
| Revoked TGTs | `COUNT(*) FROM ticket.revoked_tgts` |
| Replay blocked | Đếm event log chứa `replay` |

### Biểu đồ nên có

- Mail theo thời gian.
- Tỷ lệ `accept/quarantine/reject`.
- Cert good vs revoked.
- Event theo service.

---

## 7.5. Alerts

### Alert types

| Alert | Điều kiện |
|---|---|
| Public-key substitution | Cert không verify được chain CA |
| Replay attack | Authenticator bị reuse |
| Revoked certificate | Cert nằm trong CRL/OCSP status revoked |
| Spoofed sender | SPF fail hoặc Kerberos identity khác MAIL FROM |
| Signature invalid | `signature_valid=False` |
| DMARC quarantine/reject | `dmarc_action in ('quarantine', 'reject')` |
| Key recovery | Có event khôi phục khóa Shamir |
| Service down | Không connect được service |

### Alert detail

Khi click một alert:

- Time.
- Service phát hiện.
- Actor: user/email nếu có.
- Affected target: recipient/cert/ticket nếu có.
- Evidence: log details hoặc scenario output.
- Recommended explanation: câu ngắn dùng để thuyết trình.

Ví dụ:

```text
Alert: Replay Attack Blocked
Service: SMTP / Ticket Auth
Evidence: authenticator nonce already used
Meaning: Kẻ tấn công dùng lại gói AUTH cũ nhưng bị replay cache chặn.
```

---

## 7.6. Session Timeline

### Mục tiêu

Cho người thuyết trình chọn một phiên gửi mail và xem từng bước bảo mật.

### Timeline cho happy path

```text
1. Alice login
2. Ticket Service cấp TGT
3. Alice xin Service Ticket cho mail/securemail
4. Alice lookup cert Bob từ KDS
5. Alice verify cert + CRL + OCSP
6. Alice ký body bằng private key
7. Alice sinh CEK và mã hóa body
8. Alice mã hóa CEK bằng public key Bob
9. SMTP STARTTLS-lite
10. SMTP AUTH bằng ST + Authenticator
11. SMTP kiểm tra SPF/DKIM/DMARC
12. Mail server lưu encrypted envelope
13. Bob POP3 fetch
14. Bob giải mã CEK bằng private key
15. Bob verify chữ ký Alice
```

### Timeline cho attack

| Scenario | Timeline đặc biệt |
|---|---|
| MITM | KDS nhận cert giả -> Client verify chain -> Reject |
| Replay | AUTH lần 1 OK -> AUTH lần 2 cùng nonce -> Replay cache reject |
| Revoked cert | CA revoke -> CRL sync KDS -> Client verify CRL -> Refuse send |
| Spoof | Eve AUTH bằng ticket Eve -> MAIL FROM Alice -> DMARC quarantine/reject |

---

## 8. Scenario Lab

## 8.1. Mục tiêu

Giữ lại sức mạnh `run_demo.py`: chạy nhanh các kịch bản kiểm thử và hiển thị kết quả có cấu trúc.

### Layout

```text
┌──────────────────────── Scenario Lab ──────────────────────────┐
│ [ Bootstrap ] [ Run All ]                                      │
├──────────────────── Scenario List ─────────────────────────────┤
│ 1 Normal encrypted + signed email       [ Run ] [PASS/FAIL]    │
│ 2 MITM / Public-key substitution        [ Run ] [PASS/FAIL]    │
│ 3 Replay Attack                         [ Run ] [PASS/FAIL]    │
│ 4 Revoked Certificate                   [ Run ] [PASS/FAIL]    │
│ 5 Spoofed Sender                        [ Run ] [PASS/FAIL]    │
│ 6 Reusable Ticket                       [ Run ] [PASS/FAIL]    │
│ 7 Key Recovery                          [ Run ] [PASS/FAIL]    │
│ 8 HKDF Subsession Key                   [ Run ] [PASS/FAIL]    │
├──────────────────── Console Output ────────────────────────────┤
│ ...                                                            │
└────────────────────────────────────────────────────────────────┘
```

### Mapping code

| UI action | Code hiện có |
|---|---|
| Bootstrap | `python -m securemail.run_demo bootstrap` hoặc `run_demo.bootstrap()` |
| Run scenario 1 | `run_demo.scenario_1_normal_flow()` |
| Run scenario 2 | `run_demo.scenario_2_mitm_substitution()` |
| Run all | Loop `run_demo.SCENARIOS` |

### Danh sách scenario

| # | Tên | Điều chứng minh | Expected |
|---|---|---|---|
| 1 | Normal encrypted + signed email | S/MIME + SMTP/POP3 happy path | PASS |
| 2 | MITM / Public-key substitution | Cert giả bị reject vì không do CA ký | PASS |
| 3 | Replay Attack | Authenticator reuse bị chặn | PASS |
| 4 | Revoked Certificate | Cert revoked làm send bị từ chối | PASS |
| 5 | Spoofed Sender | SPF/DMARC phát hiện giả mạo | PASS |
| 6 | Reusable Ticket | Một ST dùng nhiều lần với authenticator mới | PASS |
| 7 | Key Recovery | Shamir 2-of-3 khôi phục key | PASS |
| 8 | HKDF Subsession Key | Key con khác nhau theo context | PASS |

### Evidence Viewer

Khi scenario chạy xong, UI nên trích ra:

- Outcome: PASS/FAIL.
- Security mechanism: cơ chế đã chứng minh.
- Raw console output.
- Related logs từ dashboard.
- Giải thích ngắn cho slide/demo.

Ví dụ cho Scenario 3:

```text
PASS - Replay rejected
First use of authenticator: ok=True
Replayed authenticator: ok=False error=replay detected

Explanation:
Authenticator chứa timestamp và nonce. SMTP server lưu replay cache trong window 5 phút.
Gói AUTH cũ bị gửi lại sẽ bị từ chối.
```

---

## 9. Luồng người dùng chính

## 9.1. Flow đăng ký và đăng nhập

```text
Register screen
  -> nhập email/password/name
  -> Generate keypair + CSR
  -> CA sign
  -> KDS publish
  -> Ticket principal register
  -> Login screen
  -> login
  -> Inbox
```

## 9.2. Flow gửi mail bảo mật

```text
Login
  -> Compose
  -> nhập To/Subject/Body
  -> Fetch recipient cert
  -> Verify chain + CRL + OCSP
  -> Send Secure Mail
  -> Security Flow chạy từng bước
  -> Result toast
  -> Sent folder
```

## 9.3. Flow nhận và đọc mail

```text
Login Bob
  -> Inbox
  -> Refresh
  -> POP3 STARTTLS + AUTH
  -> Retrieve envelope
  -> Decrypt CEK
  -> Decrypt body
  -> Verify signature
  -> Open detail
```

## 9.4. Flow demo tấn công

```text
Monitoring Dashboard mở sẵn
  -> Scenario Lab
  -> Run Scenario
  -> Event Stream cập nhật
  -> Alert xuất hiện
  -> Click Alert để giải thích
```

---

## 10. Trạng thái ứng dụng

### 10.1. App state

```text
AppState
  current_user: str | None
  ctx: dict | None
  services:
    ca: ON/OFF
    kds: ON/OFF
    ticket: ON/OFF
    smtp: ON/OFF
    pop3: ON/OFF
  inbox_cache: list[dict]
  sent_cache: list[dict]
  selected_message: dict | None
  selected_scenario: str | None
  operation_log: list[OperationEvent]
```

### 10.2. Ticket state

| State | Điều kiện |
|---|---|
| Not logged in | `ctx is None` |
| TGT available | `ctx["tgt"]` và `ctx["k_c_tgs"]` tồn tại |
| ST not requested | Chưa gọi `get_service_ticket` |
| ST active | Có `ticket_v`, `k_c_v`, lifetime |
| Expired | Request bị service từ chối do ticket expired |

### 10.3. Mail security state

| State | Điều kiện |
|---|---|
| SECURE | Signature valid, DMARC accept, SPF pass, không có error |
| WARNING | DMARC quarantine, SPF/DKIM fail nhẹ, sender ngoài domain |
| DANGEROUS | Decrypt error, signature invalid, DMARC reject |

---

## 11. Wireframe chi tiết

## 11.1. Header

```text
┌────────────────────────────────────────────────────────────────────────┐
│ SecureMail  |  alice@mail.local  |  TGT ACTIVE  |  ST ACTIVE 24m       │
│ CA ON | KDS ON | TICKET ON | SMTP ON | POP3 ON                         │
└────────────────────────────────────────────────────────────────────────┘
```

Actions:

- Click user -> account/security.
- Click TGT/ST -> mở session detail.
- Click service status -> mở Monitoring Dashboard.

## 11.2. Sidebar

```text
User App
  Inbox
  Sent
  Compose
  Security

Monitoring
  Overview
  Events
  Alerts
  Timeline

Scenario Lab
  Scenarios
  Results
```

## 11.3. Right Security Panel

Context theo màn hình:

| Màn hình | Nội dung right panel |
|---|---|
| Login | Kerberos AS flow |
| Register | Register progress |
| Inbox | Security summary của selected mail |
| Compose | Send security timeline |
| Security | Certificate detail |
| Monitoring | Selected event detail |
| Scenario | Mechanism explanation |

---

## 12. Mapping UI với code hiện có

### 12.1. Auth

| Feature | Hàm/file |
|---|---|
| Register | `securemail.client_core.register` |
| Login | `securemail.client_core.login` |
| Save session | `securemail.client_core.save_session` |
| Load session | `securemail.client_core.load_session` |
| Logout | `securemail.client_core.clear_session` |
| Recover key | `securemail.client_core.recover_user_key` |

### 12.2. Mail

| Feature | Hàm/file |
|---|---|
| Send | `securemail.client_core.send_secure_email` |
| Inbox | `securemail.client_core.fetch_inbox` |
| Read inbox mail | `securemail.client_core.fetch_message` |
| Sent | `securemail.client_core.fetch_sent` |
| Read sent mail | `securemail.client_core.fetch_sent_message` |
| Security label | `securemail.client_core.classify_security` |

### 12.3. Certificate

| Feature | Hàm/file |
|---|---|
| KDS lookup | `securemail.kds.kds_client.get_cert`, `bulk_get` |
| CRL | `securemail.kds.kds_client.get_crl` |
| Verify chain | `securemail.auth.cert_validator.verify_chain` |
| OCSP | RPC `ca.ocsp` qua `network.json_framing.request` |
| CA root cert | RPC `ca.root_cert` |

### 12.4. Monitoring

| Feature | Nguồn |
|---|---|
| CA logs | `ca.audit_log` |
| KDS logs | `kds.audit_log` |
| Ticket logs | `ticket.audit_log` |
| Mail logs | `mail.server_log` |
| Metrics mail | `mail.mailbox` |
| Metrics cert | `ca.issued`, `kds.certs` |
| Metrics ticket | `ticket.principals`, `ticket.revoked_tgts` |
| Current helper | `view_logs.py` |

### 12.5. Scenario

| Feature | Hàm/file |
|---|---|
| Bootstrap | `securemail.run_demo.bootstrap` |
| Scenario list | `securemail.run_demo.SCENARIOS` |
| Scenario 1-8 | `securemail.run_demo.scenario_*` |

---

## 13. Các controller nên viết

## 13.1. AuthController

```text
login(email, password, remember=False)
register(email, password, display_name, role="user")
logout()
load_saved_session()
get_current_status()
recover_key(email, share_indices)
```

Trả về object thống nhất:

```text
{
  ok: bool,
  message: str,
  data: dict | None,
  operation_log: list[str]
}
```

## 13.2. MailController

```text
refresh_inbox()
refresh_sent()
read_message(id)
read_sent_message(id)
send_mail(to, subject, body, options)
preview_recipient_cert(to)
```

## 13.3. MonitorController

```text
check_services()
get_metrics()
get_logs(service="all", limit=200)
get_alerts()
get_session_timeline(message_id=None)
```

## 13.4. ScenarioController

```text
bootstrap()
run_scenario(number)
run_all()
parse_result(output)
```

---

## 14. Quy tắc hiển thị lỗi

### 14.1. Nguyên tắc

- Không show traceback Python cho người dùng thường.
- Luôn có thông báo ngắn, dễ hiểu.
- Có nút `Show technical detail` cho demo/kỹ thuật.
- Operation log giữ lại chi tiết từng bước.

### 14.2. Bảng lỗi

| Lỗi kỹ thuật | Message thân thiện |
|---|---|
| Connection refused port 9000 | `CA Service is offline. Please start python -m securemail.main_ca serve.` |
| Connection refused port 9001 | `KDS is offline. Cannot fetch certificates.` |
| Connection refused port 9002 | `Ticket Service is offline. Cannot login.` |
| Connection refused port 2525 | `SMTP service is offline. Cannot send mail.` |
| Connection refused port 1100 | `POP3 service is offline. Cannot fetch inbox.` |
| no cert for recipient | `Recipient has no certificate in KDS.` |
| cert revoked | `Recipient certificate has been revoked.` |
| replay detected | `Replay attack blocked.` |
| signature invalid | `Email signature is invalid.` |
| decrypt failed | `Cannot decrypt this message with current private key.` |

---

## 15. Demo script đề xuất

### Demo 1: Happy path

1. Mở Monitoring Dashboard.
2. Login Alice.
3. Compose mail gửi Bob.
4. Bật Security Flow panel.
5. Send.
6. Login Bob.
7. Inbox -> mở mail.
8. Chỉ vào badge `ENCRYPTED`, `SIGNED`, `VERIFIED`, `SECURE`.

Thông điệp:

```text
Mail server chỉ lưu encrypted envelope. Bob là người duy nhất giải mã được nội dung.
Chữ ký số chứng minh Alice thật sự gửi mail này.
```

### Demo 2: MITM/Public-key substitution

1. Scenario Lab -> Run scenario 2.
2. Dashboard hiển thị alert public-key substitution.
3. Mở Evidence Viewer.

Thông điệp:

```text
KDS có thể bị chèn cert giả, nhưng client không tin KDS mù quáng.
Client verify chain về Root CA nên cert giả bị từ chối.
```

### Demo 3: Replay attack

1. Scenario Lab -> Run scenario 3.
2. Xem log `First use ok=True`, `Replay ok=False`.
3. Dashboard alert `REPLAY BLOCKED`.

Thông điệp:

```text
Ticket có thể reuse, nhưng Authenticator phải mới mỗi lần.
Nonce/timestamp cũ bị replay cache chặn.
```

### Demo 4: Revoked certificate

1. Scenario Lab -> Run scenario 4.
2. Dashboard hiển thị cert Alice revoked.
3. Bob gửi mail cho Alice bị từ chối.

Thông điệp:

```text
CRL/OCSP giúp hệ thống ngừng gửi dữ liệu mật tới người có chứng chỉ bị thu hồi.
```

### Demo 5: Spoofed sender

1. Scenario Lab -> Run scenario 5.
2. Bob inbox thấy `WARNING` hoặc DMARC quarantine.
3. Mail detail hiển thị SPF fail/DMARC quarantine.

Thông điệp:

```text
Eve có ticket của Eve nhưng không thể giả danh Alice một cách sạch sẽ.
Hệ thống đối chiếu Kerberos identity và MAIL FROM/policy.
```

---

## 16. Lộ trình triển khai UI

### Giai đoạn 1: Client App cơ bản

Mục tiêu: có app mail thật.

Nên làm:

- Login screen.
- Register screen.
- Inbox/Sent.
- Mail Detail.
- Compose.
- Security badges.

Files thêm:

```text
securemail/gui/app.py
securemail/gui/state.py
securemail/gui/controllers/auth_controller.py
securemail/gui/controllers/mail_controller.py
securemail/gui/views/login_view.py
securemail/gui/views/register_view.py
securemail/gui/views/mailbox_view.py
securemail/gui/views/compose_view.py
```

### Giai đoạn 2: Security Status

Mục tiêu: làm rõ chất SecureMail.

Nên làm:

- Ticket status ở header.
- Cert detail.
- Security flow khi gửi mail.
- Mail detail có full verification panel.
- Key recovery UI.

### Giai đoạn 3: Monitoring Dashboard

Mục tiêu: quan sát backend.

Nên làm:

- Service status cards.
- Event stream đọc từ audit log.
- Metrics cards.
- Alert list.
- Session timeline.

Files thêm:

```text
securemail/gui/controllers/monitor_controller.py
securemail/gui/views/monitor_view.py
```

### Giai đoạn 4: Scenario Lab

Mục tiêu: bảo vệ đồ án tốt hơn khi giảng viên hỏi.

Nên làm:

- Danh sách 8 scenario.
- Bootstrap button.
- Run scenario / Run all.
- Console output.
- PASS/FAIL badge.
- Evidence explanation.

Files thêm:

```text
securemail/gui/controllers/scenario_controller.py
securemail/gui/views/scenario_lab_view.py
```

---

## 17. Ưu tiên màn hình khi thời gian ít

Nếu chỉ có ít thời gian, ưu tiên theo thứ tự:

1. Login.
2. Compose có Security Flow.
3. Inbox + Mail Detail có badge bảo mật.
4. Monitoring Event Stream.
5. Scenario Lab.
6. Register.
7. Security/Certificates.

Lý do: Login -> Compose -> Inbox là luồng demo chính. Monitoring và Scenario Lab giúp trả lời câu hỏi bảo mật. Register đẹp nhưng có thể dùng bootstrap sẵn nếu thiếu thời gian.

---

## 18. Checklist hoàn thành UI

### Client App

- [ ] User đăng ký được tài khoản mới.
- [ ] User đăng nhập được bằng email/password.
- [ ] Header hiển thị current user và TGT status.
- [ ] Gửi mail được từ Alice sang Bob.
- [ ] Inbox hiển thị mail mới.
- [ ] Mở mail thấy body đã giải mã.
- [ ] Mail detail hiển thị signature/SPF/DKIM/DMARC.
- [ ] Sent folder đọc lại được sender copy.
- [ ] Key recovery chạy được với share 1 + 2.

### Monitoring

- [ ] Hiển thị CA/KDS/Ticket/SMTP/POP3 ON/OFF.
- [ ] Đọc được log từ 4 audit table.
- [ ] Có metric mail/cert/ticket.
- [ ] Có alert replay/spoof/revoked/quarantine.
- [ ] Có timeline phiên gửi mail.

### Scenario Lab

- [ ] Bootstrap được.
- [ ] Run từng scenario được.
- [ ] Run all được.
- [ ] Hiển thị PASS/FAIL.
- [ ] Có phần giải thích ý nghĩa mỗi scenario.

---

## 19. Kết luận thiết kế

Hướng UI tốt nhất cho SecureMail là không thay thế toàn bộ CLI hiện tại, mà bọc các hàm lõi đã có thành 3 trải nghiệm:

1. User App để người dùng thao tác thật với email.
2. Monitoring Dashboard để người xem thấy hệ thống bảo mật đang vận hành.
3. Scenario Lab để chứng minh các case tấn công và cơ chế phòng thủ.

Thiết kế này phù hợp với bản chất đồ án vì SecureMail có 2 tầng cần thể hiện cùng lúc:

- Tầng nghiệp vụ: đăng ký, đăng nhập, gửi mail, nhận mail.
- Tầng bảo mật: chứng chỉ, ticket, mã hóa, chữ ký, CRL/OCSP, replay cache, SPF/DKIM/DMARC, key recovery.

Nếu triển khai theo tài liệu này, demo sẽ thuyết phục hơn giao diện scenario-only vì người xem vừa thấy hệ thống email hoạt động như thật, vừa thấy bằng chứng kỹ thuật bảo mật ngay trên từng thao tác.
