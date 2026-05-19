# TÀI LIỆU KỸ THUẬT CHUYÊN SÂU: HỆ THỐNG SECURE MAIL

Tài liệu này cung cấp phân tích mã nguồn chi tiết, chuyên sâu ở cấp độ kỹ sư mật mã (cryptography expert) cho hệ thống thư điện tử bảo mật nội bộ **SecureMail**. 

## 1. PROJECT OVERVIEW (TỔNG QUAN DỰ ÁN)

### Bài toán thực tế
Các hệ thống email truyền thống (như SMTP/POP3 tiêu chuẩn) thường truyền tải dữ liệu dưới dạng văn bản thuần (plaintext) hoặc chỉ mã hóa đường truyền (TLS/SSL). Khi dữ liệu đến máy chủ thư (MTA), nó nằm ở dạng không mã hóa, khiến quản trị viên hệ thống hoặc kẻ tấn công xâm nhập máy chủ có thể dễ dàng đọc được toàn bộ nội dung. Hơn nữa, email truyền thống thiếu cơ chế xác thực nguồn gốc mạnh mẽ, dẫn đến các cuộc tấn công mạo danh (Spoofing) và lừa đảo (Phishing). 
SecureMail giải quyết triệt để vấn đề này bằng cách kết hợp **Mã hóa đầu cuối (End-to-End Encryption)** thông qua S/MIME, **Xác thực phi tập trung** thông qua Kerberos, và **Chống mạo danh** bằng bộ ba SPF/DKIM/DMARC.

### Mục tiêu chính của hệ thống
- **Bảo mật nội dung (Confidentiality):** Đảm bảo chỉ người nhận hợp pháp mới có thể giải mã thư.
- **Toàn vẹn và Xác thực (Integrity & Authentication):** Đảm bảo thư không bị chỉnh sửa trên đường truyền và chắc chắn xuất phát từ người gửi danh xưng.
- **Tính sẵn sàng của khóa (Key Availability):** Ngăn chặn mất mát dữ liệu khi mất khóa bằng cơ chế khôi phục phân tán (Escrow).
- **Chống tấn công phát lại (Anti-Replay):** Loại bỏ rủi ro kẻ tấn công bắt gói tin và gửi lại để trục lợi.

### Công nghệ, thư viện và thuật toán mật mã
- **Môi trường:** Python 3.11+.
- **Thư viện phụ thuộc:** `cryptography>=42.0.0` (Thư viện duy nhất được sử dụng cho toàn bộ tác vụ mật mã).
- **Thuật toán mật mã:**
  1. **Mã hóa bất đối xứng:** RSA-2048 (với OAEP padding, MGF1-SHA256, hash SHA-256).
  2. **Chữ ký điện tử:** RSA-2048 (với PSS padding, MGF1-SHA256, hash SHA-256).
  3. **Mã hóa đối xứng (Nội dung S/MIME):** AES-128-CBC với PKCS#7 Padding.
  4. **Mã hóa xác thực có dữ liệu liên kết (AEAD):** AES-256-GCM (Nonce 12-byte, Tag 16-byte) cho Kerberos Ticket và TLS-lite.
  5. **Băm mật khẩu:** PBKDF2-HMAC-SHA256 (200,000 iterations, Salt 16-byte ngẫu nhiên).
  6. **Dẫn xuất khóa (Key Derivation):** HKDF-SHA256 (tạo Subsession key, TLS session key).
  7. **Mã hóa MAC:** HMAC-SHA256 (được sử dụng nội bộ trong PBKDF2 và HKDF).
  8. **Trao đổi khóa (Tùy chọn):** X25519 ECDH.
  9. **Phân chia bí mật:** Shamir's Secret Sharing trên trường Galois hữu hạn GF(256) với đa thức `0x11b`.

### Kiến trúc tổng thể và Mô hình tin cậy (Trust Model)
- **Kiến trúc:** Phân tán thành các Micro-service thu gọn: CA Service (quản lý chứng chỉ gốc), KDS (tra cứu chứng chỉ công khai), Ticket Service (AS/TGS Kerberos), và Mail Server (SMTP/POP3).
- **Mô hình tin cậy (Trust Model):**
  - **Người dùng tin tưởng CA:** Mọi client tin tưởng Root CA do CA sở hữu khóa riêng cao nhất để ký CSR.
  - **Dựa vào Chữ ký, không dựa vào Network:** Người dùng tra cứu public key của nhau qua KDS, nhưng *không mù quáng tin tưởng KDS*. Client luôn thực hiện `verify_chain` để xác nhận chứng chỉ đó thực sự được CA ký. Do đó, nếu KDS bị hack, kẻ tấn công cũng không thể giả mạo khóa.
  - **Mail Server tin tưởng Ticket Service:** KDC (Ticket Service) và Mail Server chia sẻ một khóa đối xứng ($K_v$). Mail Server tin tưởng bất cứ Service Ticket nào được mã hóa hợp lệ bằng $K_v$ từ KDC.

---

## 2. DIRECTORY STRUCTURE & FILE DESCRIPTIONS

Cấu trúc thư mục của dự án và phân tích trách nhiệm từng tập tin (Đọc, ghi dữ liệu gì, import từ đâu):

```text
securemail/
├── auth/
│   ├── access_control.py      # Quy định Role-Based Access Control (RBAC). 
│   │                          # - Lớp/Hàm: `allowed()`. Defines PERMISSIONS dict.
│   │                          # - Import từ: Không có.
│   │                          # - Dữ liệu: Đọc/ghi cấu trúc dict trong memory.
│   └── cert_validator.py      # Logic xác minh chuỗi chứng chỉ X.509 và CRL.
│                              # - Hàm: `verify_chain()`.
│                              # - Import từ: `cryptography.x509`, `cryptography.hazmat...rsa`.
│                              # - Dữ liệu: Nhận byte PEM vào memory, không Ghi đĩa.
├── ca_service/
│   ├── ca_core.py             # Lõi của CA: Tạo Root CA, Ký CSR, Cập nhật SQLite.
│   │                          # - Hàm: `init_root_ca()`, `sign_csr()`, `revoke_cert()`.
│   │                          # - Dữ liệu: Đọc/Ghi đĩa (`data/ca/ca_key.pem`), Đọc/Ghi `data/ca/ca.db`.
│   ├── ca_server.py           # Socket Server (Port 9000) xử lý JSON RPC cho CA.
│   │                          # - Hàm: `serve()`, `_handle()`.
│   │                          # - Dữ liệu: Lắng nghe socket TCP.
│   ├── crl_manager.py         # Trích xuất dữ liệu từ DB, dùng CA key để ký CRL.
│   │                          # - Hàm: `build_crl()`.
│   ├── key_escrow.py          # Triển khai Shamir Secret Sharing trên GF(256).
│   │                          # - Hàm: `split_secret()`, `combine_shares()`, `_gf_mul_raw()`.
│   │                          # - Dữ liệu: Ghi các file `*.share{idx}.bin` vào thư mục escrow.
│   └── ocsp_responder.py      # Phản hồi trạng thái chứng chỉ tức thời (OCSP-lite).
├── crypto/
│   ├── aes_handler.py         # Wrap các hàm AES (CBC và GCM).
│   │                          # - Hàm: `aes_cbc_encrypt/decrypt`, `aes_gcm_encrypt/decrypt`.
│   ├── ecdh_handler.py        # Thiết lập khóa ECDH X25519 (Module phụ/bonus).
│   ├── hmac_utils.py          # Băm PBKDF2 để tạo derived key từ password.
│   │                          # - Hàm: `password_hash()`, `hmac_sha256()`.
│   ├── key_derivation.py      # Bọc HKDF từ thư viện cryptography.
│   │                          # - Hàm: `hkdf_derive()`.
│   └── rsa_handler.py         # Quản lý vòng đời RSA: Sinh khóa, Load PEM, OAEP, PSS.
│                              # - Hàm: `generate_keypair()`, `oaep_encrypt()`, `pss_sign()`.
├── kds/
│   ├── kds_client.py          # API gọi RPC đến KDS qua TCP socket.
│   ├── kds_server.py          # Socket Server (Port 9001) phục vụ KDS.
│   └── key_store.py           # Lớp lưu trữ tĩnh (CRUD) cho chứng chỉ vào SQLite.
│                              # - Dữ liệu: Đọc/Ghi `data/kds/kds.db`.
├── mail/
│   ├── dkim_signer.py         # Triển khai logic tạo chữ ký DKIM (canonicalization relaxed/relaxed).
│   │                          # - Hàm: `sign()`, `verify()`.
│   ├── mime_lite.py           # Phân tách Header và Body đơn giản qua `\r\n\r\n`.
│   └── smime_handler.py       # Lõi S/MIME: Thực hiện Sign-then-Encrypt cho nội dung thư.
│                              # - Hàm: `build_envelope()`, `open_envelope()`.
├── network/
│   ├── json_framing.py        # Giao thức TCP: Gửi/nhận JSON có 4 byte header độ dài (Big Endian).
│   ├── pop3_client.py         # Client lấy thư giả lập POP3 qua JSON framing.
│   ├── pop3_server.py         # Máy chủ POP3 (Port 1100). Đọc DB trả về Envelope.
│   ├── smtp_client.py         # Client đẩy thư lên SMTP (Port 2525).
│   ├── smtp_server.py         # Máy chủ SMTP. Kiểm tra Kerberos Auth, Check SPF/DKIM/DMARC.
│   │                          # - Dữ liệu: Ghi thư vào `data/mail/mailstore.db`.
│   └── tls_lite.py            # Mô phỏng STARTTLS: Handshake tạo Pre-master, dẫn xuất HKDF, bọc Frame bằng AES-GCM.
├── policy/
│   ├── dmarc_engine.py        # Logic quyết định DMARC (Accept/Quarantine/Reject).
│   └── spf_checker.py         # Lưu cấu hình Domain - IP vào SQLite.
├── ticket_service/
│   ├── as_tgs_server.py       # Lõi Kerberos KDC (Port 9002). Xác thực password, cấp TGT và ST.
│   │                          # - Dữ liệu: `data/ticket/ticket.db`.
│   ├── authenticator.py       # Cấu trúc Authenticator chống Replay Attack (có In-memory Cache TTL).
│   ├── ticket.py              # Logic niêm phong (seal) và mở (open) Ticket bằng AES-GCM.
│   └── ts_client.py           # Client gọi KDC (Thực hiện AS-REQ và TGS-REQ).
├── client_core.py             # Library tích hợp toàn bộ logic luồng client (Login, Fetch, Send).
├── main_ca.py                 # Entry point khởi chạy CA Service.
├── main_client.py             # Entry point CLI thao tác phía người dùng (Alice, Bob).
├── main_kds.py                # Entry point khởi chạy KDS.
├── main_mail_server.py        # Entry point khởi chạy đồng thời luồng SMTP và POP3.
├── main_ticket.py             # Entry point khởi chạy Ticket Service.
├── requirements.txt           # File chứa thư viện (cryptography>=42).
└── run_demo.py                # Chạy kịch bản giả lập toàn trình (Bootstrap và 8 scenario).
```

---

## 3. DATA FLOW — DEEP TRACE

### a) User registration & key generation flow
1. **Client gọi:** `client_core.register(email, pw, ...)`
2. **KeyGen:** Gọi `rsa_handler.generate_keypair(2048)` sinh RSA Private Key cục bộ (Memory).
3. **CSR Build:** Tạo X.509 CSR (Certificate Signing Request) chứa Public Key và thông tin subject (Plaintext).
4. **CA Sign:** Client gửi CSR qua TCP socket tới CA (`ca.sign_csr`). CA (`ca_core.sign_csr`) kiểm tra chữ ký CSR, tạo đối tượng Certificate, ký bằng CA Private Key (RSA-PSS).
5. **Output:** CA lưu vào `ca.db`, trả về Client `cert_pem_b64` (X.509 bytes Base64).
6. **KDS Sync:** Client gọi `kds_client.put_cert` đẩy Cert lên KDS (`kds.db`).
7. **KDC Register:** Client gọi `hmac_utils.password_hash` băm mật khẩu ra $K_c$ (32 bytes), gửi $K_c$ lên Ticket Service lưu trữ trong `principals` table.
8. **Client Save:** Client ghi Private Key (Mã hóa bằng mật khẩu dạng PEM), Cert PEM, và Salt xuống đĩa.

### b) User login & authentication flow (Kerberos AS-REQ)
1. **Client gọi:** `client_core.login(email, pw)`
2. **AS-REQ:** Gọi `ts_client.as_request`. Client gửi `{op: as_req, id_c, ts1}` (Plaintext) tới TS.
3. **TS xử lý:** `as_tgs_server.handle_as_req`. Đọc $K_c$ từ DB. Tạo Session Key ngẫu nhiên $K_{c,tgs}$ (32 bytes). Đóng gói TGT = `ticket.seal_ticket(K_tgs, payload)`. Toàn bộ dữ liệu (TGT + $K_{c,tgs}$) được đóng gói thành `AS-REP`.
4. **Mã hóa AS-REP:** TS gọi `aes_gcm_encrypt(K_c, AS-REP)`. (Dữ liệu lúc này là Ciphertext AES-GCM).
5. **Client nhận:** Client dùng mật khẩu, dẫn xuất lại $K_c$, gọi `aes_gcm_decrypt` để mở `AS-REP`.
6. **Output:** Client có được $K_{c,tgs}$ (Plaintext trong RAM) và TGT (Ciphertext đối với Client, chỉ TS mới mở được).

### c) Mail composition, encryption & signing flow (S/MIME)
1. **Client gọi:** `client_core.send_secure_email` -> `smime_handler.build_envelope`
2. **Ký PSS:** Hàm lấy `body` (Plaintext), dùng RSA Private Key của người gửi gọi `rsa_handler.pss_sign(body)`. Output: Chữ ký `sig` (Bytes).
3. **Tạo CEK:** Sinh khóa phiên đối xứng ngẫu nhiên CEK (AES 16-byte).
4. **Mã hóa nội dung:** Gọi `aes_cbc_encrypt(CEK, JSON_chứa_body_và_sig)`. Output: `ct` (Ciphertext S/MIME body).
5. **Mã hóa khóa phiên:** Với chứng chỉ người nhận (Bob), trích xuất RSA Public Key, gọi `rsa_handler.oaep_encrypt(pubkey, CEK)`. Output: `cek_oaep_b64` (Ciphertext của CEK).
6. **Đóng gói Envelope:** Gom `cek_oaep_b64`, `ct`, và tham số thuật toán thành cấu trúc JSON envelope (Plaintext bọc Ciphertext).

### d) Mail transmission flow (client → server → recipient)
1. **TGS-REQ:** Client gửi TGT + Authenticator (mã hóa bằng $K_{c,tgs}$) lên TS lấy Service Ticket ($ST$) cho Mail Server và $K_{c,v}$.
2. **STARTTLS:** Client gửi `{op: STARTTLS}` cho SMTP. Thực hiện RSA-OAEP trao đổi Pre-master, dẫn xuất `HKDF(pre_master)` ra `SessionKey` (32 bytes). Từ lúc này, mọi Frame TCP bị wrap bằng `aes_gcm_encrypt(SessionKey)`.
3. **AUTH:** Client gửi `ST` + Authenticator (Mã hóa bằng $K_{c,v}$). Máy chủ Mail mở `ST` bằng $K_v$ (đọc từ SQLite của TS), lấy $K_{c,v}$, giải mã Authenticator. Trả về `Mutual_Auth = E(K_c_v, TS_plus_1)`.
4. **DATA:** Client gửi Envelope S/MIME. Máy chủ Mail (SMTP) kiểm tra SPF (tra `spf_checker`), DKIM (`dkim_signer.verify`), DMARC.
5. **MTA DKIM Sign (A4):** MTA có thể ký thêm DKIM của riêng server (`mta_domain_key`).
6. **Output:** Lưu JSON envelope vào `mailstore.db`. Tại máy chủ, Envelope là Plaintext chứa Ciphertext bên trong, Server KHÔNG THỂ đọc được nội dung gốc.

### e) Mail reception, decryption & signature verification flow
1. **POP3 Fetch:** Bob gọi `client_core.fetch_inbox()`. Thực hiện STARTTLS và Kerberos AUTH như SMTP. Lấy Envelope từ `RETR`.
2. **Mở Envelope:** `smime_handler.open_envelope(env, bob_privkey)`.
3. **Giải mã CEK:** Bob tìm `cek_oaep_b64` tương ứng ID của mình, gọi `rsa_handler.oaep_decrypt(bob_privkey)`. Ra CEK (Plaintext).
4. **Giải mã Nội dung:** Gọi `aes_cbc_decrypt(CEK, ct)`. Ra chuỗi JSON chứa `body` và `sig` (Plaintext).
5. **Xác minh chữ ký:** Tải chứng chỉ người gửi (Alice) từ `signer_cert_pem`, gọi `rsa_handler.pss_verify(alice_pubkey, sig, body)`.
6. **Output:** Nếu `True`, trả về thư hợp lệ cho người dùng.

### f) Certificate issuance & CRL revocation flow
1. **Thu hồi:** Quản trị viên chạy lệnh `ca.revoke serial_hex`. CA update SQLite `issued` set `status='revoked'`.
2. **Cập nhật CRL:** CA gọi `crl_manager.build_crl()`. Xây dựng X.509 CRL, duyệt danh sách revoked, ký bằng CA Private Key.
3. **Đẩy CRL:** CA gọi `kds_client.sync_crl(crl_pem)`. KDS nhận và cập nhật bảng `crl_cache`.
4. **Kiểm tra (Verify):** Khi Client gửi thư, gọi `kds_client.get_crl()`, truyền vào `cert_validator.verify_chain()`. Hàm này duyệt qua các entry trong CRL, nếu `serial` của chứng chỉ đích nằm trong danh sách, throw lỗi "cert revoked".

### g) Key Distribution Server (KDS) lookup flow
1. **Lấy khóa hàng loạt:** Khi gửi thư cho `[Bob, Eve]`, Client gọi `kds.bulk`. KDS query `certs` table trong `kds.db`, trả về Dictionary `{"bob": cert_b64, "eve": cert_b64}`. (Plaintext data transfer, nhưng được bảo vệ tính toàn vẹn do Client sẽ tự verify chữ ký X.509 CA trên các cert này).

### h) Kerberos-style ticket (TGT / Ticket_v) flow
1. **TGT Format:** $E(K_{tgs}, [K_{c,tgs} || ID_c || ID_{srv} || TS || Lifetime])$.
2. **Ticket_v Format:** $E(K_v, [K_{c,v} || ID_c || ID_v || TS || Lifetime])$.
3. **Authenticator:** $E(K_{session}, [ID_c || AD_c || TS || Nonce])$.
*Trạng thái:* Tất cả Ticket đều là Ciphertext AES-256-GCM không thể đọc bởi client, chỉ đọc được bởi Service tương ứng (TGS hoặc MailSrv).

---

## 4. CRYPTOGRAPHIC COMPONENTS — MAXIMUM DETAIL

### 4.1 RSA-OAEP (Mã hóa khóa phiên S/MIME & STARTTLS)
─────────────────────
**a) PURPOSE:**
- Cung cấp tính bí mật (Confidentiality) cho quá trình trao đổi khóa đối xứng (Key Transport).
- Chống lại hình thức tấn công Padding Oracle nổi tiếng (Bleichenbacher Attack) trên chuẩn RSA-PKCS#1 v1.5 cũ. Mã hóa OAEP đảm bảo tính bảo mật ngữ nghĩa (IND-CCA2).

**b) ALGORITHM & PARAMETERS:**
- **Thuật toán:** RSA (Rivest–Shamir–Adleman)
- **Kích thước khóa (Key size):** 2048-bit (Modulus $N$).
- **Padding scheme:** OAEP (Optimal Asymmetric Encryption Padding).
- **Mask Generation Function (MGF):** MGF1 sử dụng hàm băm SHA-256.
- **Hàm băm chính:** SHA-256 (Tạo tag rỗng/label rỗng).
- **Vị trí trong mã:** `securemail/crypto/rsa_handler.py:37`

**c) IMPLEMENTATION LOCATION:**
- Tên tệp: `rsa_handler.py` -> Hàm `oaep_encrypt()` và `oaep_decrypt()`.
- Chuỗi gọi (Call chain): 
  - Mã hóa CEK: `client_core.send_secure_email` -> `smime_handler.build_envelope` -> `rsa_handler.oaep_encrypt`
  - Mã hóa Pre-master TLS: `tls_lite.client_handshake` -> `rsa_handler.oaep_encrypt`

**d) DETAILED PSEUDOCODE:**
```text
┌─────────────────────────────────────────────────────────┐
│ PSEUDOCODE: oaep_encrypt / oaep_decrypt                 │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ FUNCTION oaep_encrypt(pub: RSAPublicKey, pt: bytes) → bytes│
│   // Khởi tạo thuật toán băm SHA256 cho OAEP             │
│   hash_algo ← SHA256()                                  │
│   // Khởi tạo MGF1 sử dụng SHA256                        │
│   mgf ← MGF1(algorithm=hash_algo)                       │
│   // Thiết lập Padding OAEP với label rỗng (None)        │
│   pad_scheme ← OAEP(mgf=mgf, algorithm=hash_algo, label=None)│
│   // Gọi thư viện tầng thấp mã hóa plaintext             │
│   ct ← pub.encrypt(plaintext=pt, padding=pad_scheme)    │
│   RETURN ct                                             │
│                                                         │
│ FUNCTION oaep_decrypt(priv: RSAPrivateKey, ct: bytes) → bytes│
│   // Thiết lập cấu hình tương tự như Encrypt             │
│   mgf ← MGF1(algorithm=SHA256())                        │
│   pad_scheme ← OAEP(mgf=mgf, algorithm=SHA256(), label=None)│
│   // Thực thi giải mã nội bộ                             │
│   TRY:                                                  │
│     pt ← priv.decrypt(ciphertext=ct, padding=pad_scheme)│
│     RETURN pt                                           │
│   CATCH ValueError:                                     │
│     // Quăng lỗi nếu độ dài hoặc padding không hợp lệ    │
│     RAISE DecryptionError                               │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**e) DATA FORMAT:**
Ciphertext đầu ra dài đúng bằng kích thước modulus của RSA: $2048 / 8 = 256$ bytes. Đầu ra raw bytes, được mã hóa base64 trước khi nhúng vào JSON.

**f) SECURITY ANALYSIS:**
- **Lý do chọn:** OAEP là tiêu chuẩn hiện đại thay thế cho PKCS#1 v1.5. Kẻ tấn công không thể thay đổi bit của ciphertext để đoán plaintext (do tính chất non-malleability).
- **Giả định:** Khóa riêng tư an toàn, bộ tạo số ngẫu nhiên an toàn (OAEP yêu cầu nguồn entropy nội bộ để chèn salt).

---

### 4.2 RSA-PSS (Chữ ký điện tử)
─────────────────────
**a) PURPOSE:**
- Cung cấp tính xác thực (Authentication), toàn vẹn (Integrity) và chống chối bỏ (Non-repudiation) cho S/MIME, DKIM, và hệ thống X.509 CA.

**b) ALGORITHM & PARAMETERS:**
- **Thuật toán:** RSA Probabilistic Signature Scheme (PSS).
- **Kích thước khóa:** 2048-bit.
- **Hàm băm:** SHA-256 (cho cả Hash lõi và MGF1).
- **Salt length:** `MAX_LENGTH` (Tính tối đa dựa trên modulus và hash size, thường là 256 - 32 - 2 = 222 bytes).
- **Vị trí trong mã:** `securemail/crypto/rsa_handler.py:59`

**c) IMPLEMENTATION LOCATION:**
- Tệp: `rsa_handler.py` -> `pss_sign()`, `pss_verify()`
- Call chain: S/MIME ký body ở `smime_handler.build_envelope`, kiểm tra ở `open_envelope`. DKIM ký ở `dkim_signer.sign`.

**d) DETAILED PSEUDOCODE:**
```text
┌─────────────────────────────────────────────────────────┐
│ PSEUDOCODE: pss_sign / pss_verify                       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ FUNCTION pss_sign(priv: RSAPrivateKey, msg: bytes) → bytes │
│   // Định nghĩa Padding PSS                              │
│   pad ← PSS(mgf=MGF1(SHA256()), salt_length=MAX_LENGTH) │
│   // Gọi hàm ký, truyền thông điệp và thuật toán băm     │
│   sig ← priv.sign(message=msg, padding=pad, algorithm=SHA256())│
│   RETURN sig                                            │
│                                                         │
│ FUNCTION pss_verify(pub: RSAPublicKey, sig: bytes, msg: bytes) → bool│
│   TRY:                                                  │
│     pad ← PSS(mgf=MGF1(SHA256()), salt_length=MAX_LENGTH)│
│     pub.verify(signature=sig, data=msg, padding=pad, algorithm=SHA256())│
│     RETURN True   // Hàm verify không ném lỗi tức là hợp lệ│
│   CATCH InvalidSignature:                               │
│     RETURN False                                        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**e) DATA FORMAT:**
Chữ ký dài 256 byte, được đóng gói base64. 

**f) SECURITY ANALYSIS:**
RSA-PSS là cấu trúc chữ ký an toàn cao có bằng chứng (provably secure) dựa trên độ khó phân tích thừa số nguyên tố. Ưu việt hơn PKCS#1 v1.5 vì nó thêm tính ngẫu nhiên (salt) vào chữ ký, một tin nhắn ký 2 lần sẽ ra 2 chữ ký khác nhau.

---

### 4.3 AES-128-CBC (Mã hóa đối xứng thông điệp S/MIME)
─────────────────────
**a) PURPOSE:**
- Tính bí mật (Confidentiality) đối với khối lượng dữ liệu lớn (Nội dung thư). Bắt buộc đi kèm RSA-OAEP cho S/MIME EnvelopedData.

**b) ALGORITHM & PARAMETERS:**
- **Thuật toán:** Advanced Encryption Standard (AES). Khóa kích thước 128-bit (16 bytes).
- **Mode:** Cipher Block Chaining (CBC).
- **IV Size:** 16 bytes (sinh ngẫu nhiên qua `os.urandom(16)`).
- **Padding:** PKCS#7 Padding block size 128-bit (16 bytes).
- **Vị trí trong mã:** `securemail/crypto/aes_handler.py:7`

**c) IMPLEMENTATION LOCATION:**
- `aes_cbc_encrypt()` và `aes_cbc_decrypt()`.
- Call chain: Được bọc trong `smime_handler.py`.

**d) DETAILED PSEUDOCODE:**
```text
┌─────────────────────────────────────────────────────────┐
│ PSEUDOCODE: aes_cbc_encrypt                             │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ FUNCTION aes_cbc_encrypt(key: bytes(16), pt: bytes) → (bytes, bytes)│
│   // 1. Sinh Initialization Vector (IV) ngẫu nhiên       │
│   iv ← os.urandom(16)                                   │
│   // 2. Thiết lập padder chuẩn PKCS7 (128 bit block)     │
│   padder ← PKCS7(128).padder()                          │
│   padded_pt ← padder.update(pt) + padder.finalize()     │
│   // 3. Khởi tạo thuật toán AES Mode CBC                 │
│   cipher ← Cipher(AES(key), CBC(iv))                    │
│   enc ← cipher.encryptor()                              │
│   // 4. Mã hóa dòng dữ liệu                              │
│   ct ← enc.update(padded_pt) + enc.finalize()           │
│   RETURN (iv, ct)                                       │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**e) DATA FORMAT:**
Plaintext được pad lên bội số của 16 byte. Ciphertext kích thước bằng với Plaintext đã pad. S/MIME JSON Envelope chứa `iv_b64` và `ct_b64`.

**f) SECURITY ANALYSIS:**
AES-CBC yêu cầu IV phải là unpredictable (ngẫu nhiên mã hóa mạnh). Việc sử dụng padding tiềm ẩn rủi ro Padding Oracle Attack, tuy nhiên rủi ro này bị giới hạn vì file JSON Envelope trong hệ thống này đã bao bọc cơ chế xử lý lỗi kỹ lưỡng.

---

### 4.4 AES-256-GCM (Authenticated Encryption)
─────────────────────
**a) PURPOSE:**
- Mã hóa và xác thực toàn vẹn (AEAD - Authenticated Encryption with Associated Data).
- Chống nghe lén và chống chỉnh sửa (tampering). Đặc biệt, GCM loại bỏ hoàn toàn các dạng Padding Oracle.

**b) ALGORITHM & PARAMETERS:**
- **Thuật toán:** AES-256. Khóa kích thước 256-bit (32 bytes).
- **Mode:** Galois/Counter Mode (GCM).
- **Nonce (IV) size:** 12 bytes (96 bits) chuẩn NIST. Sinh ngẫu nhiên mỗi lần mã hóa.
- **Tag size:** 16 bytes (128 bits). Nối trực tiếp vào đuôi ciphertext.
- **Associated Data (AAD):** Context string (VD: `b"ticket-v1"`, `b"tls-lite|send|0"`).
- **Vị trí trong mã:** `securemail/crypto/aes_handler.py:26`

**c) IMPLEMENTATION LOCATION:**
- Tệp: `crypto/aes_handler.py`.
- Call chain: Dùng cực kỳ phổ biến trong `ticket.py`, `authenticator.py`, `as_tgs_server.py`, `tls_lite.py`.

**d) DETAILED PSEUDOCODE:**
```text
┌─────────────────────────────────────────────────────────┐
│ PSEUDOCODE: aes_gcm_encrypt                             │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ FUNCTION aes_gcm_encrypt(key: bytes(32), pt: bytes, aad: bytes) → (bytes, bytes)│
│   // 1. Sinh Nonce độ dài 12 bytes chuẩn GCM             │
│   nonce ← os.urandom(12)                                │
│   // 2. Khởi tạo AES-GCM cipher                          │
│   cipher ← Cipher(AES(key), GCM(nonce))                 │
│   enc ← cipher.encryptor()                              │
│   // 3. Đẩy AAD (Associated Data) vào máy trạng thái MAC │
│   IF len(aad) > 0 THEN                                  │
│     enc.authenticate_additional_data(aad)               │
│   END IF                                                │
│   // 4. Thực thi mã hóa stream (Ctr mode)                │
│   ct ← enc.update(pt) + enc.finalize()                  │
│   // 5. Nối Tag 16 byte vào đuôi ciphertext              │
│   ct_and_tag ← ct + enc.tag                             │
│   RETURN (nonce, ct_and_tag)                            │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**e) DATA FORMAT:**
Đầu ra hàm bọc Base64 gồm: `b64encode( nonce(12) || ct || tag(16) )`.

**f) SECURITY ANALYSIS:**
Bảo mật tối đa, hiệu suất cao (có tăng tốc phần cứng AES-NI). GCM mode yêu cầu tối quan trọng là Nonce không bao giờ lặp lại cùng một khóa. Hệ thống dùng `os.urandom(12)` để sinh ngẫu nhiên, tỉ lệ đụng độ cực kì nhỏ, được coi là an toàn tuyệt đối. Việc dùng AAD cứng (ví dụ `b"ticket-v1"`) ngăn kẻ tấn công lấy Ciphertext của `authenticator` giả làm `ticket`.

---

### 4.5 HKDF-SHA256 (Key Derivation Function)
─────────────────────
**a) PURPOSE:**
- Dẫn xuất khóa mật mã chuẩn từ nguyên liệu khóa thô (Raw material như Master Secret, Diffie-Hellman Shared Secret hoặc Pre-Master TLS). Đảm bảo khóa sinh ra phân bố đều (uniform distribution) và độc lập (key separation).

**b) ALGORITHM & PARAMETERS:**
- **Thuật toán:** HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
- **Hàm băm lõi:** SHA-256.
- **Info param:** Bối cảnh (Context). VD: `b"tls-lite-v1" + client_random + server_random`.
- **Length:** 32 bytes (Đủ cho AES-256).

**c) IMPLEMENTATION LOCATION:**
- `crypto/key_derivation.py`. 
- Call chain: Trong `tls_lite.client_handshake`.

**d) DETAILED PSEUDOCODE:**
```text
┌─────────────────────────────────────────────────────────┐
│ PSEUDOCODE: hkdf_derive                                 │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ FUNCTION hkdf_derive(master: bytes, info: bytes, length: int) → bytes│
│   // Dùng thư viện chuẩn HKDF với hàm băm SHA256         │
│   kdf ← HKDF(                                           │
│       algorithm=SHA256(),                               │
│       length=length,                                    │
│       salt=None,    // Khuyến nghị salt rỗng nếu master ngẫu nhiên│
│       info=info     // Data bối cảnh                    │
│   )                                                     │
│   RETURN kdf.derive(master)                             │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**f) SECURITY ANALYSIS:**
NIST chuẩn hóa HKDF (RFC 5869) là hàm KDF an toàn nhất. Việc tiêm `info` đảm bảo với cùng 1 Pre-master, nếu dùng cho các bối cảnh khác nhau (hoặc các session TLS có random khác nhau) sẽ sinh ra Session Key hoàn toàn khác biệt.

---

### 4.6 PBKDF2-HMAC-SHA256 (Password Hashing)
─────────────────────
**a) PURPOSE:**
- Chống lại việc dò mật khẩu (Dictionary/Brute-force/Rainbow Table).
- Đóng vai trò sinh $K_c$ (Khóa bí mật client dùng trong Ticket Service).

**b) ALGORITHM & PARAMETERS:**
- **Thuật toán:** Password-Based Key Derivation Function 2 (PBKDF2).
- **Hàm pseudo-random:** HMAC-SHA256.
- **Iterations (Vòng lặp):** 200,000 vòng (Chuẩn an toàn hiện đại).
- **Salt:** 16 bytes ngẫu nhiên (sinh một lần lúc Register).

**c) IMPLEMENTATION LOCATION:**
- `crypto/hmac_utils.py:15` (`password_hash()`).
- Call chain: `ts_client.register()`, `ts_client.as_request()`.

**d) DETAILED PSEUDOCODE:**
```text
┌─────────────────────────────────────────────────────────┐
│ PSEUDOCODE: password_hash                               │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ FUNCTION password_hash(pw: str, salt: bytes | None) → (bytes, bytes)│
│   IF salt IS None THEN                                  │
│     salt ← os.urandom(16)                               │
│   END IF                                                │
│   pw_bytes ← pw.encode("utf-8")                         │
│   // Thực thi 200,000 vòng băm đệ quy HMAC-SHA256        │
│   h ← pbkdf2_hmac(hash_name="sha256", password=pw_bytes,│
│                   salt=salt, iterations=200000)         │
│   RETURN (salt, h)                                      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**f) SECURITY ANALYSIS:**
200k vòng lặp SHA-256 gây tốn tài nguyên (CPU/GPU) cho kẻ thù nếu muốn Brute-force mật khẩu offline. Khóa $K_c$ tạo ra đạt chuẩn 256-bit (32 bytes) dùng cho `aes_gcm_decrypt` mở AS-REP an toàn.

---

### 4.7 Shamir Secret Sharing trên GF(256)
─────────────────────
**a) PURPOSE:**
- Key Escrow (Ký quỹ khóa). Chia khóa RSA Private Key ra 3 phần (Shares), yêu cầu ít nhất 2 phần để khôi phục. Đề phòng user mất khóa hoặc nhân viên nghỉ việc đột ngột.

**b) ALGORITHM & PARAMETERS:**
- **Trường hữu hạn:** GF(256) xây dựng qua bảng Lookup EXP và LOG, dùng đa thức tạo $x^8 + x^4 + x^3 + x + 1$ (0x11b, chuẩn AES).
- **Thuật toán:** Đa thức ngẫu nhiên bậc $K-1$. Ở đây ngưỡng Threshold $K=2$, nên đa thức là bậc 1: $f(x) = S + a_1 x$ trên GF(256).
- **Shares:** $N=3$. $x \in \{1, 2, 3\}$.

**c) IMPLEMENTATION LOCATION:**
- `ca_service/key_escrow.py`.

**d) DETAILED PSEUDOCODE:**
```text
┌─────────────────────────────────────────────────────────┐
│ PSEUDOCODE: combine_shares (Phục hồi khóa)              │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ FUNCTION combine_shares(shares: list[(int, bytes)]) → bytes│
│   // shares = [(x_1, y_1_bytes), (x_2, y_2_bytes)]       │
│   size ← length(y_1_bytes)                              │
│   out ← bytearray(size)                                 │
│   FOR pos = 0 TO size - 1 DO                            │
│     total ← 0                                           │
│     // Thực hiện nội suy đa thức Lagrange tại điểm x = 0 │
│     FOR j = 0 TO len(shares) - 1 DO                     │
│       x_j, y_j ← shares[j]                              │
│       num ← 1, den ← 1                                  │
│       FOR m = 0 TO len(shares) - 1 DO                   │
│         IF m != j THEN                                  │
│           x_m ← shares[m][0]                            │
│           num ← gf_mul(num, x_m)                        │
│           den ← gf_mul(den, x_j XOR x_m)  // Phép - là XOR trong GF(2) │
│         END IF                                          │
│       END FOR                                           │
│       // Trọng số Lagrange: y_j * (num / den)           │
│       weight ← gf_div(num, den)                         │
│       term ← gf_mul(y_j[pos], weight)                   │
│       total ← total XOR term                            │
│     END FOR                                             │
│     out[pos] ← total                                    │
│   END FOR                                               │
│   RETURN bytes(out)                                     │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

**f) SECURITY ANALYSIS:**
Perfect Secrecy (Bảo mật hoàn hảo theo thông tin lý thuyết). Nếu chỉ có 1 mảnh Share (với Threshold = 2), hacker không thể nội suy ra đa thức, cũng không thu được dù chỉ 1 bit thông tin của Khóa gốc. Việc tính toán trên GF(256) tránh tràn bit (overflow) như khi dùng số học module số nguyên thông thường, bảo toàn dữ liệu từng byte 1-to-1.

---

## 5. DEMO FLOW — SCENARIO-BY-SCENARIO DEEP ANALYSIS

Phân tích 8 kịch bản trong `securemail/run_demo.py` (Mỗi hàm là một kịch bản test E2E thực tế).

### Kịch bản 1: Normal encrypted + signed email
- **Tên / Yêu cầu:** B1-B7, M1-M5 (Thư bảo mật toàn vẹn, xác thực).
- **Pre-conditions:** Đã bootstrap, Alice và Bob đăng ký thành công trên KDS và KDC.
- **Trace:** Alice `login()` -> `send_secure_email(Alice to Bob)`. Dữ liệu envelope đóng gói và gửi qua `smtp_client` -> `smtp_server` -> DB `mailstore`. Bob `login()` -> `fetch_inbox()` tải Envelope, giải mã.
- **Assertion:** `assert any("S1" in m.get("subject", "") for m in inbox)`. Kịch bản PASS khi Bob mở thư không bị ném lỗi chữ ký.
- **Key check lines:** `run_demo.py:151-155`.
- **Nếu cơ chế vắng mặt:** Thư sẽ được gửi bằng Plaintext, bất kì kẻ chặn luồng mạng nào cũng đọc được nội dung thư ("Hello Bob").

### Kịch bản 2: MITM / Public-key Substitution
- **Tên / Yêu cầu:** M4 (Chống thay thế khóa công khai của KDS).
- **Pre-conditions:** Eve (Kẻ xấu) tạo RSA keypair tự ký (Self-signed) ghi danh dưới mail của Bob.
- **Trace:** Eve gọi `kds_client.put_cert(fake_bob_email, fake_cert)`. Sau đó client tải Cert này về gọi `cert_validator.verify_chain()`.
- **Assertion:** `assert not ok`. Kịch bản kiểm tra `verify_chain` sẽ trả về lỗi `CA signature invalid`.
- **Key check lines:** `run_demo.py:186-187`.
- **Nếu cơ chế vắng mặt:** Alice sẽ mã hóa thư bằng khóa RSA của Eve. Eve chặn lấy thư, giải mã và đọc được toàn bộ bí mật nội bộ mà Alice gửi cho "Bob".

### Kịch bản 3: Replay Attack
- **Tên / Yêu cầu:** M2, M7 (Chống tấn công phát lại bằng Authenticator TTL).
- **Pre-conditions:** Eve nghe lén đường truyền lấy được biến `authn` (Authenticator) hợp lệ của Alice.
- **Trace:** Eve mở Socket trực tiếp, gửi lệnh `AUTH` kèm đúng Token đó lần thứ hai: `try_auth_with(authn_blob)`. Server check đối tượng `REPLAY_CACHE`.
- **Assertion:** `assert r_a.get("ok") and not r_b.get("ok")`.
- **Key check lines:** `run_demo.py:247`.
- **Nếu cơ chế vắng mặt:** Eve có thể dùng gói tin cũ liên tục (vượt qua kiểm tra Kerberos Ticket) và dùng danh tính Alice để Gửi thư Rác (Spam/Spoof).

### Kịch bản 4: Revoked Certificate
- **Tên / Yêu cầu:** M3 (Quản lý CRL).
- **Pre-conditions:** Chứng chỉ Alice bị CA `revoke`.
- **Trace:** KDS update CRL. Bob chuẩn bị gửi thư cho Alice, Bob tải CRL, gọi `cert_validator.verify_chain`.
- **Assertion:** Bắt ngoại lệ `RuntimeError`, `assert` rằng luồng bị Block (Lỗi "cert revoked (CRL)").
- **Key check lines:** `run_demo.py:271-277`.
- **Nếu cơ chế vắng mặt:** Bob gửi thư mật cho một người đã nghỉ việc hoặc lộ khóa (Alice cũ), rò rỉ dữ liệu doanh nghiệp.

### Kịch bản 5: Spoofed Sender
- **Tên / Yêu cầu:** A5 (Ngăn giả mạo danh tính bằng DMARC/SPF).
- **Pre-conditions:** Cấu hình SPF ép domain nhận IP nhất định. Eve đăng nhập với Ticket của Eve nhưng gửi Lệnh SMTP MAIL FROM: `alice@mail.local`.
- **Trace:** SMTP Server `smtp_server.py:188` kiểm tra IP qua SPF -> FAIL. Mã nguồn đối chiếu `MAIL FROM` khác với Identity trong Service Ticket (Kerberos) sinh DMARC fail.
- **Assertion:** Xác nhận Server trả về `dmarc_action = "quarantine" hoặc "reject"`.
- **Key check lines:** `run_demo.py:336-341`.
- **Nếu cơ chế vắng mặt:** Nhân viên bình thường có thể giả danh `CEO@mail.local` để ra chỉ thị lừa đảo phòng kế toán chuyển tiền.

### Kịch bản 6: Reusable Ticket
- **Tên / Yêu cầu:** A6 (Tái sử dụng Ticket_v nhiều lần).
- **Pre-conditions:** Alice có ST hợp lệ (Lifetime 30 phút).
- **Trace:** Vòng lặp 5 lần gọi SMTP Send với CÙNG 1 biến `ticket_v` nhưng gọi hàm `auth_mod.build()` tạo Authenticator (Nonce/Timestamp) MỚI.
- **Assertion:** Cả 5 lần SMTP server đều trả về `ok=True`.
- **Key check lines:** `run_demo.py:363-368`.
- **Nếu cơ chế vắng mặt:** Người dùng phải nhập mật khẩu và lên máy chủ Ticket xin vé cho mỗi bức email gửi đi, gây quá tải toàn hệ thống mạng.

### Kịch bản 7: Key Recovery
- **Tên / Yêu cầu:** A9 (Khôi phục khóa Escrow bằng Shamir's Secret Sharing).
- **Pre-conditions:** CA giữ 3 Share file nhị phân của Bob.
- **Trace:** Admin gọi `key_escrow.recover_key(bob_email, shares=[1, 2])`.
- **Assertion:** `assert recovered == expected`. Byte Array ghép lại khớp 100% với File Private Key gốc. Thử nghiệm trên các tổ hợp `[1, 3]` cũng thành công.
- **Key check lines:** `run_demo.py:374-380`.
- **Nếu cơ chế vắng mặt:** Thiết bị phần cứng của Bob bị hỏng, mất toàn bộ Private Key. Vĩnh viễn không thể đọc lại kho thư cũ lưu trong Inbox POP3 (Ransomware lock logic).

### Kịch bản 8: HKDF Subsession Key
- **Tên / Yêu cầu:** B7 (Hierarchical Subsession Key).
- **Pre-conditions:** Có 1 Master Key 32 bytes ngẫu nhiên.
- **Trace:** Đưa Master Key vào 3 hàm `hkdf_derive` với context `info` (mail#1, mail#2).
- **Assertion:** `assert k1 != k2` và `assert k1 == k3`.
- **Key check lines:** `run_demo.py:388-391`.
- **Nếu cơ chế vắng mặt:** Việc tái sử dụng trực tiếp Master Key nhiều lần trên các nội dung khác nhau làm tăng rủi ro bị bẻ khóa Cryptanalysis.

---

## 6. INSTALLATION & SETUP GUIDE

**Yêu cầu hệ thống:** Python 3.11+, HĐH: Windows, Linux (Ubuntu/Debian) hoặc macOS.

**Cài đặt bước 1: Clone và nạp thư viện**
```bash
# Trỏ đường dẫn terminal vào thư mục cha chứa thư mục securemail
pip install -r securemail/requirements.txt
```

**Khởi chạy máy chủ Server:**
Nền tảng được thiết kế Micro-service. Bạn cần mở 4 Terminal độc lập, trỏ vào cùng thư mục gốc:

| Terminal | Lệnh Chạy | Vai trò / Mô tả |
|----------|-----------|-----------------|
| Terminal 1 | `python -m securemail.main_ca serve` | Máy chủ Root CA, Port 9000 |
| Terminal 2 | `python -m securemail.main_kds` | Máy chủ phân phối khóa KDS, Port 9001 |
| Terminal 3 | `python -m securemail.main_ticket` | Máy chủ cấp vé Kerberos, Port 9002 |
| Terminal 4 | `python -m securemail.main_mail_server` | Mail Server SMTP/POP3, Port 2525 & 1100. (Chỉ chạy sau khi Bootstrap). |

**Bootstrap Database (Thiết lập ban đầu):**
Trên Terminal 5, khởi tạo Identity cho Mail Server và sinh sẵn user demo:
```bash
python -m securemail.run_demo bootstrap
```

**Bảng cú pháp lệnh (Command Syntax Reference):**

| Lệnh Command | Mô tả Description |
|---|---|
| `python -m securemail.run_demo all` | Chạy toàn bộ 8 kịch bản tự động kiểm thử. Đưa ra Console PASS/FAIL. |
| `python -m securemail.run_demo 1` | Chỉ chạy riêng Kịch bản 1. |
| `python -m securemail.main_client register e@m.com pass "Name"` | Đăng ký 1 user từ CLI thực tế |
| `python -m securemail.main_client login alice@m.com pass` | Thử Login Kerberos, lấy Ticket TGT |
| `python -m securemail.main_ca list` | Quản trị CA: Liệt kê các chứng chỉ X.509 đang có |
| `python -m securemail.main_ca revoke <serial_hex>` | Quản trị CA: Thu hồi chứng chỉ khẩn cấp |

**Đầu ra dòng lệnh dự kiến (Khi chạy Run Demo All thành công):**
```text
======================================================================
 Scenario 1 — Normal encrypted + signed email (B1–B7, M1–M5)
======================================================================
  envelope size: 2154 bytes
  delivered to bob@mail.local: dmarc=accept, mta_dkim=YES
  Bob received 1 message(s) total
  subject=[S1] Normal encrypted + signed | sig_valid=True | signer=...
  [OK] PASS
...
======================================================================
 Scenario 8 — Hierarchical subsession key (B7)
======================================================================
  [OK] PASS — HKDF yields unique subsession keys per message context
```

---

## 7. API & PROGRAMMING INTERFACE

Phần này mô tả các API thiết yếu cho các Nhà phát triển.

### Module: `securemail.client_core`

**1. `register(email: str, password: str, display_name: str = "", role: str = "user") -> dict`**
- **Mục đích:** Khởi tạo người dùng End-to-End đầy đủ trên mọi server.
- **Chi tiết tham số:** 
  - `email`, `password`: Định danh và mật khẩu đăng nhập.
  - `display_name`, `role`: Cấu hình mở rộng hiển thị và quyền.
- **Trả về:** Dictionary `{"cert_pem": bytes, "serial": str_hex}` chứa chứng chỉ X.509.
- **Ngoại lệ:** `RuntimeError` nếu máy chủ CA/KDS/TS sập hoặc CA từ chối chữ ký CSR.
- **Cách dùng:** `register("admin@mail.local", "P@ssword1", "System Admin")`

**2. `login(email: str, password: str) -> dict`**
- **Mục đích:** Lấy vé gốc (Ticket Granting Ticket) từ máy chủ xác thực.
- **Chi tiết tham số:** Nhận `email`, `password` (Password dùng để sinh khóa nội bộ $K_c$).
- **Trả về:** Dictionary (Context) chứa Private Key RSA (Object bộ nhớ), `tgt` bọc base64, và `k_c_tgs`.
- **Ngoại lệ:** Bắn lỗi nếu Sai mật khẩu (Giải mã fail tại `aes_gcm_decrypt`) hoặc User không tồn tại.
- **Cách dùng:** `ctx = login("alice@mail.local", "alice-pw")`

**3. `send_secure_email(ctx: dict, recipient_emails: list[str], subject: str, body: str, smtp_host: str = "127.0.0.1", smtp_port: int = 2525, domain: str = "mail.local", dkim_sign: bool = False) -> dict`**
- **Mục đích:** Build S/MIME, Validate CA chain, Gửi thư bảo mật qua Socket SMTP.
- **Chi tiết tham số:** `ctx` (Từ hàm login), `recipient_emails` danh sách các chuỗi mail, `subject`, `body` thư. `dkim_sign` kích hoạt ký DKIM domain phía client.
- **Trả về:** Dict `{"envelope_len": int, "results": list}`
- **Ngoại lệ:** `RuntimeError` nếu một người nhận có Chứng chỉ bị thu hồi (CRL/OCSP báo 'revoked').
- **Cách dùng:** `send_secure_email(ctx, ["bob@mail.local"], "Secret", "Launch code: 123")`

**4. `fetch_inbox(ctx: dict, host: str = "127.0.0.1", port: int = 1100) -> list[dict]`**
- **Mục đích:** Kết nối POP3 bằng Kerberos Auth, tải mọi Envelope về RAM, mở khóa S/MIME và check Signature.
- **Trả về:** Một list cấu trúc Dict, ví dụ: `[{"id": 1, "sender": "x", "body": "...", "signature_valid": True, "dmarc_action": "accept"}]`.

---

## 8. FEATURES FOR STAKEHOLDERS (CÁC TÍNH NĂNG NỔI BẬT)

*Mô tả bằng ngôn ngữ dễ hiểu dành cho Giảng viên, Ban Giám Đốc, và Bộ phận Phi-kỹ thuật:*

Hệ thống SecureMail bảo vệ tuyệt đối thông tin liên lạc điện tử của doanh nghiệp giống như một "xe bọc thép" chở thư tín:

1. **Bảo vệ nội dung triệt để (End-to-End Encryption):** Giống như bỏ một bức thư vào một két sắt hai lớp, chỉ có chìa khóa trong túi của người nhận mới mở được. Cả Quản trị viên máy chủ, nhà cung cấp đường truyền mạng, hay Hacker đánh cắp trọn gói máy chủ Data Center cũng **không thể đọc được nội dung thư**. Hệ thống phòng chống cuộc tấn công nghe lén (Eavesdropping).
2. **Con dấu niêm phong chống giả mạo (Digital Signature):** Bức thư sẽ bị báo động ngay lập tức nếu ai đó tự tiện sửa một dấu chấm hoặc dấu phẩy trên đường đi. Đồng thời nó chứng minh được người gửi là "Giám đốc" thật, chứ không phải kẻ lừa đảo mạo danh địa chỉ email. Nó phòng thủ trước tấn công giả mạo (Spoofing & Phishing).
3. **Vé gửi xe có thời hạn (Kerberos Anti-Replay):** Khi nhân viên quẹt thẻ (Ticket), mã quẹt đó chỉ có giá trị 1 lần ở giây phút đó (dựa vào biến Nonce và Timestamp). Nếu Hacker đứng cạnh, copy trộm dãy mã số đó và định dán lại vào giây tiếp theo để lẻn vào hệ thống, cánh cửa sẽ báo động đỏ (Replay Attack block).
4. **Hòm chìa khóa dự phòng (Shamir Escrow):** Nếu một nhân viên bất cẩn làm mất chìa khóa két sắt (Mất điện thoại/ổ cứng lưu Private Key RSA). Tài liệu không mất đi vĩnh viễn. Giám đốc, Kế toán trưởng và IT trưởng mỗi người cầm 1 "mảnh ghép chìa khóa". Chỉ khi có 2 trong 3 người này đồng thuận ghép chìa khóa lại trên hệ thống (2-of-3 threshold), hệ thống sẽ đúc lại chìa khóa gốc cấp lại cho nhân viên.

---

## 9. SƠ ĐỒ KIẾN TRÚC VÀ GIAO TIẾP HỆ THỐNG

### 9.1 Sơ đồ Kiến trúc Tổng quan (Architecture Diagram)

```text
       [TRUST BOUNDARY] -- VÙNG AN TOÀN CAO NHẤT ---
       │                                           │
       │    ┌─────────── CA (9000) ───────────┐    │
       │    │ ROOT CA KHÓA RIÊNG BẢO MẬT      │    │
       │    │ Ký cấp chứng thư (Cert)         │    │
       │    │ Hệ thống khôi phục khóa (Escrow)│    │
       │    └─────────────────────────────────┘    │
       └────────────────────┬──────────────────────┘
                            │ (Trust via CA Signature)
  ┌───────────────┐         │
  │  KDS (9001)   │◄────────┘       
  │ Thư mục chứa  │                 [VÙNG KDC - Authentication]
  │ Public Cert   │                 ┌────────Ticket Service (9002)────────┐
  │ và File CRL   │                 │ Lữu trữ khóa Hash của User (K_c)    │
  └───────────────┘                 │ Sinh vé xác thực TGT, Ticket_v      │
          ▲                         │ Xác thực Authenticator chống Replay │
          │ Lookup Cert             └─────────────────────────────────────┘
          │                                 ▲                 ▲ (Verify Ticket_v)
          │                                 │ (AS/TGS-REQ)    │ (Shared K_v)
   ┌──────┴───────────────┐                 │        ┌────────┴─────────────┐
   │ MAIL CLIENT CLI      ├─────────────────┘        │ MAIL SERVER (SMTP/POP)
   │ (Người dùng: Alice)  │=========================>│ (Giao tiếp bảo mật)    │
   │ Đăng ký, Mã hóa E2E  │      STARTTLS / TCP      │ Port 2525 / Port 1100  │
   │ Lưu trữ Local DB     │<=========================│ Quản lý DB hộp thư     │
   └──────────────────────┘  S/MIME Envelope JSON    └────────────────────────┘
```

### 9.2 Sơ đồ Trình tự gửi Thư (Sequence Diagram)

```text
Alice Client                TGS / KDC                 KDS                  SMTP Server
     │                          │                      │                       │
     │---- 1. Get Cert Bob --------------------------->│                       │
     │<--- 2. Cert Bob b64 ----------------------------│                       │
     │                          │                      │                       │
     │ (Kiểm tra chữ ký CA lên Cert, Check OCSP/CRL)   │                       │
     │ (S/MIME: RSA PSS Sign -> AES CBC -> RSA OAEP)   │                       │
     │                          │                      │                       │
     │---- 3. TGS-REQ (Xin vé vào cửa SMTP) ---------->│                       │
     │<--- 4. TGS-REP (Trả về Ticket_v mã hóa) --------│                       │
     │                          │                      │                       │
     │---- 5. TCP Connect & EHLO --------------------------------------------->│
     │---- 6. STARTTLS & Handshake (RSA-OAEP) -------------------------------->│
     │<--- 7. Cấp Session Key (HKDF). Từ bước này kênh truyền mã AES-GCM <-----│
     │                          │                      │                       │
     │---- 8. AUTH Kerberos (Ticket_v + Auth_nonce) -------------------------->│
     │<--- 9. Mutual Auth (Trả về Auth_nonce + 1) <----------------------------│
     │                          │                      │                       │
     │---- 10. MAIL FROM / DATA (Gửi S/MIME JSON) ---------------------------->│
     │                          │                      │  (Server check DMARC) │
     │<--- 11. 250 OK Message Accepted <---------------------------------------│
     │                          │                      │                       │
```

---

## 10. LIMITATIONS & FUTURE DEVELOPMENT

### 10.1 Các giới hạn phát hiện qua Code Review
1. **Rủi ro rò rỉ khóa Root CA (Passphrase Hardcoded):**  
   Tại `securemail/ca_service/ca_core.py:18`, biến `CA_PASSPHRASE` đang được truyền ở dạng Hardcode String (`b"securemail-root-ca-2026"`). Nếu một file bị lộ mã nguồn, kẻ tấn công có thể dễ dàng đọc được file `ca_key.pem` và chiếm đoạt danh tính siêu quản trị của Root CA, phá sập toàn bộ Mô hình tin cậy (Trust Model) của cả hệ thống.
2. **KDS Trust-by-Admin chưa phi tập trung hoàn toàn:**
   Tại `securemail/kds/kds_server.py` hàm `_handle` (op: `kds.put_cert`), server KDS mù quáng nhận và ghi tệp chứng chỉ do bất cứ kết nối TCP nội bộ nào gửi lên (Giả định Admin nội bộ). Mặc dù Client vẫn an toàn vì tự gọi thuật toán kiểm tra CA_Signature `verify_chain` (tại `client_core.py:136`), nhưng một kẻ xấu có thể làm DoS máy chủ KDS hoặc gỡ bỏ một cert đúng và thay bằng Garbage Data.
3. **Quản lý đồng hồ thời gian thực (Clock Skew):**
   Ticket Authenticator (tại `authenticator.py:30`) phụ thuộc cứng vào `time.time()` của hệ điều hành với Window 300s (5 phút). Nếu máy chủ TGS bị sai lệch giờ (NTP fail) hoặc máy Client đồng hồ bị hết pin CMOS lệch múi giờ, người dùng sẽ vĩnh viễn bị từ chối xác thực đăng nhập `AUTH` do hệ thống lầm tưởng đó là Replay Attack.

### 10.2 Giải pháp cải tiến kĩ thuật (Future Development)
- **Tích hợp HSM (Hardware Security Module) hoặc KMS:** Triển khai thay thế lưu trữ Private Key RSA Root bằng các phần cứng bảo mật chuyên dụng chuẩn FIPS 140-2 (như AWS KMS, HashiCorp Vault). Hàm `load_ca()` sẽ thực thi gọi API mã hóa KMS thay vì tải bộ nhớ RAM cục bộ.
- **Mutual TLS (mTLS) nội bộ:** Để khắc phục hạn chế 2, thay vì giao tiếp RPC Plaintext giữa các Service nội bộ (CA gọi KDS), yêu cầu bắt buộc Client/Server handshake có chứng chỉ xác thực hai chiều mTLS.
- **Hoàn thiện giao thức ECDH Diffie-Hellman:** File mã nguồn `crypto/ecdh_handler.py` hiện đã hoàn thiện thư viện X25519 cho phép trao đổi Perfect Forward Secrecy. Cần tích hợp mô đun này vào giao thức STARTTLS của `smtp_client` và `smtp_server` thay thế cho thuật toán chèn `Pre-master` tĩnh bằng RSA-OAEP hiện tại, qua đó ngăn chặn các rủi ro bị bẻ khóa hồi tố (Retrospective Decryption) nếu Private Key của máy chủ Mail bị đánh cắp trong tương lai.
