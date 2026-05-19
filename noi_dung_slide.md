# KỊCH BẢN THUYẾT TRÌNH: HỆ THỐNG SECURE MAIL
*Tối ưu theo chuẩn 1-6-6 dựa trên phân tích Source Code thực tế*
*(1 ý chính, tối đa 6 gạch đầu dòng, tối đa 6 chữ/dòng)*

---

## 👤 NGƯỜI 1: TỔNG QUAN & ĐỊNH DANH (CA)

### Slide 1: Đặt Vấn Đề
**Ý chính:** Tại sao cần hệ thống SecureMail?

* Hệ thống mail thường kém an toàn.
* Plaintext dễ bị nghe lén mạng.
* Kẻ gian dễ dàng giả mạo thư.
* Giải pháp: Mã hóa E2E đầu cuối.
* Xác thực mạnh qua vé Kerberos.

### Slide 2: Mô Hình Hệ Thống
**Ý chính:** Kiến trúc Microservices bảo mật phân tán.

* Gồm bốn dịch vụ cốt lõi riêng.
* CA Service: Quản lý cấp chứng chỉ.
* KDS: Thư mục tra cứu public key.
* Ticket Service: Xác thực trung tâm Kerberos.
* Mail Server: Máy chủ xử lý SMTP/POP3.

### Slide 3: Cấp Phát Danh Tính
**Ý chính:** Luồng tạo chứng chỉ X.509 tại CA.

* Client tự sinh khóa RSA-2048.
* Gửi yêu cầu ký X.509 CSR.
* CA xác minh và ký RSA-PSS.
* Lưu chứng chỉ vào CSDL SQLite.
* Client đẩy public cert lên KDS.

> **[VỊ TRÍ CHÈN PSEUDOCODE] - Minh họa luồng cấp phát (Logic file `ca_service/ca_core.py`)**
> ```text
> ┌────────────────────────────────────────────────────────┐
> │ QUY TRÌNH: Cấp_Phát_Chứng_Chỉ(Yêu_Cầu_CSR, Email)      │
> │                                                        │
> │   // 1. Kiểm tra tính hợp lệ của người nộp yêu cầu     │
> │   NẾU Chữ_Ký_Trên_CSR KHÔNG HỢP LỆ:                    │
> │       TỪ CHỐI cấp chứng chỉ                            │
> │                                                        │
> │   // 2. Chuẩn bị nguyên liệu                           │
> │   Khóa_Công_Khai_User = Trích_Xuất_Từ(Yêu_Cầu_CSR)     │
> │   Khóa_Bí_Mật_CA = Tải_Từ_Kho_An_Toàn()                │
> │                                                        │
> │   // 3. Xây dựng nội dung chứng chỉ chuẩn X.509        │
> │   Chứng_Chỉ = Tạo_Phôi_Mới()                           │
> │   Gắn_Định_Danh_Email(Chứng_Chỉ, Email)                │
> │   Gắn_Khóa_Công_Khai(Chứng_Chỉ, Khóa_Công_Khai_User)   │
> │   Gắn_Thời_Hạn_Sử_Dụng(Chứng_Chỉ, 1_Năm)               │
> │                                                        │
> │   // 4. CA đóng dấu (Ký số bằng thuật toán an toàn)    │
> │   Chứng_Chỉ_Hoàn_Chỉnh = Ký_Xác_Nhận(Chứng_Chỉ, Khóa_Bí_Mật_CA)
> │                                                        │
> │   Lưu_Vào_Hệ_Thống_Quản_Lý(Chứng_Chỉ_Hoàn_Chỉnh)       │
> │   TRẢ VỀ Chứng_Chỉ_Hoàn_Chỉnh                          │
> └────────────────────────────────────────────────────────┘
> ```

### Slide 4: Khôi Phục Khóa (Shamir)
**Ý chính:** Cơ chế Key Escrow chống mất khóa.

* Tránh nguy cơ mất khóa RSA.
* Dùng Shamir's Secret Sharing SSS.
* Tính toán trên trường Galois GF(256).
* Chia khóa thành ba mảnh nhỏ.
* Cần hai mảnh để khôi phục.

> **[VỊ TRÍ CHÈN PSEUDOCODE] - Dựa theo file `ca_service/key_escrow.py`**
> ```text
> ┌───────────────────────────────────────┐
> │ GF_256_SPLIT(key_bytes, k=2, n=3):    │
> │   coeffs = [key] + urandom(k-1)       │
> │   FOR i = 1 TO n:                     │
> │     shares[i] = eval_poly(coeffs, i)  │
> │   RETURN shares                       │
> └───────────────────────────────────────┘
> ```

---

## 👤 NGƯỜI 2: XÁC THỰC KERBEROS & ĐƯỜNG TRUYỀN

### Slide 5: Xác Thực Kerberos
**Ý chính:** Xác thực an toàn không lộ mật khẩu.

* Không truyền mật khẩu qua mạng.
* Băm mật khẩu bằng hàm PBKDF2.
* Đổi khóa băm lấy vé TGT.
* Dùng vé xin Service Ticket ST.
* Gửi vé cho máy chủ Mail.

### Slide 6: Vé & Chống Phát Lại
**Ý chính:** Cấu trúc bảo mật của Ticket.

* Vé bọc mã hóa AES-256-GCM.
* Client không thể tự giải mã.
* Ticket chứa Session Key an toàn.
* Authenticator kèm Nonce và Timestamp.
* Ngăn chặn tấn công phát lại Replay.

> **[VỊ TRÍ CHÈN PSEUDOCODE] - Dựa theo file `ticket_service/ticket.py`**
> ```text
> ┌───────────────────────────────────────┐
> │ SEAL_TICKET(service_key, payload):    │
> │   data = json(payload).encode()       │
> │   nonce = os.urandom(12)              │
> │   ct = AES_GCM_ENCRYPT(key, data)     │
> │   RETURN base64(nonce + ct)           │
> └───────────────────────────────────────┘
> ```

### Slide 7: Kênh Truyền TLS
**Ý chính:** Giao thức mạng STARTTLS.

* STARTTLS mở kênh mã hóa mạng.
* RSA-OAEP trao đổi khóa Pre-master.
* HKDF-SHA256 dẫn xuất Session Key.
* Bọc mọi frame bằng AES-GCM.
* Chống nghe lén toàn bộ luồng.

---

## 👤 NGƯỜI 3: MÃ HÓA NỘI DUNG S/MIME

### Slide 8: Quy Trình Ký & Mã
**Ý chính:** Nguyên tắc Sign-then-Encrypt trong S/MIME.

* Tuân thủ tiêu chuẩn bảo mật S/MIME.
* Ký nội dung trước để xác minh.
* Mã hóa toàn bộ thư sau đó.
* Đảm bảo tính chống chối bỏ.
* Ngăn chặn sửa đổi nội dung thư.

### Slide 9: Thuật Toán Cốt Lõi
**Ý chính:** Sức mạnh của RSA PSS và OAEP.

* Dùng RSA-PSS tạo chữ ký số.
* Có Salt ngẫu nhiên, rất an toàn.
* Dùng RSA-OAEP bọc khóa đối xứng.
* Chống tấn công giải mã Padding Oracle.
* Dùng hàm băm chuẩn cao SHA-256.

### Slide 10: Vỏ Bọc S/MIME
**Ý chính:** Cơ chế đóng gói Envelope.

* Sinh khóa ngẫu nhiên AES-128-CBC.
* Dùng khóa này mã hóa thư.
* RSA-OAEP bọc khóa AES lại.
* Người nhận dùng Private Key mở.
* Lấy khóa AES giải mã nội dung.

> **[VỊ TRÍ CHÈN PSEUDOCODE] - Dựa theo file `mail/smime_handler.py`**
> ```text
> ┌───────────────────────────────────────┐
> │ ENCRYPT_ENVELOPE(msg, bob_pub_key):   │
> │   cek = os.urandom(16)                │
> │   ct = AES_CBC_ENCRYPT(cek, msg)      │
> │   cek_enc = RSA_OAEP_ENCRYPT(pub, cek)│
> │   RETURN {cek_enc, ct}                │
> └───────────────────────────────────────┘
> ```

---

## 👤 NGƯỜI 4: CHÍNH SÁCH CHỐNG GIẢ MẠO & KIỂM THỬ

### Slide 11: Chống Giả Mạo Domain
**Ý chính:** Bộ ba bảo vệ SPF-DKIM-DMARC.

* SPF: Chỉ IP hợp lệ được gửi.
* DKIM: Máy chủ ký thêm chữ ký.
* DMARC: Áp dụng chính sách cách ly.
* Kiểm tra chéo identity vé Kerberos.
* Ngăn chặn hoàn toàn trò Phishing.

### Slide 12: Thu Hồi Chứng Chỉ
**Ý chính:** Xử lý sự cố khi lộ khóa.

* Khóa bị lộ hoặc nhân viên nghỉ.
* CA cập nhật DB sang Revoked.
* CA ký danh sách thu hồi CRL.
* Client tải CRL từ máy KDS.
* Chặn gửi thư nếu chứng chỉ hỏng.

> **[VỊ TRÍ CHÈN PSEUDOCODE] - Dựa theo file `auth/cert_validator.py`**
> ```text
> ┌───────────────────────────────────────┐
> │ VERIFY_CHAIN(cert, ca_pub, crl):      │
> │   ca_pub.verify_signature(cert)       │
> │   IF cert.serial IN crl.revoked:      │
> │      RAISE "Cert Revoked!"            │
> │   RETURN True                         │
> └───────────────────────────────────────┘
> ```

### Slide 13: Kịch Bản Demo
**Ý chính:** Kết quả 8 kịch bản kiểm thử (run_demo.py).

* Chạy tự động tám kịch bản test.
* Gửi, nhận S/MIME: Thành công 100%.
* Mạo danh chứng chỉ: Bị hệ thống chặn.
* Tấn công Replay: Báo lỗi block ngay.
* Phục hồi khóa Shamir: Chính xác tuyệt đối.

### Slide 14: Kết Luận & Tương Lai
**Ý chính:** Đánh giá tổng quan dự án.

* Hoàn thành ứng dụng mã hóa sâu.
* Tích hợp nhiều thuật toán mật mã.
* Triển khai kiến trúc Microservices an toàn.
* Tương lai: Tích hợp phần cứng HSM.
* Tương lai: Xây dựng WebUI hoàn chỉnh.
