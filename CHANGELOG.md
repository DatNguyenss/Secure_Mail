# 📋 CHANGELOG — Secure Mail Project
> File này ghi lại toàn bộ lịch sử cập nhật, sửa đổi, và bổ sung trong dự án Secure Mail.
> Mỗi lần thay đổi sẽ được ghi theo thứ tự thời gian mới nhất ở trên.
---

## 🛠️ DANH SÁCH LỆNH CỦA MAIL CLIENT (COMMAND REFERENCE)

Dưới đây là danh sách toàn bộ các lệnh được hỗ trợ bởi Mail Client trong cả hai chế độ:

### 1. Chế độ Stateful CLI (Lệnh đơn từ Terminal)
Chạy trực tiếp từ shell hệ thống, tự động lưu và tải phiên từ file session cục bộ (`data/active_session.json`).

| Cú pháp lệnh | Mô tả |
| :--- | :--- |
| `python -m securemail.main_client register <email> <password> [<display>]` | Đăng ký tài khoản mới trên hệ thống. |
| `python -m securemail.main_client login <email> <password>` | Đăng nhập và lưu thông tin phiên (TGT, private key...) vào file session. |
| `python -m securemail.main_client status` | Kiểm tra trạng thái đăng nhập hiện tại (email đang active). |
| `python -m securemail.main_client send <to> <subject>` | Gửi email bảo mật (nội dung nhập từ stdin, kết thúc bằng `Ctrl-D`/`Ctrl-Z`). |
| `python -m securemail.main_client list` | **[MỚI]** Liệt kê bảng rút gọn inbox có nhãn bảo mật màu (`SECURE`, `WARNING`, `DANGEROUS`). |
| `python -m securemail.main_client read <id>` | **[MỚI]** Xem chi tiết nội dung giải mã và chứng thực của một email cụ thể theo ID. |
| `python -m securemail.main_client sent` | **[MỚI]** Liệt kê bảng rút gọn các email đã gửi ra (Sent Mails). |
| `python -m securemail.main_client read_sent <id>` | **[MỚI]** Xem metadata của email đã gửi. |
| `python -m securemail.main_client fetch` | Tải và giải mã toàn bộ inbox (giao diện legacy, dump toàn bộ thư). |
| `python -m securemail.main_client recover [<email>] [<share1> <share2>]` | Khôi phục khóa riêng bằng cơ chế Shamir Secret Sharing (2-of-3). Nếu chưa đăng nhập, bắt buộc truyền vào `<email>`. |
| `python -m securemail.main_client logout` | Đăng xuất, xóa file session cục bộ. |

### 2. Chế độ Interactive Shell (REPL)
Khởi chạy giao diện dòng lệnh tương tác bằng cách gõ:
```bash
python -m securemail.main_client
```
Phiên làm việc được giữ trực tiếp trong bộ nhớ (In-Memory).

| Lệnh trong REPL | Mô tả |
| :--- | :--- |
| `login <email> <password>` | Đăng nhập trong REPL. Thay đổi prompt thành `<email>> `. |
| `status` | Xem thông tin chi tiết về session đang hoạt động (TGT, RSA Key size...). |
| `send <to> [<subject>]` | Gửi email bảo mật (gõ các dòng nội dung, ấn Enter dòng trống hoặc `Ctrl-D` để gửi). |
| `list` | **[MỚI]** Tải inbox và hiển thị danh sách thư rút gọn kèm nhãn bảo mật. Đồng thời cache kết quả. |
| `read <id>` | **[MỚI]** Xem chi tiết email cụ thể theo ID (đọc nhanh từ cache nếu đã chạy `list`, hoặc fetch POP3). |
| `sent` | **[MỚI]** Hiển thị danh sách các email đã gửi ra. Đồng thời cache kết quả. |
| `read_sent <id>` | **[MỚI]** Xem metadata email đã gửi cụ thể theo ID (từ cache hoặc qua POP3). |
| `fetch` | Tải và giải mã hiển thị toàn bộ inbox (legacy view). |
| `recover [<email>] [<share1> <share2>]` | Khôi phục khóa riêng bằng Shamir từ REPL. Nếu chưa đăng nhập, bắt buộc truyền vào `<email>`. |
| `logout` | Đăng xuất người dùng hiện tại, prompt quay lại thành `securemail> `. |
| `help` / `help <lệnh>` | Hiển thị trợ giúp của REPL hoặc chi tiết cách dùng một lệnh. |
| `exit` / `quit` | Thoát chế độ Interactive Shell (REPL). |

---

## [2026-06-02] — Thêm chức năng xem lại Email đã gửi (Sent Mails)

### 🎯 Mục tiêu
Cho phép người gửi xem lại lịch sử các email đã được gửi ra khỏi hệ thống (Sent Mails) thay vì chỉ có thể đọc Inbox như trước đây. Do cơ chế mã hóa S/MIME mã hóa toàn bộ nội dung (Body) bằng Public Key của người nhận, nên tính năng này chỉ cho phép xem metadata (Tiêu đề, Người nhận, Thời gian) và ngăn chặn việc đọc lại Body để đảm bảo an toàn tuyệt đối.

### 📁 File thay đổi
- `securemail/network/pop3_server.py`: Bổ sung thêm API `LIST_SENT` và `RETR_SENT` cho server.
- `securemail/network/pop3_client.py`: Thêm phương thức gọi tương ứng.
- `securemail/client_core.py`: Bổ sung hàm `fetch_sent_list` và `fetch_sent_message`.
- `securemail/main_client.py`: Bổ sung lệnh `sent` và `read_sent <id>` vào chế độ dòng lệnh đơn và REPL Shell.

---

## [2026-06-02] — Migrate Database from SQLite/Flat-files to Microsoft SQL Server

### 🎯 Mục tiêu
Chuyển đổi toàn bộ kiến trúc lưu trữ dữ liệu của hệ thống SecureMail từ các file SQLite rời rạc (`ca.db`, `kds.db`, `ticket.db`, `policy.db`, `mailstore.db`) và các file nhị phân (flat binary files lưu khóa chia sẻ Shamir) sang một cơ sở dữ liệu **Microsoft SQL Server** tập trung duy nhất (`SecureMail`).

### 📁 File thay đổi
- **Tạo mới**:
  - `.env` — Lưu trữ thông tin kết nối SQL Server (host, port, db name, user, password).
  - `securemail/db_conn.py` — Tiện ích kết nối tập trung sử dụng `pymssql` cho tất cả các service.
- **Cập nhật (12 files)**:
  - `securemail/requirements.txt`: Thêm `pymssql` và `python-dotenv`.
  - Toàn bộ các service (`ca_core.py`, `key_store.py`, `as_tgs_server.py`, `spf_checker.py`, `dmarc_engine.py`, `smtp_server.py`, `pop3_server.py`, `view_logs.py` v.v...) đã được xóa bỏ các truy vấn `sqlite3`.

### ⚡ Các thay đổi Kỹ thuật Chính (Technical Changes)
- **Cấu trúc Schema**: Database được gom nhóm gọn gàng theo schemas của SQL Server (`ca.*`, `kds.*`, `ticket.*`, `policy.*`, `mail.*`).
- **SQL Dialect**:
  - Chuyển đổi `ON CONFLICT DO UPDATE` (SQLite) sang `MERGE INTO` (SQL Server).
  - Chuyển đổi `INSERT OR IGNORE` sang luồng `IF NOT EXISTS ... INSERT`.
  - Thay thế `cursor.lastrowid` bằng mệnh đề `OUTPUT INSERTED.id`.
- **Lưu trữ nhị phân (VARBINARY Fix)**: Cập nhật cơ chế wrap dữ liệu dạng `bytes` thành `bytearray()` trước khi truyền vào `pymssql` để SQL Server hiểu đúng định dạng `VARBINARY(MAX)` thay vì `VARCHAR`.
- **Lưu trữ Shamir Shares**: Thay vì lưu khóa bị chia sẻ (Shamir Secret Sharing) dưới dạng nhiều file `.bin` rời rạc trên đĩa, toàn bộ share nay được mã hóa và lưu trực tiếp vào bảng `ca.escrow_shares`.

---

## [2026-06-02] — Hướng dẫn Demo 8 Kịch bản (Scenarios) bằng CLI Thủ công

### 🎯 Mục tiêu
Hướng dẫn chi tiết từng bước cách chạy demo 8 kịch bản (Scenario) bảo mật bằng dòng lệnh (CLI/REPL) thủ công để người đọc dễ dàng thao tác, kiểm thử hoạt động của hệ thống thay vì chỉ chạy các script tự động.

### 📁 File thay đổi
- `CHANGELOG.md` — Bổ sung hướng dẫn chạy demo thủ công cho 8 Scenario.

### 🧪 Tập lệnh Demo 8 Scenario thủ công

Dưới đây là các bước chi tiết để chạy thủ công bằng tay từ Terminal/CLI:

#### 📂 Chuẩn bị chung (Khởi chạy các dịch vụ)
Trước khi chạy bất kỳ kịch bản nào, hãy mở 4 Terminal độc lập và chạy các lệnh sau:
1. **CA Service**: `python -m securemail.main_ca serve`
2. **KDS (Key Distribution Center)**: `python -m securemail.main_kds`
3. **Ticket Service**: `python -m securemail.main_ticket`
4. **Mail Server**: `python -m securemail.main_mail_server`

*(Nếu hệ thống chưa được khởi tạo, hãy khởi tạo trước bằng cách chạy script bootstrap: `python -m securemail.run_demo bootstrap`)*

---

#### 1️⃣ Scenario 1: Luồng gửi/nhận email mã hóa & ký số thông thường (Normal Flow)
*Chứng minh tính năng xác thực Kerberos, trao đổi khóa, S/MIME mã hóa + ký số, truyền nhận SMTP/POP3.*

- **Bước 1**: Đăng nhập Alice trên Terminal CLI:
  ```bash
  python -m securemail.main_client login alice@mail.local alice-pw
  ```
- **Bước 2**: Gửi thư mã hóa bảo mật từ Alice tới Bob:
  ```bash
  python -m securemail.main_client send bob@mail.local "Hello Bob"
  ```
  Nhập nội dung thư (ví dụ: `Xin chao Bob, day la email bao mat.`), sau đó nhấn `Ctrl-D` (hoặc `Ctrl-Z` trên Windows) rồi `Enter` để hoàn tất gửi.
- **Bước 3**: Đăng xuất Alice và đăng nhập Bob:
  ```bash
  python -m securemail.main_client logout
  python -m securemail.main_client login bob@mail.local bob-pw
  ```
- **Bước 4**: Kiểm tra danh sách thư và đọc thư đã giải mã:
  ```bash
  python -m securemail.main_client list
  python -m securemail.main_client read 1
  ```
  *Kết quả:* Thư hiển thị chi tiết với nhãn `SECURE` màu xanh lá, trạng thái chữ ký `VALID`, và các kiểm tra SPF, DKIM, DMARC đều thành công.

---

#### 2️⃣ Scenario 2: Tấn công MITM / Thay thế khóa công khai (Public-key Substitution)
*Chứng minh client sẽ từ chối gửi thư nếu chứng chỉ đích không có chữ ký hợp lệ từ CA.*

- **Bước 1**: Kẻ tấn công tự tạo khóa và chứng chỉ giả mạo (Self-Signed) mạo danh Bob rồi đẩy lên KDS. Do KDS không có CLI trực tiếp cho việc này, ta chạy script python nhỏ để giả lập đẩy cert giả vào KDS:
  ```bash
  python -c "from securemail.crypto import rsa_handler; from securemail.kds import kds_client; from cryptography import x509; from cryptography.hazmat.primitives import hashes, serialization; from cryptography.x509.oid import NameOID; import datetime as dt; priv = rsa_handler.generate_keypair(2048); subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'FAKE Bob'), x509.NameAttribute(NameOID.EMAIL_ADDRESS, 'bob@mail.local')]); now = dt.datetime.now(dt.timezone.utc); fake_cert = x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(priv.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + dt.timedelta(days=30)).sign(priv, hashes.SHA256()); kds_client.put_cert('eve-fake-bob@mail.local', hex(fake_cert.serial_number), fake_cert.public_bytes(serialization.Encoding.PEM))"
  ```
- **Bước 2**: Đăng nhập Alice:
  ```bash
  python -m securemail.main_client login alice@mail.local alice-pw
  ```
- **Bước 3**: Alice thử gửi thư bảo mật cho địa chỉ có chứng chỉ giả mạo đó:
  ```bash
  python -m securemail.main_client send eve-fake-bob@mail.local "Hi Fake Bob"
  ```
  *Kết quả:* Hệ thống báo lỗi `RuntimeError: verify_chain failed` và chặn không cho gửi thư đi, do chứng chỉ tự ký của kẻ tấn công không dẫn về CA Root tin cậy.

---

#### 3️⃣ Scenario 3: Tấn công phát lại (Replay Attack)
*Chứng minh Mail Server phát hiện và từ chối các Authenticator bị bắt trộm và gửi lại.*

- **Bước 1**: Đăng nhập Alice:
  ```bash
  python -m securemail.main_client login alice@mail.local alice-pw
  ```
- **Bước 2**: Gửi một email thông thường tới Bob để tạo phiên làm việc (hoặc sử dụng REPL để thực hiện gửi liên tục):
  ```bash
  python -m securemail.main_client send bob@mail.local "Replay Test"
  ```
- **Bước 3**: Chạy script giả lập kẻ tấn công bắt gói tin chứa `Authenticator` và `Ticket` gửi lại Mail Server lần thứ hai liên tiếp:
  ```bash
  python -c "exec('import socket, securemail.client_core as c, securemail.ticket_service.authenticator as a, securemail.network.json_framing as j, securemail.network.tls_lite as t\nst = c.get_service_ticket(c.load_session())\nauthn = a.build(st[\'k_c_v\'], \'alice@mail.local\', \'127.0.0.1\')\nfor step in [\'First Use\', \'Replay\']:\n    s = socket.create_connection((\'127.0.0.1\', 2525))\n    j.send_json(s, {\'op\': \'EHLO\', \'domain\': \'mail.local\'})\n    j.recv_json(s)\n    j.send_json(s, {\'op\': \'STARTTLS\'})\n    key, _ = t.client_handshake(s)\n    fr = t.SecureFramer(s, key)\n    fr.send({\'op\': \'AUTH\', \'ticket_v\': st[\'ticket_v\'], \'authenticator\': authn})\n    print(step, fr.recv())\n    s.close()\n')"
  ```
  *Kết quả:* Lần đầu xác thực sẽ thành công (`ok=True`), nhưng lần gửi thứ hai (Replay) với cùng Authenticator sẽ bị từ chối với lỗi `replay detected` do trùng khớp nonce trong Replay Cache của Mail Server.

---

#### 4️⃣ Scenario 4: Chứng chỉ bị thu hồi (Certificate Revocation - CRL/OCSP)
*Chứng minh hệ thống ngăn chặn việc gửi thư đến người dùng có chứng chỉ đã bị thu hồi.*

- **Bước 1**: Thu hồi chứng chỉ hiện tại của Alice ở phía CA bằng cách chạy script API thu hồi:
  ```bash
  python -c "from securemail.network.json_framing import request; from securemail.db_conn import get_conn; conn=get_conn(); cursor=conn.cursor(); cursor.execute(\"SELECT serial FROM ca.issued WHERE email='alice@mail.local'\"); res=cursor.fetchone(); serial=res[0]; print('Revoking Alice cert:', serial); request('127.0.0.1', 9000, {'op': 'ca.revoke', 'serial_hex': serial})"
  ```
- **Bước 2**: Đồng bộ CRL (danh sách chứng chỉ bị thu hồi) lên KDS:
  ```bash
  python -c "from securemail.ca_service import crl_manager; from securemail.kds import kds_client; kds_client.sync_crl(crl_manager.build_crl())"
  ```
- **Bước 3**: Đăng nhập Bob và cố gắng gửi thư tới Alice:
  ```bash
  python -m securemail.main_client login bob@mail.local bob-pw
  python -m securemail.main_client send alice@mail.local "Test Revoked Cert"
  ```
  *Kết quả:* Lệnh gửi sẽ bị chặn ngay lập tức ở phía client với lỗi: `RuntimeError: verify_chain failed: cert revoked (CRL)`.
- **Bước 4 (Dọn dẹp)**: Khôi phục lại tài khoản/chứng chỉ hợp lệ cho Alice bằng cách đăng ký lại:
  ```bash
  python -c "import os; [os.unlink(f) for f in ['data/users/alice_at_mail.local.key.pem', 'data/users/alice_at_mail.local.cert.pem', 'data/users/alice_at_mail.local.salt.bin'] if os.path.exists(f)]"
  python -m securemail.main_client register alice@mail.local alice-pw Alice
  ```

---

#### 5️⃣ Scenario 5: Kẻ mạo danh người gửi (Spoofed Sender - SPF + DMARC)
*Chứng minh Mail Server phát hiện và cảnh báo thư giả mạo tiêu đề From.*

- **Bước 1**: Đổi SPF của domain `mail.local` sang một IP khác (ví dụ: `10.9.9.9`) để giả lập thư gửi đến từ IP ngoài danh sách SPF:
  ```bash
  python -c "from securemail.db_conn import get_conn; conn=get_conn(); cursor=conn.cursor(); cursor.execute(\"UPDATE policy.spf SET ip='10.9.9.9' WHERE domain='mail.local'\"); conn.close()"
  ```
- **Bước 2**: Đăng nhập dưới tư cách kẻ tấn công Eve:
  ```bash
  python -m securemail.main_client login eve@mail.local eve-pw
  ```
- **Bước 3**: Soạn thư mạo danh Alice bằng cách gửi thư có header `From: alice@mail.local` nhưng xác thực bằng session của `eve@mail.local`:
  ```bash
  python -c "from securemail import client_core; from securemail.kds import kds_client; from securemail.mail import smime_handler; from securemail.network import smtp_client; eve=client_core.load_session(); bob_cert=kds_client.get_cert('bob@mail.local'); env=smime_handler.build_envelope(b'Forged message content', [('bob@mail.local', bob_cert)], eve['cert_pem'], eve['privkey']); headers={'From': 'alice@mail.local', 'To': 'bob@mail.local', 'Subject': '[S5] Forged Mail', 'Date': 'now'}; st=client_core.get_service_ticket(eve); r=smtp_client.send_mail('127.0.0.1', 2525, 'mail.local', eve['email'], st['ticket_v'], st['k_c_v'], 'alice@mail.local', 'bob@mail.local', env, headers); print(r)"
  ```
- **Bước 4**: Khôi phục lại cấu hình SPF về localhost:
  ```bash
  python -c "from securemail.db_conn import get_conn; conn=get_conn(); cursor=conn.cursor(); cursor.execute(\"UPDATE policy.spf SET ip='127.0.0.1' WHERE domain='mail.local'\"); conn.close()"
  ```
- **Bước 5**: Đăng nhập Bob để kiểm tra thư:
  ```bash
  python -m securemail.main_client logout
  python -m securemail.main_client login bob@mail.local bob-pw
  python -m securemail.main_client list
  ```
  *Kết quả:* Email mạo danh sẽ được hiển thị với trạng thái `WARNING` hoặc `DANGEROUS` (do vi phạm DMARC alignment và SPF fail). Khi xem chi tiết bằng lệnh `read <id>`, người đọc sẽ thấy chi tiết lý do vi phạm DMARC.

---

#### 6️⃣ Scenario 6: Tái sử dụng vé Kerberos (Reusable Ticket)
*Chứng minh cơ chế hoạt động hiệu quả của Kerberos: Đăng nhập 1 lần, gửi nhiều email bằng cùng một Ticket trong thời hạn hiệu lực.*

- **Bước 1**: Đăng nhập Alice:
  ```bash
  python -m securemail.main_client login alice@mail.local alice-pw
  ```
- **Bước 2**: Gửi nhiều thư liên tục cho Bob mà không cần đăng nhập lại:
  ```bash
  python -m securemail.main_client send bob@mail.local "Mail test 1"
  # (Nhập nội dung thư 1)
  python -m securemail.main_client send bob@mail.local "Mail test 2"
  # (Nhập nội dung thư 2)
  python -m securemail.main_client send bob@mail.local "Mail test 3"
  # (Nhập nội dung thư 3)
  ```
  *Giải thích:* Client tự động lấy `TGT` đã lưu trong file session, gửi yêu cầu lấy Ticket dịch vụ từ TGS (nếu cần), rồi đính kèm `Ticket_v` cùng một `Authenticator` mới (chứa timestamp hiện tại) cho mỗi lần gửi thư. Mail Server chấp nhận tất cả các thư này vì vé vẫn còn hạn và các Authenticator là duy nhất (không bị trùng lặp thời gian/nonce).

---

#### 7️⃣ Scenario 7: Khôi phục khóa riêng (Key Recovery - Shamir 2-of-3)
*Chứng minh tính năng ký quỹ khóa riêng (Key Escrow) và khôi phục khi mất khóa bằng cách kết hợp 2 trên 3 mảnh chia sẻ.*

- **Bước 1**: Giả lập Bob làm mất file khóa riêng cục bộ:
  ```bash
  python -c "import os; os.unlink('data/users/bob_at_mail.local.key.pem')"
  ```
- **Bước 2**: Bob thực hiện khôi phục lại khóa riêng bằng cách chọn mảnh chia sẻ số 1 và 2:
  ```bash
  python -m securemail.main_client recover bob@mail.local 1 2
  ```
- **Bước 3**: Kiểm tra xem file khóa đã xuất hiện trở lại tại thư mục `data/users/bob_at_mail.local.key.pem` chưa:
  ```bash
  python -m securemail.main_client login bob@mail.local bob-pw
  ```
  *(Đăng nhập thành công chứng minh khóa riêng đã được khôi phục chính xác).*
- **Bước 4**: Thử khôi phục bằng cặp mảnh chia sẻ khác (ví dụ mảnh 1 và 3):
  ```bash
  python -m securemail.main_client recover bob@mail.local 1 3
  ```
  *Kết quả:* Khóa riêng được phục hồi hoàn hảo ở mọi tổ hợp mảnh chia sẻ hợp lệ (ngưỡng k=2).

---

#### 8️⃣ Scenario 8: Khóa phiên phân cấp (Hierarchical Subsession Key)
*Chứng minh mỗi email được mã hóa bằng một khóa phụ khác nhau (HKDF) dẫn xuất từ khóa phiên chính.*

Cơ chế này tích hợp tự động vào quá trình đóng gói S/MIME. Để chạy thử CLI minh chứng cách thức dẫn xuất khóa con bằng HKDF độc lập:
- Chạy lệnh:
  ```bash
  python -c "from securemail.crypto.key_derivation import hkdf_derive; import os; master_key = os.urandom(32); print('Master Session Key:', master_key.hex()); print('Sub-key for Message #1:', hkdf_derive(master_key, b'mail#1', 32).hex()); print('Sub-key for Message #2:', hkdf_derive(master_key, b'mail#2', 32).hex()); print('Re-derived Sub-key for Message #1:', hkdf_derive(master_key, b'mail#1', 32).hex())"
  ```
  *Kết quả:* Lệnh in ra hai khóa con khác nhau cho hai message ID khác nhau (`mail#1` vs `mail#2`), và chứng minh tính nhất quán khi dẫn xuất lại cùng một context (`mail#1` tạo ra khóa giống hệt). Điều này đảm bảo tính bảo mật riêng biệt cho từng email.
---

## [2026-06-02] — Tài liệu hóa quy trình kiểm thử đầy đủ Mail Client CLI

### 🎯 Mục tiêu
Sau khi hoàn thiện code cho chế độ CLI, bổ sung trực tiếp vào `CHANGELOG.md` phần tài liệu vận hành để người dùng có thể tự kiểm tra toàn bộ các lệnh Mail Client bằng terminal.

### 1. CLI là gì?
CLI là viết tắt của **Command Line Interface** — giao diện dòng lệnh. Người dùng thao tác bằng lệnh trong PowerShell/CMD/Terminal thay vì bấm nút như GUI.

Trong project SecureMail, Mail Client CLI nằm ở module:
```powershell
python -m securemail.main_client
```

Mail Client hỗ trợ 2 chế độ:
- **Stateful CLI**: chạy từng lệnh riêng từ terminal. Sau khi `login`, session được lưu tại `data/active_session.json`.
- **Interactive Shell / REPL**: chạy một shell tương tác bằng `python -m securemail.main_client`; session được giữ trong bộ nhớ cho đến khi `logout` hoặc `exit`.

### 2. Điều kiện trước khi test CLI
Chạy từ thư mục root của project:
```powershell
cd "d:\Hoc_Tap\2025-2026\KI_2\Ma_hoa_ung_dung\do_an\Secure_Mail"
```

Cần mở các service trong 4 terminal riêng:
```powershell
python -m securemail.main_ca serve
```
```powershell
python -m securemail.main_kds
```
```powershell
python -m securemail.main_ticket
```
```powershell
python -m securemail.main_mail_server
```

Nếu Mail Server báo thiếu key/cert, chạy bootstrap trước rồi mở lại Mail Server:
```powershell
python -m securemail.run_demo bootstrap
```

### 3. Quy trình test đủ 9 lệnh Stateful CLI
Chạy khối lệnh sau trong terminal thứ 5 sau khi đã mở đủ service:
```powershell
$stamp = Get-Date -Format "yyyyMMddHHmmss"
$testUser = "cli_test_$stamp@mail.local"
$testPass = "cli-test-pw"
$subject = "CLI Full Test $stamp"

Write-Host "`n[1] TEST register"
python -m securemail.main_client register $testUser $testPass "CLI Test User"

Write-Host "`n[2] TEST login"
python -m securemail.main_client login $testUser $testPass

Write-Host "`n[3] TEST status"
python -m securemail.main_client status

Write-Host "`n[4] TEST send"
"Hello Bob, this is a full CLI test: $stamp" | python -m securemail.main_client send bob@mail.local $subject

Write-Host "`nSwitch session to Bob for inbox commands"
python -m securemail.main_client login bob@mail.local bob-pw

Write-Host "`n[5] TEST list"
python -m securemail.main_client list

$msgId = @'
import sqlite3
c = sqlite3.connect("data/mail/mailstore.db")
r = c.execute(
    "SELECT id FROM mailbox WHERE recipient=? ORDER BY id DESC LIMIT 1",
    ("bob@mail.local",)
).fetchone()
c.close()
print(r[0] if r else "")
'@ | python -

Write-Host "`nLatest message id = $msgId"

Write-Host "`n[6] TEST read"
python -m securemail.main_client read $msgId

Write-Host "`n[7] TEST fetch"
python -m securemail.main_client fetch

Write-Host "`n[8] TEST recover"
python -m securemail.main_client recover bob@mail.local 1 2

Write-Host "`n[9] TEST logout"
python -m securemail.main_client logout

Write-Host "`nCheck status after logout"
python -m securemail.main_client status
```

### 4. Kết quả mong đợi của 9 lệnh CLI
| Lệnh | Kết quả đạt |
|---|---|
| `register` | Tạo user mới không lỗi, có cert/key/salt và principal Kerberos tương ứng. |
| `login` | In `Logged in as ... Session saved.` và tạo/cập nhật `data/active_session.json`. |
| `status` | Hiển thị email đang active và độ dài TGT. |
| `send` | Gửi mail thành công, output có `ok: True` trong kết quả SMTP. |
| `list` | Hiển thị bảng inbox gồm `ID`, `Status`, `Date`, `From`, `Subject`. |
| `read <id>` | Hiển thị chi tiết thư gồm `From`, `To`, `Subject`, `Security`, `Signature`, `SPF`, `DKIM`, `DMARC`, `Body`. |
| `fetch` | Vẫn dump toàn bộ inbox kiểu legacy, giữ tương thích ngược. |
| `recover` | Khôi phục private key bằng 2 share Shamir và báo restored key. |
| `logout` | Xóa session local; chạy `status` sau đó phải báo `No active session.` |

### 5. Quy trình test Interactive Shell / REPL
Khởi chạy:
```powershell
python -m securemail.main_client
```

Trong prompt `securemail>`, nhập:
```text
login alice@mail.local alice-pw
status
send bob@mail.local REPL CLI Test
```

Sau lệnh `send`, nhập nội dung mail rồi Enter thêm một dòng trống để gửi:
```text
Hello Bob from REPL

```

Tiếp tục trong REPL:
```text
logout
login bob@mail.local bob-pw
status
list
read <id>
fetch
recover bob@mail.local 1 2
logout
exit
```

Thay `<id>` bằng ID có thật trong bảng `list`.

### 6. Kiểm tra lỗi tham số CLI
Các lệnh sau phải báo lỗi thân thiện, không được hiện traceback Python:
```powershell
python -m securemail.main_client register
python -m securemail.main_client login alice@mail.local
python -m securemail.main_client send
python -m securemail.main_client read abc
python -m securemail.main_client recover unknown@mail.local 1
```

Kết quả đạt nếu output có dạng `Usage:` hoặc thông báo lỗi rõ ràng.

### 7. Ý nghĩa nhãn bảo mật trong `list`
| Nhãn | Ý nghĩa |
|---|---|
| `SECURE` | Chữ ký hợp lệ, SPF pass, DMARC accept, không có dấu hiệu nghi ngờ. |
| `WARNING` | Có dấu hiệu cần chú ý như DMARC quarantine, SPF fail, DKIM fail/anomaly, từ khóa cảnh báo, hoặc sender ngoài `@mail.local`. |
| `DANGEROUS` | Có lỗi giải mã/xác thực, chữ ký S/MIME invalid, DMARC reject, hoặc nội dung chứa từ khóa nguy hiểm. |

### 8. File dữ liệu liên quan khi chạy CLI
| File | Vai trò |
|---|---|
| `data/active_session.json` | Session đăng nhập của Stateful CLI. |
| `data/mail/mailstore.db` | Database SQLite lưu email. |
| `data/mail.log` | Log Mail Server. |
| `data/ticket/ticket.db` | Dữ liệu Ticket Service. |
| `data/users/*.key.pem` | Private key người dùng. |
| `data/users/*.cert.pem` | Certificate người dùng. |
| `data/ca/escrow/*.share*.bin` | Shamir key recovery shares. |

### 9. Lưu ý khi test
- `register` tạo user thật và ghi dữ liệu vào `data/users`, `data/ca/ca.db`, `data/kds/kds.db`, `data/ticket/ticket.db`.
- `send` tạo email thật trong `data/mail/mailstore.db`.
- `recover` có thể ghi đè private key local của user được khôi phục.
- Nếu muốn test mà không làm thay đổi dữ liệu đã commit, nên backup thư mục `data` trước khi chạy.

Backup nhanh:
```powershell
Copy-Item data data_backup_cli_test -Recurse
```

Khôi phục nhanh:
```powershell
Remove-Item data -Recurse -Force
Copy-Item data_backup_cli_test data -Recurse
```
---

## [2026-06-01] — Hoàn thiện Stateful CLI theo Command Reference

### 🎯 Mục tiêu
Rà soát lại `CHANGELOG` và hoàn thiện chế độ CLI/REPL để các lệnh được công bố trong Command Reference chạy đúng cú pháp, báo lỗi rõ ràng, và hiển thị inbox theo chế độ rút gọn/chi tiết.

### 📁 File thay đổi

#### 1. `securemail/client_core.py`
- Chuẩn hóa dữ liệu thư trả về từ `fetch_inbox()` và `fetch_message()` qua helper dùng chung, bổ sung trường `recipient`/`to`.
- Đảm bảo kết nối POP3 luôn được đóng bằng `quit()` kể cả khi có lỗi.
- Mở rộng `classify_security()`:
  - Vẫn giữ phân loại theo S/MIME, SPF, DKIM, DMARC như thiết kế ban đầu.
  - Bổ sung nhận diện từ khóa nguy hiểm (`virus`, `malware`, `hack`, `phishing`) và từ khóa cảnh báo (`warning`, `critical`, `suspicious`).
  - Cảnh báo khi người gửi không thuộc domain nội bộ `@mail.local`.
  - Hỗ trợ cả dạng gọi `classify_security(msg)` và `classify_security(subject, body, sender)`.

#### 2. `securemail/main_client.py`
- Thêm `help` / `-h` / `--help` cho chế độ CLI một lệnh.
- Kiểm tra tham số cho `register`, `login`, `send`, `read`, `recover` để không còn lỗi `IndexError` khi gọi thiếu đối số.
- Hoàn thiện cú pháp `recover [<email>] [<share1> <share2>]`:
  - Đã đăng nhập: có thể bỏ qua email hoặc truyền email khác.
  - Chưa đăng nhập: bắt buộc truyền email.
  - Share phải là 2 chỉ số khác nhau trong `1, 2, 3`.
- Màn hình `read <id>` hiển thị thêm người nhận (`To`).
- REPL xóa cache inbox khi `login`/`logout` để tránh đọc nhầm cache của phiên trước.
- REPL chuẩn hóa input có BOM khi pipe từ PowerShell để không nhận nhầm `login` thành lệnh không hợp lệ.

#### 3. `securemail/README.md`
- Cập nhật phần CLI người dùng sang đúng chế độ stateful: `login` một lần, sau đó dùng `status`, `send`, `list`, `read`, `fetch`, `recover`, `logout`.

### ✅ Tương thích ngược
- `fetch` legacy vẫn giữ nguyên chức năng dump toàn bộ inbox.
- `register`, `login`, `send_secure_email()`, `fetch_inbox()` và các service server-side không đổi giao thức.

### 🧪 Cách kiểm thử
```bash
python -m compileall securemail
python -m securemail.main_client help
python -m securemail.main_client status
python -m securemail.main_client read
python -m securemail.main_client recover
```

---

## [2026-05-31] — Inbox Listing, Security Classification & Detailed Message View

### 🎯 Mục tiêu
Thêm tính năng liệt kê danh sách email trong hộp thư (inbox) kèm theo phân loại mức độ bảo mật (Security Classification) và lệnh đọc nội dung chi tiết email cụ thể, tránh việc hiển thị toàn bộ nội dung gây rối mắt.

### 📁 File thay đổi

#### 1. `securemail/client_core.py` — Phân loại bảo mật & Truy xuất thư lẻ
| Hàm mới / Cải tiến | Mô tả |
|---|---|
| `classify_security(subject, body, sender)` | Phân loại bảo mật email thành 3 mức: `SECURE` (mặc định), `WARNING` (nếu tiêu đề/nội dung có từ khóa nhạy cảm như "warning", "critical", "suspicious" hoặc người gửi không thuộc domain nội bộ `@mail.local`), `DANGEROUS` (nếu chứa các từ khóa nguy hiểm như "virus", "malware", "hack", "phishing"). |
| `fetch_message(idx)` | Tải một email cụ thể từ mail server dựa trên chỉ mục (1-indexed) để phục vụ lệnh `read`. |

#### 2. `securemail/main_client.py` — Tích hợp lệnh `list` và `read` vào CLI/REPL
- **Lệnh `list`**: Liệt kê danh sách thư dưới dạng bảng rút gọn bao gồm: ID, Trạng thái bảo mật (badge màu), Thời gian nhận (Date), Người gửi, và Tiêu đề email.
  - Nhãn bảo mật (badge) có màu sắc tương ứng (sử dụng mã màu ANSI):
    - `SECURE`: Màu xanh lá (Green)
    - `WARNING`: Màu vàng (Yellow)
    - `DANGEROUS`: Màu đỏ (Red)
- **Lệnh `read <id>`**: Xem chi tiết một email gồm Người gửi, Người nhận, Tiêu đề, Mức độ bảo mật, và Nội dung thư, được đóng khung Unicode đẹp mắt.
- **Tối ưu hóa Cache REPL**: Trong chế độ Interactive Shell (REPL), kết quả của lệnh `list` được lưu tạm thời. Lệnh `read <id>` sẽ ưu tiên đọc từ cache này để giải mã và hiển thị ngay lập tức mà không cần kết nối và tải lại từ POP3 server, giúp tăng tốc độ phản hồi.

#### 3. [NEW] `PROMPT_list_read_commands.md`
- Tạo file prompt tiếng Anh chi tiết chứa các chỉ dẫn kỹ thuật và phân rã công việc (task breakdown) cho AI thực hiện toàn bộ tính năng này.

### ✅ Tương thích ngược
- Lệnh `fetch` cũ hiển thị toàn bộ thư vẫn hoạt động bình thường.
- Các hàm/phương thức cũ không bị ảnh hưởng.

### 🧪 Cách kiểm thử
1. Đăng nhập vào hệ thống (ở chế độ CLI hoặc REPL).
2. Chạy lệnh `list` để xem danh sách email và nhãn bảo mật tương ứng:
   ```bash
   # CLI:
   python -m securemail.main_client list
   # REPL:
   alice@mail.local> list
   ```
3. Chạy lệnh `read <id>` để xem chi tiết email cụ thể (ví dụ email ID là 1):
   ```bash
   # CLI:
   python -m securemail.main_client read 1
   # REPL:
   alice@mail.local> read 1
   ```

---

## [2026-05-31] — Stateful Session Management & Interactive CLI
### 🎯 Mục tiêu
Cho phép người dùng đăng nhập **một lần duy nhất**, sau đó mọi thao tác (gửi/nhận mail, khôi phục khóa, v.v.) đều tự động chạy dưới danh tính người dùng đó mà **không cần nhập lại email/password**.
### 📁 File thay đổi
#### 1. `securemail/client_core.py` — Mở rộng API phiên & khôi phục khóa
| Hàm mới | Mô tả |
|---|---|
| `save_session(ctx)` | Lưu phiên đăng nhập (email, TGT, K\_c\_tgs, cert, private key PEM) vào `data/active_session.json` |
| `load_session()` | Đọc file phiên, khôi phục đầy đủ context dict bao gồm RSA private key. Trả `None` nếu chưa đăng nhập |
| `clear_session()` | Xóa file phiên (đăng xuất) |
| `recover_user_key(email, shares)` | Khôi phục khóa riêng qua Shamir 2-of-3. Tự phát hiện share files nếu không chỉ định. Ghi đè lại file key local |
**Thêm hằng số:**
- `SESSION_FILE = Path("data/active_session.json")`
**Không thay đổi:**
- Các hàm `register()`, `login()`, `get_service_ticket()`, `send_secure_email()`, `fetch_inbox()` — giữ nguyên 100%.
---
#### 2. `securemail/main_client.py` — Viết lại hoàn toàn (65 → 287 dòng)
**Chế độ 1 — Stateful CLI (lệnh đơn, lưu phiên vào file):**
```
python -m securemail.main_client register <email> <password> [<display>]   # Đăng ký (giữ nguyên)
python -m securemail.main_client login <email> <password>                   # Đăng nhập + lưu phiên
python -m securemail.main_client logout                                     # Xóa phiên
python -m securemail.main_client send <to> <subject>                        # Gửi mail (tự load phiên)
python -m securemail.main_client fetch                                      # Nhận mail (tự load phiên)
python -m securemail.main_client recover [<share1> <share2>]                # Khôi phục khóa
python -m securemail.main_client status                                     # Xem ai đang đăng nhập
```
**Chế độ 2 — Interactive Shell (REPL, phiên trong bộ nhớ):**
```
python -m securemail.main_client                                            # Khởi chạy shell
```
Các lệnh trong shell: `login`, `logout`, `send`, `fetch`, `recover`, `status`, `help`, `exit`/`quit`.
**Tính năng shell:**
- Dùng module `cmd.Cmd` chuẩn của Python (hỗ trợ tab-completion, lệnh `help`)
- Prompt thay đổi: `securemail> ` → `alice@mail.local> ` khi đăng nhập
- Xử lý EOF (Ctrl-D / Ctrl-Z) gracefully
- Bắt mọi exception, hiển thị lỗi mà không crash shell
### ✅ Tương thích ngược
- `run_demo.py` và `interactive_demo.py` **không bị ảnh hưởng** — chúng gọi trực tiếp `client_core.login()` / `client_core.send_secure_email()`
- Lệnh `register` hoạt động giống hệt như cũ
### 🧪 Cách kiểm thử
```bash
# Khởi chạy services (4 terminal riêng biệt):
python -m securemail.main_ca serve
python -m securemail.main_kds
python -m securemail.main_ticket
python -m securemail.main_mail_server
# CLI mode:
python -m securemail.main_client login alice@mail.local alice-pw
python -m securemail.main_client status
python -m securemail.main_client send bob@mail.local "Hello Bob"
python -m securemail.main_client logout
# REPL mode:
python -m securemail.main_client
```
---
<!-- 
=== TEMPLATE cho lần cập nhật tiếp theo ===
## [YYYY-MM-DD] — Tiêu đề thay đổi
### 🎯 Mục tiêu
Mô tả ngắn gọn mục đích.
### 📁 File thay đổi
- `path/to/file.py` — Mô tả thay đổi
### ✅ Tương thích ngược
Ghi chú về backward compatibility.
### 🧪 Cách kiểm thử
Lệnh kiểm thử.
-->
