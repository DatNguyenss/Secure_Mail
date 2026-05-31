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
| `fetch` | Tải và giải mã hiển thị toàn bộ inbox (legacy view). |
| `recover [<email>] [<share1> <share2>]` | Khôi phục khóa riêng bằng Shamir từ REPL. Nếu chưa đăng nhập, bắt buộc truyền vào `<email>`. |
| `logout` | Đăng xuất người dùng hiện tại, prompt quay lại thành `securemail> `. |
| `help` / `help <lệnh>` | Hiển thị trợ giúp của REPL hoặc chi tiết cách dùng một lệnh. |
| `exit` / `quit` | Thoát chế độ Interactive Shell (REPL). |

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
