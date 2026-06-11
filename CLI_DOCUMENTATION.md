# SecureMail CLI Documentation

Tài liệu này dùng để theo dõi cách chạy, cách kiểm thử, và ý nghĩa các lệnh CLI của Mail Client trong project SecureMail.

## 1. CLI là gì?

CLI là viết tắt của **Command Line Interface**, tức giao diện dòng lệnh. Thay vì thao tác bằng nút bấm như GUI, người dùng nhập lệnh trong Terminal, PowerShell, CMD, hoặc shell tương tự.

Trong project này, CLI nằm ở module:

```powershell
python -m securemail.main_client
```

Mail Client hỗ trợ 2 chế độ:

- **Stateful CLI**: chạy từng lệnh riêng từ terminal, session đăng nhập được lưu trong `data/active_session.json`.
- **Interactive Shell / REPL**: chạy một shell tương tác, session giữ trong bộ nhớ cho đến khi `logout` hoặc `exit`.

## 2. Điều kiện trước khi test CLI

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

GUI hiện có 2 lệnh tách vai trò:

```powershell
# Client cho user: login/register user, gửi/nhận/đọc mail, recovery
python -m securemail.gui.app --mode client

# Monitor: bật service trước, sau đó login admin để xem log/warning/audit/metrics
python -m securemail.main_monitor
```

Trên Windows có thể dùng `run_client.bat` và `run_monitor.bat`.
Lan dau chua co admin, mo Monitor, bam `Start all services`, roi bam `Bootstrap demo data` o man hinh Monitor Login de tao `admin@mail.local` / `admin-pw`.

## 3. Stateful CLI

Stateful CLI là chế độ chạy từng lệnh một. Sau khi `login`, chương trình lưu phiên vào:

```text
data/active_session.json
```

Các lệnh sau như `send`, `list`, `read`, `fetch`, `recover`, `status`, `logout` sẽ tự dùng session này.

### 3.1. Danh sách lệnh

| Lệnh | Mục đích |
|---|---|
| `python -m securemail.main_client register <email> <password> [<display>]` | Đăng ký tài khoản mới. |
| `python -m securemail.main_client login <email> <password>` | Đăng nhập và lưu session. |
| `python -m securemail.main_client status` | Kiểm tra user đang đăng nhập. |
| `python -m securemail.main_client send <to> <subject>` | Gửi email bảo mật, body nhập từ stdin. |
| `python -m securemail.main_client list` | Liệt kê inbox dạng bảng rút gọn. |
| `python -m securemail.main_client read <id>` | Xem chi tiết một email theo ID. |
| `python -m securemail.main_client fetch` | Dump toàn bộ inbox kiểu legacy. |
| `python -m securemail.main_client recover [<email>] [<share1> <share2>]` | Khôi phục private key bằng Shamir 2-of-3. |
| `python -m securemail.main_client admin-register <email> <password> [<display>]` | Tạo tài khoản admin mới, bắt buộc session hiện tại là admin. |
| `python -m securemail.main_client logout` | Đăng xuất và xóa session local. |
| `python -m securemail.main_client gui [client\|monitor\|all]` | Mở GUI theo mode; mặc định là `client`. |

Public `register` luôn tạo role `user`. Muốn tạo role `admin`, login trước bằng admin rồi dùng `admin-register` hoặc mở Monitor > `Accounts`.

### 3.2. Quy trình test đủ 9 lệnh CLI

Chạy trong terminal thứ 5 sau khi đã mở đủ service:

```powershell
$stamp = Get-Date -Format "yyyyMMddHHmmss"
$testUser = "cli_test_$stamp@mail.local"
$testPass = "cli-test-pw"
$subject = "CLI Full Test $stamp"

Write-Host "`n[1] register"
python -m securemail.main_client register $testUser $testPass "CLI Test User"

Write-Host "`n[2] login"
python -m securemail.main_client login $testUser $testPass

Write-Host "`n[3] status"
python -m securemail.main_client status

Write-Host "`n[4] send"
"Hello Bob, this is a full CLI test: $stamp" | python -m securemail.main_client send bob@mail.local $subject

Write-Host "`nSwitch session to Bob for inbox commands"
python -m securemail.main_client login bob@mail.local bob-pw

Write-Host "`n[5] list"
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

Write-Host "`n[6] read"
python -m securemail.main_client read $msgId

Write-Host "`n[7] fetch"
python -m securemail.main_client fetch

Write-Host "`n[8] recover"
python -m securemail.main_client recover bob@mail.local 1 2

Write-Host "`n[9] logout"
python -m securemail.main_client logout

Write-Host "`nCheck status after logout"
python -m securemail.main_client status
```

Kết quả đạt:

- `register` tạo user mới không lỗi.
- `login` báo `Logged in as ... Session saved.`
- `status` hiển thị email đang active.
- `send` trả kết quả có `ok: True`.
- `list` hiện bảng có cột `ID`, `Status`, `Date`, `From`, `Subject`.
- `read <id>` hiện `From`, `To`, `Subject`, `Security`, `Signature`, `SPF`, `DKIM`, `DMARC`, `Body`.
- `fetch` vẫn dump toàn bộ inbox.
- `recover` báo restored private key.
- `logout` xóa session, `status` sau logout báo `No active session.`

## 4. Interactive Shell / REPL

Khởi chạy:

```powershell
python -m securemail.main_client
```

Prompt ban đầu:

```text
securemail>
```

Sau khi login thành công:

```text
alice@mail.local>
```

### 4.1. Lệnh trong REPL

| Lệnh | Mục đích |
|---|---|
| `login <email> <password>` | Đăng nhập trong REPL. |
| `status` | Xem session hiện tại. |
| `send <to> [<subject>]` | Gửi email, nhập body nhiều dòng. |
| `list` | Xem inbox dạng bảng và cache kết quả. |
| `read <id>` | Đọc thư theo ID, ưu tiên cache từ `list`. |
| `fetch` | Dump toàn bộ inbox kiểu legacy. |
| `recover [<email>] [<share1> <share2>]` | Khôi phục private key. |
| `logout` | Đăng xuất khỏi REPL. |
| `help` / `help <lệnh>` | Xem trợ giúp. |
| `exit` / `quit` | Thoát REPL. |

### 4.2. Quy trình test REPL

Chạy:

```powershell
python -m securemail.main_client
```

Nhập lần lượt:

```text
login alice@mail.local alice-pw
status
send bob@mail.local REPL CLI Test
```

Sau lệnh `send`, nhập nội dung mail và Enter dòng trống để gửi:

```text
Hello Bob from REPL

```

Tiếp tục:

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

## 5. Kiểm tra lỗi tham số

Các lệnh sau phải báo lỗi thân thiện, không được hiện traceback Python:

```powershell
python -m securemail.main_client register
python -m securemail.main_client login alice@mail.local
python -m securemail.main_client send
python -m securemail.main_client read abc
python -m securemail.main_client recover unknown@mail.local 1
```

Kết quả đạt nếu output có dạng `Usage:` hoặc thông báo lỗi rõ ràng.

## 6. Ý nghĩa nhãn bảo mật trong `list`

| Nhãn | Ý nghĩa |
|---|---|
| `SECURE` | Chữ ký hợp lệ, SPF pass, DMARC accept, không có dấu hiệu nghi ngờ. |
| `WARNING` | Có dấu hiệu cần chú ý như DMARC quarantine, SPF fail, DKIM fail/anomaly, từ khóa cảnh báo, hoặc sender ngoài `@mail.local`. |
| `DANGEROUS` | Có lỗi giải mã/xác thực, chữ ký S/MIME invalid, DMARC reject, hoặc nội dung chứa từ khóa nguy hiểm. |

## 7. File dữ liệu liên quan

| File | Vai trò |
|---|---|
| `data/active_session.json` | Session đăng nhập của Stateful CLI. |
| `data/mail/mailstore.db` | Database SQLite lưu email. |
| `data/mail.log` | Log Mail Server. |
| `data/ticket/ticket.db` | Dữ liệu Ticket Service. |
| `data/users/*.key.pem` | Private key người dùng. |
| `data/users/*.cert.pem` | Certificate người dùng. |
| `data/ca/escrow/*.share*.bin` | Shamir key recovery shares. |

## 8. Ghi chú khi test

- Lệnh `register` tạo user thật và ghi dữ liệu vào `data/users`, `data/ca/ca.db`, `data/kds/kds.db`, `data/ticket/ticket.db`.
- Lệnh `send` tạo email thật trong `data/mail/mailstore.db`.
- Lệnh `recover` có thể ghi đè private key local của user được khôi phục.
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

