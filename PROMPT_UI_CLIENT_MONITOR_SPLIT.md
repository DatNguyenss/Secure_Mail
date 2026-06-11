# Prompt thiet ke lai UI SecureMail: tach Client va Monitor

Ban la coding agent dang lam tren project Python SecureMail. Hay thiet ke va trien khai lai UI theo huong tach ro hai ung dung chay bang hai lenh rieng:

1. SecureMail Client
   - Chay bang `python -m securemail.gui.app --mode client` hoac `run_client.bat`.
   - Chi phuc vu luong nguoi dung theo do an: login, public register tai khoan user, inbox, sent, compose, message detail, security/recovery.
   - Khong hien nut start/stop service, monitor log, warning, audit, DKIM admin hay scenario admin.
   - Public register luon tao role `user`; khong duoc tao role `admin` tu man hinh client.

2. SecureMail Monitor
   - Chay bang `python -m securemail.main_monitor` hoac `run_monitor.bat`.
   - Co man hinh login. Nut start/stop service duoc phep hien truoc login de tranh ket khi Ticket Service dang tat.
   - Monitor Login can co nut bootstrap demo data truoc khi dang nhap, vi bootstrap tao tai khoan `admin@mail.local`.
   - Chi role `admin` moi duoc vao dashboard monitor.
   - Monitor chiu trach nhiem start/stop service, refresh trang thai CA/KDS/Ticket/SMTP/POP3, xem audit log, warning/alert, metrics, DKIM domain admin, scenario evidence.
   - Neu user thuong login vao monitor thi hien man hinh bao khong du quyen va cho logout.

3. Quan ly tai khoan admin
   - Muon tao tai khoan admin moi thi phai dang nhap bang tai khoan admin da ton tai.
   - Them man hinh Accounts trong Monitor cho admin tao account voi role `user`, `admin`, hoac `mailing_list_manager`.
   - Them API trong client-core de tao account tu `actor_ctx`; API nay phai kiem tra `actor_ctx.role == "admin"`.
   - Them CLI `python -m securemail.main_client admin-register <email> <password> [<display>]` va bat buoc dung saved session admin.

4. Chap nhan ket qua
   - `run_client.bat` mo Client mode.
   - `run_monitor.bat` mo Monitor mode.
   - `python -m securemail.gui.app --mode all` van co the mo giao dien gom tat ca neu can demo legacy.
   - `python -m py_compile` qua cho cac file da sua.
   - README va CLI documentation phai ghi ro hai lenh Client/Monitor va rule tao admin.
