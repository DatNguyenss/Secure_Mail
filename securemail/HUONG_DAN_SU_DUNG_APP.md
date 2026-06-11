# Huong dan su dung SecureMail Desktop App

Tai lieu nay huong dan chay SecureMail bang giao dien desktop Tkinter, khong can mo tung service bang CLI.

## 1. Chuan bi truoc khi mo app

Can cai dependency mot lan:

```powershell
pip install -r securemail/requirements.txt
```

Can SQL Server dang chay va database `SecureMail` da duoc tao tu file `securemail_sqlserver.sql`.

Neu khong co file `.env`, app dung cau hinh mac dinh:

```text
DB_HOST=localhost
DB_PORT=1433
DB_NAME=SecureMail
DB_USER=sa
DB_PASSWORD=123
```

Neu may ban dung thong tin SQL khac, tao file `.env` o project root va sua cac gia tri tren.

## 2. Mo app

Cach khuyen dung co 2 app rieng:

| App | File/Lệnh | Vai tro |
|---|---|---|
| Client | `run_client.bat` | Mail app dark theme theo huong Gmail: nut Compose lon, dang nhap, public register user, gui/nhan/doc mail, recovery. Khong co log/debug panel. |
| Monitor | `run_monitor.bat` | Dashboard dark theme: admin login, start/stop service, log, warning, audit, metrics, account admin. Detail panel mac dinh an de khong che noi dung. |

Cach thay the neu dang dung terminal:

```powershell
python -m securemail.gui.app --mode client
python -m securemail.main_monitor
```

`run_gui.bat` hien duoc giu nhu alias mo Client. Neu can giao dien gom tat ca nhu ban cu, chay `python -m securemail.gui.app --mode all`.

Khong chay truc tiep file `securemail/gui/app.py` bang duong dan tuyet doi, vi Python co the khong tim thay package `securemail`.

## 3. Bat tat tat ca service trong app

Mo `run_monitor.bat`. Nut service nam ngay tren sidebar Monitor nen co the bat service truoc khi login:

1. Bam `Start all services`.
2. Doi cac badge tren header chuyen thanh:
   `CA ON`, `KDS ON`, `TICKET ON`, `SMTP ON`, `POP3 ON`.
3. Khi muon tat, bam `Stop all services`.
4. Doi cac badge chuyen ve `OFF`.

Neu chua bootstrap, Mail Server co the duoc skip cho den khi co `data/server/mail_key.pem` va `data/server/mail_cert.pem`.

Nut nay quan ly cac service:

| Service | Cong |
|---|---:|
| CA | 9000 |
| KDS | 9001 |
| Ticket Service | 9002 |
| SMTP | 2525 |
| POP3 | 1100 |

Sau khi `TICKET ON`, login bang tai khoan admin de vao `Monitoring > Dashboard`, log, warning va audit. Neu admin chua ton tai, bam `Bootstrap demo data` ngay man hinh Monitor Login.

## 4. Bootstrap du lieu demo lan dau

Lan dau chay Monitor, sau khi bam `Start all services`, bam `Bootstrap demo data` ngay man hinh Monitor Login. Neu da login admin duoc, cung co the vao `Scenario Lab > Scenarios` va bam `Bootstrap`.

Bootstrap se tao:

- Chung thu server mail.
- Key DKIM/MTA.
- User demo: `alice@mail.local`, `bob@mail.local`, `eve@mail.local`, `admin@mail.local`.
- SPF/DMARC policy.
- CRL ban dau.
- Key escrow cho Bob.

Tai khoan demo:

| Email | Password |
|---|---|
| alice@mail.local | alice-pw |
| bob@mail.local | bob-pw |
| eve@mail.local | eve-pw |
| admin@mail.local | admin-pw |

## 5. Dang ky va dang nhap

Trong Client, vao `Login / Register`.

Dang nhap:

1. Nhap email va password.
2. Chon `Remember session` neu muon app luu session.
3. Bam `Login`.

Dang ky user moi:

1. O man hinh dang nhap, bam `Create account`.
2. Nhap display name, email, password.
3. Nhap lai password o confirm password.
4. Bam `Generate identity`.

App se kiem tra email hop le, password khop confirm, password du dai va email chua bi trung truoc khi tao identity. Khi dang ky thanh cong, app tao local private key/cert trong `data/users`, dang ky principal voi Ticket Service, va push cert len KDS.
Tai khoan dang ky tu man hinh nay luon co role `user`.

Tao admin moi:

1. Mo Monitor bang `run_monitor.bat`.
2. Login bang admin hien co, vi du `admin@mail.local` / `admin-pw`.
3. Vao `Administration > Accounts`.
4. Chon role `admin` va bam `Create account`.

Tu CLI, login admin truoc roi chay:

```powershell
python -m securemail.main_client admin-register new_admin@mail.local new-admin-pw "New Admin"
```

Neu app da luu session cu, logout hoac mo lai app roi dang nhap lai de cap nhat role moi nhat tu Ticket Service.

## 6. Gui email bao mat

Trong Client, vao `Compose`.

1. Dang nhap truoc, vi gui mail can TGT va Service Ticket.
2. O `To`, nhap email nguoi nhan, vi du `bob@mail.local`.
3. Nhap subject va body.
4. Bam `Preview recipient cert` de kiem tra cert nguoi nhan.
5. Bam `Send secure mail`.

App se tu dong:

- Lay cert nguoi nhan tu KDS.
- Verify chain voi Root CA va CRL/OCSP.
- Ky mail bang RSA-PSS.
- Ma hoa S/MIME-lite bang AES + RSA-OAEP.
- Lay Service Ticket Kerberos-lite.
- Gui qua SMTP STARTTLS-lite.
- Server kiem tra SPF/DKIM/DMARC va luu encrypted envelope.

## 7. Doc Inbox va Sent

Trong Client, vao `Inbox` hoac `Sent`.

1. Dang nhap bang user can xem mail.
2. Bam `Refresh`.
3. Chon mot dong mail de xem chi tiet.

Bang mail hien thi:

- `Status`: SECURE / WARNING / DANGEROUS.
- `SPF`, `DKIM`, `DMARC`.
- Sender/recipient, subject, date.

Khi chon mail, app mo cua so chi tiet va panel ben phai hien giai thich security.

## 8. Security / Recovery

Trong Client, vao `Security / Recovery`.

Chuc nang kiem tra identity:

1. Nhap email.
2. Bam `Inspect local identity`.
3. Panel ben phai hien file key/cert/salt, subject, issuer, serial, han cert.

Chuc nang khoi phuc private key:

1. Nhap email can khoi phuc, vi du `bob@mail.local`.
2. Chon dung 2 share trong 3 share.
3. Bam `Recover private key`.

Demo mac dinh da co escrow cho Bob sau khi bootstrap.

## 9. Monitoring Dashboard

Trong Monitor, vao `Monitoring > Dashboard`.

Trang nay dung de:

- Bat/tat tat ca service.
- Refresh trang thai service.
- Xem audit event stream tu CA/Ticket/KDS/Mail.
- Xem metrics va alert bao mat.

Neu SQL Server khong ket noi duoc, app van mo duoc nhung khu vuc metrics/log se hien loi SQL.

## 10. Scenario Lab

Trong Monitor, vao `Scenario Lab > Scenarios`.

Nut chinh:

- `Bootstrap`: tao du lieu demo.
- `Run all`: chay toan bo 8 scenario.
- `Run`: chay tung scenario rieng.

8 scenario gom:

1. Normal encrypted + signed email.
2. MITM / public-key substitution.
3. Replay attack.
4. Revoked certificate.
5. Spoofed sender.
6. Reusable ticket.
7. Key recovery.
8. HKDF subsession key.

Ket qua va evidence hien trong `Console Output`; badge tung scenario se chuyen sang `PASS` neu thanh cong.

## 11. Thu tu su dung khuyen nghi

Lan dau:

1. Double-click `run_monitor.bat`.
2. Bam `Start all services`.
3. Bam `Bootstrap demo data` neu admin chua ton tai.
4. Login Monitor bang `admin@mail.local` / `admin-pw`.
5. Bam `Start all services` lai neu Mail Server dang bi skip truoc bootstrap.
6. Mo `run_client.bat`.
7. Login `alice@mail.local` / `alice-pw`.
8. Gui mail cho `bob@mail.local`.
9. Login Bob va vao Inbox de doc mail.
10. Quay lai Monitor de xem log/alert.
11. Khi xong, bam `Stop all services`.

Nhung lan sau:

1. Double-click `run_monitor.bat`.
2. Bam `Start all services`.
3. Double-click `run_client.bat` de dung mail client.
4. Bam `Stop all services` trong Monitor truoc khi thoat.

## 12. Loi thuong gap

### App bao loi CA/KDS/Ticket/SMTP/POP3 offline

Bam `Start all services`, sau do bam `Refresh services`.

### Mail Server khong start

Chay `Bootstrap` trong Scenario Lab de tao `data/server/mail_key.pem` va `data/server/mail_cert.pem`, roi bam `Start all services` lai.

### Khong ket noi duoc SQL Server

Kiem tra SQL Server dang chay, database `SecureMail` da duoc tao, va file `.env` dung thong tin ket noi.

### Chay truc tiep `app.py` bi `ModuleNotFoundError: No module named 'securemail'`

Dung `run_client.bat`, `run_monitor.bat`, hoac chay module tu project root:

```powershell
python -m securemail.gui.app --mode client
python -m securemail.main_monitor
```

### Port da bi dung

Bam `Stop all services` trong app. Neu van con loi, dong cac cua so Python cu hoac restart may de giai phong port.
