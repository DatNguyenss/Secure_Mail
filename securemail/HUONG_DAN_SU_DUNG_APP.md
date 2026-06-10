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

Cach khuyen dung:

1. Double-click file `run_gui.bat` o thu muc project root.
2. Cua so `SecureMail Desktop` se mo len.

Cach thay the neu dang dung terminal:

```powershell
python -m securemail.gui.app
```

Khong chay truc tiep file `securemail/gui/app.py` bang duong dan tuyet doi, vi Python co the khong tim thay package `securemail`.

## 3. Bat tat tat ca service trong app

Trong sidebar ben trai hoac trang `Monitoring > Dashboard`:

1. Bam `Start all services`.
2. Doi cac badge tren header chuyen thanh:
   `CA ON`, `KDS ON`, `TICKET ON`, `SMTP ON`, `POP3 ON`.
3. Khi muon tat, bam `Stop all services`.
4. Doi cac badge chuyen ve `OFF`.

Nut nay quan ly cac service:

| Service | Cong |
|---|---:|
| CA | 9000 |
| KDS | 9001 |
| Ticket Service | 9002 |
| SMTP | 2525 |
| POP3 | 1100 |

## 4. Bootstrap du lieu demo lan dau

Lan dau chay app, sau khi bam `Start all services`, vao:

`Scenario Lab > Scenarios`

Bam `Bootstrap`.

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

Vao `User App > Login / Register`.

Dang nhap:

1. Nhap email va password.
2. Chon `Remember session` neu muon app luu session.
3. Bam `Login`.

Dang ky user moi:

1. Nhap display name, email, password.
2. Nhap lai password o confirm password.
3. Bam `Generate keypair + Register`.

Khi dang ky thanh cong, app tao local private key/cert trong `data/users`, dang ky principal voi Ticket Service, va push cert len KDS.
Tai khoan dang ky tu man hinh nay luon co role `user`. Tai khoan `admin` duoc tao san khi chay `Bootstrap`, khong cho nguoi dung tu dang ky admin.
Neu app da luu session cu, logout hoac mo lai app roi dang nhap lai de cap nhat role moi nhat tu Ticket Service.

## 6. Gui email bao mat

Vao `User App > Compose`.

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

Vao `User App > Inbox` hoac `User App > Sent`.

1. Dang nhap bang user can xem mail.
2. Bam `Refresh`.
3. Chon mot dong mail de xem chi tiet.

Bang mail hien thi:

- `Status`: SECURE / WARNING / DANGEROUS.
- `SPF`, `DKIM`, `DMARC`.
- Sender/recipient, subject, date.

Khi chon mail, app mo cua so chi tiet va panel ben phai hien giai thich security.

## 8. Security / Recovery

Vao `User App > Security / Recovery`.

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

Vao `Monitoring > Dashboard`.

Trang nay dung de:

- Bat/tat tat ca service.
- Refresh trang thai service.
- Xem audit event stream tu CA/Ticket/KDS/Mail.
- Xem metrics va alert bao mat.

Neu SQL Server khong ket noi duoc, app van mo duoc nhung khu vuc metrics/log se hien loi SQL.

## 10. Scenario Lab

Vao `Scenario Lab > Scenarios`.

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

1. Double-click `run_gui.bat`.
2. Bam `Start all services`.
3. Vao `Scenario Lab`, bam `Bootstrap`.
4. Login `alice@mail.local` / `alice-pw`.
5. Gui mail cho `bob@mail.local`.
6. Login Bob va vao Inbox de doc mail.
7. Vao Monitoring de xem log/alert.
8. Khi xong, bam `Stop all services`.

Nhung lan sau:

1. Double-click `run_gui.bat`.
2. Bam `Start all services`.
3. Login va dung app binh thuong.
4. Bam `Stop all services` truoc khi thoat.

## 12. Loi thuong gap

### App bao loi CA/KDS/Ticket/SMTP/POP3 offline

Bam `Start all services`, sau do bam `Refresh services`.

### Mail Server khong start

Chay `Bootstrap` trong Scenario Lab de tao `data/server/mail_key.pem` va `data/server/mail_cert.pem`, roi bam `Start all services` lai.

### Khong ket noi duoc SQL Server

Kiem tra SQL Server dang chay, database `SecureMail` da duoc tao, va file `.env` dung thong tin ket noi.

### Chay truc tiep `app.py` bi `ModuleNotFoundError: No module named 'securemail'`

Dung `run_gui.bat` hoac chay module tu project root:

```powershell
python -m securemail.gui.app
```

### Port da bi dung

Bam `Stop all services` trong app. Neu van con loi, dong cac cua so Python cu hoac restart may de giai phong port.
