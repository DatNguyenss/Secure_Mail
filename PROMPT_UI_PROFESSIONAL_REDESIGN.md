# Prompt thiet ke lai UI SecureMail chuyen nghiep

Ban la senior product engineer va UI designer dang lam tren project Python Tkinter SecureMail. Hay thiet ke lai UI theo huong ung dung desktop chuyen nghiep, lay cam hung tu anh mau dark-mode SecureMail:

> Luu y: Neu can spec chi tiet theo tung component, dung `PROMPT_UI_COMPONENT_DESIGN_SYSTEM.md` lam nguon chinh. File nay la tom tat muc tieu tong the.

## Muc tieu san pham

1. Client la ung dung mail that su
   - Chay bang `python -m securemail.gui.app --mode client` hoac `run_client.bat`.
   - Khong hien log/debug panel ben phai.
   - Khong hien dieu khien service, audit, warning, scenario, DKIM admin.
   - Man hinh chinh gom sidebar trai, header gon, workspace lon.
   - Cac view can co: Login/Register, Inbox, Sent, Compose, Security/Recovery.
   - Inbox/Sent uu tien doc nhanh: search, filter, nut refresh, nut compose, bang thu rong, mau status ro rang.
   - Compose phai trong nhu form mail hien dai: To, Subject, Body lon, actions ro rang.
   - Khi khong co mail, khong de bang trong vo nghia; can empty state co thong diep ngan gon.
   - Cac thong tin ky thuat nhu cert preview, identity inspection phai hien bang dialog/thong bao nguoi dung, khong dung log panel.

2. Monitor la dashboard quan tri rieng
   - Chay bang `python -m securemail.main_monitor` hoac `run_monitor.bat`.
   - Cho phep start/stop service truoc login de tranh ket khi Ticket Service dang tat.
   - Co nut bootstrap demo data o man login neu chua co admin.
   - Sau login admin, hien dashboard service, metrics, audit event stream, warning/alerts, DKIM, Accounts, Scenario Lab.
   - Monitor duoc phep co operation/detail panel vi day la cong cu audit/admin, nhung panel nay phai an/ hien duoc va khong chiem man hinh mac dinh.
   - Dashboard can co 2 lop so lieu: service health cards va security/operation metric cards.
   - Event stream can de doc nhanh: time, service, event, detail; click mot event thi detail panel cap nhat.

3. Visual style
   - Dark professional, nen gan den xanh den, surface slate, border slate sang.
   - Accent chinh xanh duong/tim hien dai; status dung xanh la, vang, do.
   - Sidebar rong vua du, brand ro, nav button co active/hover feel.
   - Khong dung giao dien xam mac dinh cua Tkinter neu co the style duoc.
   - Khoang cach, font size, heading, card, table phai gon va nhin nhu mot app that, khong phai log viewer.

## Layout chi tiet

### Client

- Header tren cung chi hien brand, subtitle ngan, current user va TGT.
- Sidebar trai co brand block, email dang nhap, nut Compose lon theo phong cach Gmail, nav item co active state.
- Workspace chi gom noi dung nghiep vu; khong co cot log.
- Login screen:
  - Mac dinh chi hien mot auth card o giua man hinh, khong co hero/intro panel lam roi bo cuc.
  - Auth card co logo, ten app, subtitle ngan va form Sign in.
  - Co link/nut chuyen sang Create account; khi bam thi card doi sang form dang ky.
  - Dang ky co validate email, password, confirm password va kiem tra trung account truoc khi tao key/cert.
  - Nut primary va link phai co hover state ro rang.
- Inbox/Sent:
  - Title + subtitle.
  - Stat strip: Total, Secure, Warning, Dangerous.
  - Toolbar: search, filter, refresh, compose.
  - Bang mail: Nguoi gui/Nguoi nhan, Tieu de, Thoi gian, Bao mat.
  - Double/click row mo detail popup dark theme.
- Compose:
  - Form rong, body lon, nut preview cert va send secure mail.
- Security:
  - Local Identity va Key Recovery thanh hai panel rieng.

### Monitor

- Header co service pills.
- Sidebar co Services, Account, Monitoring, Administration, Scenario Lab.
- Truoc login van thay Start/Stop services va Bootstrap demo data.
- Sau login admin:
  - Service health row.
  - Metric cards row: mail stored, quarantine, revoked certs, principals, revoked TGT.
  - Event Stream va Alerts/Metrics dat canh nhau.
  - Detail panel mac dinh an, co nut hien/ an, rong vua du, chi mo khi admin can xem selected event hoac debug operation.

## Chap nhan ket qua

- Client mode khong con thay panel log ben phai.
- Client khong thay service controls hay audit/debug content.
- Monitor mode van co service controls, audit detail va bootstrap.
- Sidebar co active state, khong chi la nut Tkinter mac dinh.
- Client co nut Compose lon o sidebar theo cach Gmail/Outlook.
- Mailbox co stat cards va empty state.
- Monitor co metric cards rieng, khong nhet tat ca vao text log.
- Monitor detail panel khong duoc che dashboard mac dinh; phai collapsible hoac hidden by default.
- `python -m py_compile securemail/gui/app.py securemail/main_client.py securemail/client_core.py securemail/main_monitor.py` thanh cong.
- Tai lieu neu co nhac UI thi cap nhat dung Client/Monitor.
