# Prompt UI Design System cho SecureMail

Ban la senior UI/UX designer va product engineer. Nhiem vu cua ban la thiet ke lai SecureMail thanh mot desktop app co tinh tham my, gon, hien dai, co cam giac nhu Gmail/Outlook/Linear hon la mot tool Tkinter mac dinh.

Hay lam theo tung thanh phan ben duoi. Khong chi "doi mau"; can thiet ke lai hierarchy, spacing, empty state, hover state, affordance, typography va content tone.

## 1. Visual Direction Tong The

Thiet ke theo huong:

- Professional dark productivity app, khong phai hacker terminal.
- Lay cam hung tu Gmail dark mode, Outlook desktop, Linear dashboard.
- Mau nen: charcoal/near-black co chieu sau, khong dung den tuyet doi qua nhieu.
- Surface: 2-3 cap do slate/charcoal de tach lop.
- Accent: xanh duong hien dai cho action chinh, xanh la/vang/do chi dung cho trang thai bao mat.
- Typography: Segoe UI, heading ro, body nho gon, khong phong to qua muc.
- Spacing: co he thong 8px, 12px, 16px, 24px; khong de widget sat nhau.
- Border: nhe, khong dong khung tat ca moi thu bang vien day.
- UI phai co cam giac san pham, khong phai demo script.

Checklist:

- Moi man hinh co 1 focal point ro rang.
- Moi action chinh co primary button duy nhat.
- Text trong UI ngan, dung ngu canh, khong giai thich ky thuat dai dong.
- Khong dat log/debug trong Client.
- Monitor moi co audit/debug detail va phai collapsible.

## 2. App Shell

Prompt:

Thiet ke app shell cho SecureMail gom header, sidebar va workspace. Header chi hien brand, current user, session badge. Sidebar la dieu huong chinh, co active state va nut Compose lon neu la Client. Workspace la vung noi dung lon, khong bi canh tranh boi panel phu.

Yeu cau:

- Client khi chua login: an header va sidebar, chi hien auth screen full workspace.
- Client sau login: hien header + sidebar + mailbox workspace.
- Monitor: hien header + sidebar tu dau vi can start service truoc login.
- Header cao vua phai, khong chiem qua nhieu chieu doc.
- Sidebar rong 220-250px, khong rong hon.
- Active nav item co accent bar hoac background ro.
- Hover nav item co doi mau nhe.

Khong duoc:

- Khong de form login nam trong app shell co sidebar khi user chua login.
- Khong de monitor detail panel chiem mac dinh qua 20% chieu ngang.

## 3. Auth Screen Client

Prompt:

Thiet ke man hinh dang nhap/dang ky cho SecureMail Client theo phong cach web auth hien dai. Mac dinh chi hien login card o giua man hinh. Khong co sidebar, khong co header, khong co hero panel lon. Register la state rieng cua cung card, chuyen qua bang link "Create account".

Login card:

- Nam giua man hinh, rong 400-460px.
- Co logo nho, ten app, subtitle ngan.
- Field Email, Password.
- Checkbox Remember session.
- Primary button "Open mailbox".
- Link "Create account".
- Error validation hien trong card, khong chi messagebox neu co the.

Register card:

- Cung kich thuoc/vi tri voi login card.
- Title "Create account".
- Field Display name, Email, Password, Confirm password.
- Primary button "Generate identity".
- Link "Sign in".
- Validate email, password >= 6, confirm khop, account chua trung.

Visual:

- Card co surface khac nen, border nhe, padding 32px.
- Button primary full width, co hover.
- Link hover doi mau.
- Field co focus border accent.

Khong duoc:

- Khong hien login va register cung luc.
- Khong dat them text giai thich dai ngoai card.
- Khong dung button Tkinter mac dinh neu co the custom hover.

## 4. Client Sidebar

Prompt:

Thiet ke sidebar Client nhu Gmail/Outlook. Tren cung la brand block nho, duoi do co nut Compose lon, sau do la nav Inbox, Sent, Security/Recovery.

Yeu cau:

- Nut Compose la primary action lon, full width, de thay.
- Nav item co active state.
- Label ngan: Inbox, Sent, Security.
- Sidebar khong hien service, audit, monitor, scenario.
- Email dang login hien nho duoi brand.

Visual:

- Compose button co background accent.
- Nav item co icon text neu co the bang ky tu ASCII/emoji? Neu khong, dung text don gian.
- Hover state: surface highlight nhe.

## 5. Client Header

Prompt:

Thiet ke header Client nho gon nhu productivity app. Hien brand SecureMail, current user, TGT/session badge. Khong hien service pills trong Client.

Yeu cau:

- Header cao 56-72px.
- Brand trai, user/session phai.
- Badge co mau subdued, khong qua loe.
- Khong chen subtitle dai tren header sau khi login.

## 6. Mailbox View

Prompt:

Thiet ke Inbox/Sent theo phong cach Gmail dark mode. Noi dung chinh la mail list rong, co toolbar tren cung va stat strip gon.

Layout:

- Page title: Inbox hoac Sent.
- Subtitle nho: email dang dang nhap.
- Toolbar: search box lon, filter dropdown, Refresh, Compose.
- Stat cards nho: Total, Secure, Warning, Dangerous.
- Mail list table chi co cac cot can thiet:
  - From/To
  - Subject
  - Date
  - Security

Visual:

- Row height 40-48px.
- Hover row doi mau nhe.
- Selected row co accent.
- Security text dung mau: secure xanh, warning vang, dangerous do.
- Empty state co icon/heading/copy ngan, khong de bang trong.

Khong duoc:

- Khong hien SPF/DKIM/DMARC thanh nhieu cot trong list; chi de trong detail popup.
- Khong hien technical log trong mailbox.

## 7. Message Detail

Prompt:

Thiet ke message detail nhu modal/doc reader. Khi click mail, mo detail popup co header thong tin va body doc de.

Noi dung:

- From, To, Subject, Date.
- Security summary.
- Chips SPF, DKIM, DMARC.
- Body mail.

Visual:

- Popup dark surface, width 760-860px.
- Header tach khoi body.
- Body text co line height de doc.
- Neu co error, hien error banner mau do/vang.

## 8. Compose View

Prompt:

Thiet ke Compose view nhu Gmail compose full-page. Form phai rong, tap trung vao soan thu.

Layout:

- Title "Compose".
- To input.
- Subject input.
- Body editor lon.
- Footer actions: Preview certificate, Send secure mail.

Visual:

- Body editor co nen input rieng, padding lon.
- Send button la primary.
- Preview cert la secondary.
- Neu gui thanh cong, toast/dialog ngan.

Khong duoc:

- Khong liet ke 7 buoc crypto trong Client UI.
- Khong hien log gui mail trong panel.

## 9. Security/Recovery View

Prompt:

Thiet ke Security view cho user binh thuong, khong qua ky thuat nhung van day du.

Layout:

- Card Local Identity:
  - Email
  - Inspect identity
  - Sau inspect hien summary trong card hoac dialog: key/cert/salt status, subject, serial, valid date.
- Card Key Recovery:
  - Email
  - Share selector 1/2/3
  - Recover button

Visual:

- Dung status chips FOUND/MISSING.
- Khong dump duong dan qua dai neu khong can.

## 10. Monitor Shell

Prompt:

Monitor la admin dashboard rieng, khac Client. Co service control truoc login, nhung cac phan audit/metrics can admin login.

Yeu cau:

- Sidebar co Services, Account, Monitoring, Administration, Scenario Lab.
- Service Start/Stop nam ro trong sidebar hoac dashboard top.
- Detail panel mac dinh an.
- Khi click log event moi mo detail panel.
- Detail panel rong 240-280px, co nut Hide.

Khong duoc:

- Khong de detail panel che dashboard ngay tu dau.
- Khong de text log lam trung tam cua dashboard.

## 11. Monitor Dashboard

Prompt:

Thiet ke Monitor dashboard nhu security operations overview.

Layout:

- Row 1: service health cards CA, KDS, Ticket, SMTP, POP3.
- Row 2: metrics Mail stored, Quarantine, Revoked certs, Principals, Revoked TGT.
- Row 3:
  - Event Stream table.
  - Alerts panel.
- Detail panel collapsible ben phai.

Visual:

- Service ON/OFF ro rang bang mau va text.
- Event stream de scan: Time, Service, Event, Details.
- Alerts co severity color.
- SQL error hien thanh banner/callout, khong pha layout.

## 12. Accounts Admin

Prompt:

Thiet ke Accounts view cho admin tao user/admin moi.

Layout:

- Form nam trong card rong vua.
- Field Display name, Email, Password, Confirm, Role.
- Role dropdown ro.
- Button Create account.
- Text nho: "Only admin can create admin accounts."

Validation:

- Email format.
- Password >= 6.
- Confirm khop.
- Account duplicate check.

## 13. DKIM Domains

Prompt:

Thiet ke DKIM view gon nhu admin form.

Layout:

- Domain input.
- Register button.
- Info card: KDS identity, local MTA key, passphrase.

Visual:

- Khong can qua nhieu text.
- Sau register hien result summary.

## 14. Scenario Lab

Prompt:

Thiet ke Scenario Lab nhu test runner/evidence console.

Layout:

- Left: list scenario cards.
- Right: console output.
- Top actions: Bootstrap, Run all.

Visual:

- Status chips READY/RUNNING/PASS/CHECK.
- Console monospace, dark, scroll duoc.
- Scenario cards co ten + co che ngan.

## 15. States va Micro-interactions

Can co:

- Hover cho primary button, secondary button, nav item, link.
- Disabled state cho button khi task dang chay.
- Busy/loading text khi refresh mailbox/service.
- Empty state cho mailbox/logs.
- Error state trong auth/register form.
- Success dialog/toast ngan gon sau send/register/recover.

Khong nen:

- Khong phu thuoc messagebox cho moi validate nho neu co the hien inline.
- Khong dat text ky thuat dai tren man hinh user thuong.

## 16. Acceptance Criteria

- Client auth khong co header/sidebar truoc login.
- Login va register khong hien cung luc.
- Client co Compose lon trong sidebar sau login.
- Mailbox co toolbar, stat cards, empty state.
- Compose khong hien crypto logs.
- Monitor detail panel hidden by default va collapsible.
- Monitor dashboard van doc duoc khi detail panel mo.
- `python -m py_compile` thanh cong.
