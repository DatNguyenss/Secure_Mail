# Testcases: DKIM, Mail Status, Key Recovery

## 1. Giai thich chuc nang

### DKIM domain signing by Mail Server

DKIM khong con la checkbox cua user trong man hinh `Compose`. Theo dung nghiep vu mail, DKIM la chinh sach cua domain/MTA: Mail Server tu ky DKIM cho domain ma he thong kiem soat duoc key.

Hanh vi hien tai:

- Mail van luon duoc ky va ma hoa bang S/MIME truoc khi gui.
- DKIM la lop kiem tra bo sung o muc header/body cua domain `mail.local`.
- Khi SMTP server nhan mail, neu co key `data/server/mta_<domain>_key.pem`, server ky DKIM bang key do.
- Server verify DKIM bang cert trong KDS tai identity `_dkim.<domain>`.
- Admin co the vao tab `DKIM Domains` de dang ky DKIM domain vao KDS. Flow nay tao key MTA local, xin CA ky cert, va publish cert len KDS.
- Neu domain khong co key/cert DKIM trong he thong, ket qua DKIM co the la `none` hoac `no_key`.
- Ben nhan se thay cot `DKIM` trong Inbox/Sent la `pass`, `fail`, `none`, hoac gia tri bat thuong khac tuy server verify.

### Status cua thu

Cot `Status` trong Inbox/Sent duoc tinh bang `client_core.classify_security(msg)`.

- `SECURE`: khong co loi giai ma/verify, S/MIME signature hop le, SPF pass, DMARC accept, DKIM pass hoac none, khong co tu khoa nguy hiem/canh bao.
- `WARNING`: co van de muc canh bao nhu DMARC quarantine, SPF fail, DKIM fail/anomaly, subject/body co `warning`, `critical`, `suspicious`, hoac sender ngoai `@mail.local`.
- `DANGEROUS`: co loi giai ma/verify, S/MIME signature invalid, DMARC reject, hoac subject/body co `virus`, `malware`, `hack`, `phishing`.

Bo loc tren mailbox:

- `All`: hien tat ca.
- `Secure`, `Warning`, `Dangerous`: loc theo status.
- `Signed`: thu co `signature_valid=True`.
- `Failed`: thu co `error` hoac `signature_valid=False`.
- `Quarantine`: thu co `dmarc_action='quarantine'`.

### Key Recovery

Man hinh `Security / Recovery` co nut `Recover private key`.

Hanh vi hien tai:

- User chon dung 2 trong 3 shares.
- GUI goi `client_core.recover_user_key(email, shares)`.
- Core doc 2 share tu bang SQL `ca.escrow_shares`, ghep lai private key bang Shamir 2-of-3.
- Key recovered duoc ghi de vao `data/users/<email_safe>.key.pem`.
- Sau khi recover thanh cong, user co the login/giai ma mail lai bang password cua account do.
- Neu chon khac dung 2 share, GUI canh bao `Chon dung 2 share trong 3 share.`

## 2. Dieu kien chuan bi

- SQL Server va `.env` da cau hinh dung.
- Da bootstrap du lieu demo:

```powershell
python -m securemail.run_demo bootstrap
```

- Chay cac service can thiet:

```powershell
python -m securemail.main_ca serve
python -m securemail.main_kds
python -m securemail.main_ticket
python -m securemail.main_mail_server
```

- Chay GUI:

```powershell
python -m securemail.gui.app
```

- Tai khoan demo:

```text
alice@mail.local / alice-pw
bob@mail.local   / bob-pw
admin@mail.local / admin-pw
```

## 3. Testcases DKIM

| ID | Muc tieu | Buoc test | Ket qua mong doi |
|---|---|---|---|
| DKIM-01 | Compose khong con checkbox DKIM | Login `alice@mail.local`; vao Compose | Khong con checkbox `Client-side DKIM`; user chi nhap To/Subject/Body va gui |
| DKIM-02 | MTA DKIM hop le cho `mail.local` | Dam bao da bootstrap hoac admin da register `mail.local`; login Alice; gui mail cho Bob; login Bob; Refresh Inbox | Cot `DKIM` la `pass`; status du kien `SECURE`; detail message hien `DKIM: pass` |
| DKIM-03 | Admin dang ky DKIM domain vao KDS | Login `admin@mail.local`; vao tab `DKIM Domains`; nhap domain `mail.local` hoac domain demo moi; bam `Register in KDS` | Messagebox bao domain created/already registered; panel log identity `_dkim.<domain>` va duong dan `data/server/mta_<domain>_key.pem` |
| DKIM-04 | Domain chua co key DKIM | Dung mot sender domain chua duoc admin register; gui/nhan mail trong demo | Cot `DKIM` la `none` hoac `no_key`; khong crash GUI; DMARC phu thuoc SPF va policy domain |
| DKIM-05 | Preview cert truoc khi gui | Compose; nhap To `bob@mail.local`; bam `Preview recipient cert` | Panel phai log subject, serial, valid-until cua cert Bob |
| DKIM-06 | Recipient khong co cert | Compose; To `unknown@mail.local`; bam `Send secure mail` | GUI bao loi `Recipient has no certificate in KDS.` hoac log failed tu KDS |

## 4. Testcases status va filter thu

| ID | Muc tieu | Buoc test | Ket qua mong doi |
|---|---|---|---|
| STATUS-01 | Thu secure binh thuong | Alice gui mail cho Bob voi subject/body binh thuong, khong co tu khoa canh bao/nguy hiem; Bob Refresh Inbox | Cot `Status` la `SECURE`; detail message ghi `Signature: VALID`, SPF pass, DMARC accept |
| STATUS-02 | Thu warning do keyword | Alice gui mail cho Bob voi subject `warning test` hoac body co chu `suspicious`; Bob Refresh Inbox | Cot `Status` la `WARNING`; detail reason co `Suspicious keyword` |
| STATUS-03 | Thu dangerous do keyword | Alice gui mail cho Bob voi subject/body co chu `phishing` hoac `malware`; Bob Refresh Inbox | Cot `Status` la `DANGEROUS`; detail reason co `Dangerous keyword detected` |
| STATUS-04 | Filter Secure | Bob vao Inbox; chon filter `Secure` | Chi hien cac mail co cot `Status=SECURE` |
| STATUS-05 | Filter Warning | Bob vao Inbox; chon filter `Warning` | Chi hien cac mail co cot `Status=WARNING` |
| STATUS-06 | Filter Dangerous | Bob vao Inbox; chon filter `Dangerous` | Chi hien cac mail co cot `Status=DANGEROUS` |
| STATUS-07 | Filter Signed | Bob vao Inbox; chon filter `Signed` | Chi hien cac mail co `signature_valid=True`; mail S/MIME hop le se xuat hien |
| STATUS-08 | Detail message | Double click/chon mot mail trong Inbox | Cua so detail hien From/To/Subject/Date, `Security: <label> - <reason>`, SPF/DKIM/DMARC, va body da giai ma |

## 5. Testcases Key Recovery

| ID | Muc tieu | Buoc test | Ket qua mong doi |
|---|---|---|---|
| REC-01 | Inspect identity hien file local | Login Bob; vao `Security / Recovery`; bam `Inspect local cert/key` | Panel phai log `Key file`, `Cert file`, `Salt file` voi `FOUND` neu bootstrap dung; log subject/issuer/serial/thoi han cert |
| REC-02 | Recover thanh cong bang share 1+2 | Login Bob; vao `Security / Recovery`; email `bob@mail.local`; chon share `1` va `2`; bam `Recover private key` | Messagebox bao recovered; panel log `Recovered <n> bytes for bob@mail.local using shares [1, 2]`; key duoc ghi vao `data/users/bob_at_mail.local.key.pem` |
| REC-03 | Recover thanh cong bang share 1+3 | Chon share `1` va `3`; bam recover | Ket qua thanh cong nhu REC-02, chung minh 2-of-3 |
| REC-04 | Recover thanh cong bang share 2+3 | Chon share `2` va `3`; bam recover | Ket qua thanh cong nhu REC-02 |
| REC-05 | Chi chon 1 share | Chi chon share `1`; bam recover | GUI canh bao `Chon dung 2 share trong 3 share.`; khong goi recovery |
| REC-06 | Chon ca 3 share | Chon `1`, `2`, `3`; bam recover | GUI canh bao `Chon dung 2 share trong 3 share.`; khong goi recovery |
| REC-07 | Email khong co escrow share | Nhap `unknown@mail.local`; chon `1` va `2`; bam recover | GUI bao loi share khong ton tai, vi SQL khong co record trong `ca.escrow_shares` |
| REC-08 | Verify sau recovery | Sau REC-02, logout; login lai Bob bang `bob-pw`; Refresh Inbox va mo mot mail cu | Login thanh cong; mail giai ma duoc; khong co loi private key/decryption |

## 6. Luu y khi test recovery that

- Nut recovery ghi de file private key local cua email dang recover.
- Neu muon test mat key that, hay backup file `data/users/<email_safe>.key.pem` truoc khi doi ten/xoa thu cong.
- Khong can xoa key de test REC-02 den REC-04; recovery thanh cong van ghi lai cung noi dung key vao file.
