# ĐỀ XUẤT DỰ ÁN (PROJECT PROPOSAL): HỆ THỐNG THƯ ĐIỆN TỬ BẢO MẬT NỘI BỘ (SECUREMAIL)

> **Môn học:** Bảo mật Mạng Máy Tính  
> **Ngôn ngữ triển khai:** Python 3.11+ (Sử dụng thư viện duy nhất cho mật mã: `cryptography>=42`)  
> **Kiến trúc:** Microservices phân tán kết hợp Mã hóa đầu cuối (E2EE), Xác thực Kerberos-lite và Bộ ba chống mạo danh SPF/DKIM/DMARC.

---

## 1. GIỚI THIỆU & BỐI CẢNH DỰ ÁN (INTRODUCTION & CONTEXT)

### 1.1. Hiện trạng và Đặt vấn đề
Hệ thống thư điện tử truyền thống (SMTP, POP3, IMAP tiêu chuẩn) được thiết kế từ thời kỳ đầu của Internet, khi các yếu tố bảo mật chưa được ưu tiên hàng đầu. Mặc dù các giao thức hiện đại đã bổ sung mã hóa kênh truyền (TLS/SSL), email vẫn gặp phải các rủi ro bảo mật nghiêm trọng sau:
1. **Rò rỉ dữ liệu tại máy chủ (Server-side Vulnerability):** TLS chỉ bảo vệ dữ liệu trên đường truyền (Transit). Khi email tới Mail Server (MTA), nó tồn tại dưới dạng văn bản thuần (Plaintext). Nếu quản trị viên hệ thống có ý đồ xấu hoặc máy chủ bị xâm nhập, toàn bộ nội dung thư điện tử nhạy cảm của doanh nghiệp sẽ bị lộ.
2. **Thiếu cơ chế xác thực nguồn gốc mạnh (Weak Authentication):** Kẻ tấn công dễ dàng thực hiện tấn công giả mạo (Spoofing) bằng cách thay đổi trường `From` trong tiêu đề email để thực hiện các chiến dịch lừa đảo (Phishing), chiếm đoạt tài sản hoặc thông tin mật của doanh nghiệp.
3. **Quản lý khóa công khai phức tạp:** Việc chia sẻ chứng chỉ/khóa công khai theo cách thủ công giữa các người dùng thường không thực tế và dễ bị tấn công giả mạo khóa (Key Substitution).
4. **Mất mát khóa bí mật:** Nếu người dùng làm mất khóa riêng tư (Private Key) dùng để giải mã email, toàn bộ các email trong quá khứ được mã hóa gửi cho họ sẽ vĩnh viễn không thể khôi phục, dẫn đến gián đoạn hoạt động kinh doanh.

### 1.2. Giải pháp đề xuất: Hệ thống SecureMail
Dự án **SecureMail** được đề xuất nhằm xây dựng một hệ thống thư điện tử nội bộ toàn diện cho các tổ chức, doanh nghiệp có yêu cầu bảo mật cao. Hệ thống kết hợp ba trụ cột chính:
- **Mã hóa đầu cuối (End-to-End Encryption - E2EE) bằng S/MIME-lite:** Nội dung email được mã hóa ngay tại máy khách của người gửi và chỉ được giải mã tại máy khách của người nhận. Máy chủ email trung gian hoàn toàn không thể đọc được nội dung thư.
- **Xác thực phi tập trung chống phát lại bằng Kerberos-lite:** Người dùng đăng nhập nhận vé TGT (Ticket-Granting Ticket) từ Ticket Service, sau đó dùng TGT để đổi lấy Service Ticket gửi cho Mail Server. Toàn bộ quá trình xác thực không truyền mật khẩu qua mạng, đồng thời sử dụng Authenticator để chống lại tấn công phát lại (Replay Attack).
- **Bộ ba chống mạo danh tên miền (SPF, DKIM, DMARC):** Enforce chính sách chống giả mạo tại SMTP server, đảm bảo email gửi đi từ đúng IP được phép và đúng chữ ký số của tên miền gửi.

---

## 2. MỤC TIÊU DỰ ÁN (PROJECT GOALS)

Hệ thống SecureMail hướng tới đạt được các mục tiêu an toàn thông tin cốt lõi sau:
- **Tính bí mật (Confidentiality):** Đảm bảo nội dung email chỉ người nhận hợp pháp mới có thể đọc thông qua việc kết hợp mã hóa đối xứng (AES-128-CBC) và bất đối xứng (RSA-OAEP-2048).
- **Tính toàn vẹn (Integrity):** Phát hiện mọi hành vi chỉnh sửa nội dung thư trên đường truyền bằng chữ ký số RSA-PSS và DKIM.
- **Tính xác thực (Authentication):** Xác minh chính xác danh tính người gửi (nhờ Kerberos-lite và chứng chỉ X.509v3) và máy chủ gửi thư (nhờ SPF và DKIM).
- **Chống chối bỏ (Non-repudiation):** Người gửi sau khi đã ký số vào email bằng khóa riêng tư của mình (không nằm trong diện ký quỹ khóa) thì không thể chối bỏ việc đã gửi bức thư đó.
- **Tính sẵn sàng của khóa (Key Availability & Escrow):** Hỗ trợ cơ chế ký quỹ khóa đối với khóa giải mã của người dùng bằng thuật toán Shamir's Secret Sharing (2-of-3), cho phép ban quản trị khôi phục lại dữ liệu khi nhân viên mất khóa hoặc nghỉ việc đột xuất mà vẫn đảm bảo tính chống chối bỏ.

---

## 3. KIẾN TRÚC HỆ THỐNG VÀ CÁC DỊCH VỤ CỐT LÕI (SYSTEM ARCHITECTURE)

Hệ thống được thiết kế theo kiến trúc Microservices phân tán, giao tiếp qua giao thức TCP Socket với cấu trúc gói tin tự định nghĩa dạng **JSON length-prefix framing** (mỗi frame gồm 4 byte độ dài Big-Endian đi kèm nội dung JSON được mã hóa UTF-8). 

```
┌────────────────────────────────────────────────────────────────────────────┐
│                        CA Admin Tool (PKI Root) :9000                      │
│   Root CA key pair → ký Cert → xuất CRL → OCSP-lite (ca_core)            │
└─────────────┬───────────────────────────────────────┬───────────────────────┘
              │ phát hành cert / push revocation      │ verify cert + CRL
              ▼                                       ▼
┌───────────────────────┐        ┌──────────────────────┐        ┌────────────────────────┐
│ Key Distribution      │        │ Ticket Service       │        │    Mail Server (MTA)    │
│ Server (KDS) :9001     │◄──────►│ (AS + TGS) :9002     │◄──────►│  SMTP-lite 2525          │
│  - Cert registry      │        │  Kerberos-lite       │        │  POP3-lite 1100          │
│  - Tra cứu cert/email │        │  - AS: cấp TGT       │        │  DKIM / SPF / DMARC     │
│  - CRL cache          │        │  - TGS: cấp ST       │        │  Message Store (SQLite) │
│  (key_store)       │        │  - Subsession key    │        │  (smtp_server)       │
└───────────┬───────────┘        │  (as_tgs_server)  │        └──────────────┬───────────┘
            │                    └──────────┬───────────┘                       ▲
            │                               │                                   │
            │  tra cứu pub-key              │ TGT / ST / Authenticator          │ SMTP / POP3
            ▼                               ▼                                   │
 ┌──────────────────┐                 ┌───────────────┐             ┌───────────┴────────┐
 │ Mail Client A    │────── SMTP ────►│  Mail Server  │◄──── POP3 ──│ Mail Client B      │
 │ (Alice) — CLI    │                 │               │             │ (Bob) — CLI        │
 └──────────────────┘                 └───────────────┘             └────────────────────┘
```

Hệ thống gồm 5 thành phần/dịch vụ chạy độc lập:

### 3.1. CA Service (Port 9000)
Đóng vai trò là Tổ chức phát hành chứng chỉ gốc (Root Certificate Authority) trong hạ tầng khóa công khai PKI nội bộ.
- **Chức năng:**
  - Khởi tạo cặp khóa Root CA và chứng chỉ tự ký (Self-signed Root Certificate).
  - Tiếp nhận và ký các yêu cầu ký chứng chỉ X.509v3 CSR từ phía Client.
  - Quản lý danh sách thu hồi chứng chỉ (CRL) và cung cấp dịch vụ OCSP-lite phản hồi trạng thái chứng chỉ tức thời.
  - Triển khai cơ chế ký quỹ khóa (Key Escrow) phân tán thông qua thuật toán Shamir.
- **CSDL sử dụng:** SQLite `data/ca/ca.db` để lưu trữ thông tin các chứng chỉ đã phát hành (`issued`) và nhật ký kiểm toán (`audit_log`).

### 3.2. Key Distribution Server - KDS (Port 9001)
Đóng vai trò là thư mục khóa công khai hoạt động trực tuyến để Client dễ dàng tra cứu khóa của nhau.
- **Chức năng:**
  - Lưu trữ chứng chỉ của tất cả người dùng trong hệ thống.
  - Hỗ trợ API tra cứu chứng chỉ đơn lẻ hoặc tra cứu hàng loạt (Bulk lookup) cho Mailing List.
  - Đồng bộ danh sách CRL từ CA và lưu trữ cache cục bộ để Client truy vấn.
- **CSDL sử dụng:** SQLite `data/kds/kds.db` (`certs`, `crl_cache`).

### 3.3. Ticket Service - KDC (Port 9002)
Đóng vai trò là Trung tâm phân phối khóa Kerberos (Key Distribution Center), thực hiện xác thực và phân phối vé.
- **Chức năng:**
  - **AS (Authentication Service):** Xác thực người dùng thông qua mã khóa dài hạn $Kc$ (dẫn xuất từ mật khẩu). Trả về vé TGT (Ticket-Granting Ticket) được mã hóa bằng khóa bí mật của TGS ($K_{tgs}$).
  - **TGS (Ticket-Granting Service):** Tiếp nhận TGT và Authenticator từ người dùng, giải mã xác thực và cấp Vé dịch vụ (Service Ticket - $ST$) cho Mail Server kèm theo khóa phiên dịch vụ $K_{c,v}$.
  - Hỗ trợ lưu trữ Replay Cache trên bộ nhớ RAM để phát hiện và ngăn chặn các cuộc tấn công phát lại trong cửa sổ thời gian 5 phút.
- **CSDL sử dụng:** SQLite `data/ticket/ticket.db` (`principals`, `service_keys`, `revoked_tgts`).

### 3.4. Mail Server - MTA (Port 2525 cho SMTP, Port 1100 cho POP3)
Nhận diện và phân phối thư điện tử trong hệ thống, thực thi các chính sách bảo mật tầng mạng.
- **Chức năng:**
  - Hỗ trợ giao thức STARTTLS-lite để thiết lập kênh truyền bảo mật giữa Client và Server trước khi truyền thông tin nhạy cảm.
  - Xác thực người dùng bằng cách mở Service Ticket bằng khóa dịch vụ $K_v$ nhận từ Ticket Service.
  - Phân quyền người dùng dựa trên vai trò (Role-Based Access Control - RBAC) lưu trong ticket (các vai trò: `user`, `admin`, `mailing_list_manager`).
  - Kiểm tra các bản ghi SPF, DKIM-lite và DMARC-lite để quyết định chấp nhận, cách ly (quarantine) hay từ chối (reject) email giả mạo.
- **CSDL sử dụng:** SQLite `data/mail/mailstore.db` (`mailbox`, `server_log`).

### 3.5. Mail Client CLI
Giao diện dòng lệnh giúp người dùng tương tác trực quan với hệ thống.
- **Chức năng:**
  - Đăng ký tài khoản: Tự tạo cặp khóa RSA-2048, gửi CSR tới CA, nhận chứng chỉ và đẩy lên KDS, đồng thời đăng ký principal mật khẩu tại Ticket Service.
  - Đăng nhập: Gửi yêu cầu AS-REQ tới Ticket Service, giải mã AS-REP để lấy TGT.
  - Gửi thư bảo mật: Lấy chứng chỉ người nhận từ KDS, xác minh chuỗi chứng chỉ X.509 và CRL, tạo vỏ bọc S/MIME (ký và mã hóa), sau đó gửi qua SMTP có STARTTLS và Kerberos AUTH.
  - Lấy thư: Kết nối POP3, xác thực Kerberos, tải envelope S/MIME, giải mã bằng khóa riêng tư và xác minh chữ ký người gửi.

---

## 4. CHI TIẾT CƠ CHẾ BẢO MẬT & GIẢI THÍCH THUẬT NGỮ (DETAILED CRYPTOGRAPHY)

Mã nguồn SecureMail được xây dựng dựa trên các tiêu chuẩn mật mã học hiện đại nhằm thay thế các giải pháp cũ đã lỗi thời. Dưới đây là phân tích chi tiết:

### 4.1. Mã hóa bất đối xứng & Chữ ký số (RSA-2048)
Hệ thống sử dụng thuật toán RSA với độ dài khóa **2048-bit** (Modulus $N$) cho tất cả các tác vụ bất đối xứng.
- **RSA-OAEP (Mã hóa khóa phiên S/MIME & STARTTLS):**
  - *Giải thích thuật ngữ:* **OAEP (Optimal Asymmetric Encryption Padding)** là cơ chế chèn thêm dữ liệu ngẫu nhiên vào bản rõ trước khi mã hóa RSA. Nó sử dụng cấu trúc mạng Feistel kết hợp với các hàm sinh mặt nạ (MGF1) để đảm bảo tính an toàn chống lại các cuộc tấn công chọn bản mã (IND-CCA2).
  - *Lý do chọn:* Khác với Padding PKCS#1 v1.5 cũ dễ bị tấn công Padding Oracle (như Bleichenbacher Attack) cho phép kẻ tấn công giải mã mà không cần khóa riêng tư, OAEP đảm bảo an toàn tuyệt đối trước lớp tấn công này.
  - *Tham số:* Hàm băm chính là `SHA-256`, hàm sinh mặt nạ MGF1 cũng sử dụng `SHA-256`, nhãn (label) để trống.
- **RSA-PSS (Chữ ký số cho S/MIME, DKIM & CA):**
  - *Giải thích thuật ngữ:* **PSS (Probabilistic Signature Scheme)** là một cơ chế tạo chữ ký số mang tính ngẫu nhiên. Khi ký cùng một thông điệp nhiều lần, thuật toán sẽ sinh ra các chữ ký khác nhau nhờ việc đưa thêm salt ngẫu nhiên vào.
  - *Lý do chọn:* PSS có chứng minh toán học chặt chẽ về độ an toàn hơn hẳn PKCS#1 v1.5 truyền thống. Nó loại bỏ hoàn toàn các điểm yếu tiềm tàng liên quan đến tính dễ uốn (malleability) của chữ ký số.
  - *Tham số:* Hàm băm `SHA-256`, độ dài salt thiết lập bằng mức tối đa (`asym_padding.PSS.MAX_LENGTH`).

### 4.2. Mã hóa đối xứng & Xác thực (AES)
Hệ thống kết hợp cả hai chế độ mã hóa CBC và GCM tùy theo mục đích sử dụng:
- **AES-128-CBC (Mã hóa thân thư S/MIME):**
  - *Giải thích thuật ngữ:* **AES (Advanced Encryption Standard)** là tiêu chuẩn mã hóa đối xứng khối của NIST. Chế độ **CBC (Cipher Block Chaining)** thực hiện XOR khối bản rõ hiện tại với khối bản mã trước đó trước khi đưa vào bộ mã hóa.
  - *Ứng dụng:* Dùng để mã hóa gói tin JSON chứa nội dung thư, chữ ký và chứng chỉ người gửi bằng một khóa đối xứng dùng một lần gọi là **CEK (Content Encryption Key)** dài 128-bit. Việc sử dụng AES-128 giúp tối ưu hóa hiệu năng mã hóa khối lượng lớn thông tin.
  - *Padding:* Sử dụng **PKCS#7 Padding** để bù đắp kích thước dữ liệu bản rõ đạt bội số của block size (16 bytes). Vector khởi tạo (IV) dài 16 bytes được sinh ngẫu nhiên mã hóa mạnh qua `os.urandom(16)`.
**AES-256-GCM (Bảo vệ Ticket, STARTTLS và Authenticator):**
  - *Giải thích thuật ngữ:* **GCM (Galois/Counter Mode)** là chế độ mã hóa AEAD (Authenticated Encryption with Associated Data). Nó không chỉ mã hóa bảo mật thông tin (Confidentiality) mà còn tính toán một mã xác thực thông điệp (Authentication Tag - Tag) dài 16 bytes để đảm bảo tính toàn vẹn (Integrity) và xác thực nguồn gốc dữ liệu.
  - *Ứng dụng:* Được sử dụng cho toàn bộ cơ chế bảo mật của Kerberos-lite (AS-REP, TGS-REP, TGT, Service Ticket, Authenticator) và TLS-lite.
  - *Dữ liệu liên kết (AAD - Associated Additional Data):* Là dữ liệu không cần mã hóa nhưng cần bảo vệ tính toàn vẹn (ví dụ: chuỗi định danh phiên `b"ticket-v1"`, `b"mutual-v1"` hoặc số thứ tự gói tin `tls-lite|send|{seq}`). Nếu kẻ tấn công thay đổi AAD hoặc bản mã, quá trình giải mã sẽ báo lỗi ngay lập tức. Điều này triệt tiêu hoàn toàn rủi ro bị tấn công Padding Oracle.
  - *Nonce:* Sử dụng Nonce ngẫu nhiên dài 12 bytes cho mỗi lần mã hóa, đảm bảo tính duy nhất và không bao giờ lặp lại trên cùng một khóa.

### 4.3. Băm mật khẩu và Dẫn xuất khóa (PBKDF2 & HKDF)
- **PBKDF2-HMAC-SHA256 (Bảo mật mật khẩu người dùng):**
  - *Giải thích thuật ngữ:* **PBKDF2 (Password-Based Key Derivation Function 2)** là hàm dẫn xuất khóa dựa trên mật khẩu. Nó thực hiện băm lặp đi lặp lại mật khẩu cùng với salt (dữ liệu ngẫu nhiên) nhiều lần nhằm kéo dài thời gian tính toán của CPU/GPU.
  - *Ứng dụng:* Khi người dùng đăng ký hoặc đăng nhập, mật khẩu của họ được đưa qua PBKDF2 với **200,000 vòng lặp** và Salt ngẫu nhiên 16 bytes để tạo ra khóa dài hạn $Kc$ (32 bytes). Khóa $Kc$ này được dùng làm khóa dùng chung giữa Client và Ticket Service để mã hóa gói tin AS-REP.
  - *Lý do chọn:* Số vòng lặp lớn giúp hệ thống chống lại hiệu quả các cuộc tấn công Brute-force hoặc Dictionary offline bằng máy chuyên dụng.
- **HKDF-SHA256 (Dẫn xuất khóa phân cấp):**
  - *Giải thích thuật ngữ:* **HKDF (HMAC-based Extract-and-Expand Key Derivation Function)** là hàm dẫn xuất khóa sử dụng cơ chế HMAC. Nó gồm 2 pha: Extract (trích xuất entropy từ khóa thô thành khóa gốc phân phối đều) và Expand (mở rộng khóa gốc thành nhiều khóa con độc lập dựa trên chuỗi bối cảnh `info`).
  - *Ứng dụng:* 
    1. **Khóa phụ phiên (Subsession Key - B7):** Khi Client có khóa phiên dịch vụ $K_{c,v}$ để làm việc với Mail Server, thay vì dùng trực tiếp $K_{c,v}$ cho mọi email (nếu lộ $K_{c,v}$ sẽ lộ hết các mail), Client sẽ dùng HKDF để sinh ra các khóa phụ độc lập: $K_{sub} = \text{HKDF-SHA256}(K_{c,v}, \text{info}=\text{b"mail\#"} + \text{seq\_i})$. Lộ khóa con này chỉ ảnh hưởng đến đúng bức thư đó.
    2. **Khóa phiên STARTTLS-lite:** Handshake TLS sinh ra Pre-master secret, sau đó cả Client và Server cùng dùng HKDF với context là random sinh từ hai phía để sinh ra session key mã hóa kênh truyền đối xứng.

### 4.4. Ký quỹ và khôi phục khóa phân tán (Shamir's Secret Sharing)
- *Giải thích thuật ngữ:* **Shamir's Secret Sharing (SSS)** là một thuật toán chia sẻ bí mật. Một bí mật $S$ được chia thành $N$ phần (shares) sao cho chỉ cần có tối thiểu $K$ phần ($K \le N$, gọi là ngưỡng - threshold) là có thể khôi phục lại hoàn toàn bí mật ban đầu bằng phương pháp nội suy đa thức Lagrange. Nếu số lượng mảnh ít hơn $K$, kẻ tấn công không thu được bất kỳ thông tin nào về bí mật gốc (đạt độ an toàn hoàn hảo - Information-theoretic security).
- *Ứng dụng trong dự án:* Triển khai cơ chế ký quỹ khóa (Key Escrow - A9) cho khóa riêng tư dùng để giải mã (Decryption Private Key) của người dùng. Hệ thống chia khóa này thành 3 mảnh ($N=3$), lưu trữ riêng biệt tại 3 vị trí an toàn trên máy chủ CA. Khi cần thiết (ví dụ nhân viên quên mật khẩu hoặc khẩn cấp pháp lý), quản trị viên cần ít nhất 2 mảnh ($K=2$) để khôi phục lại khóa.
- *Thiết kế an toàn:* Hệ thống chỉ ký quỹ khóa mã hóa/giải mã (Encryption Key), **tuyệt đối không ký quỹ khóa dùng để ký số (Signing Key)**. Điều này đảm bảo tính chống chối bỏ (Non-repudiation) của người dùng vì CA không bao giờ sở hữu khóa ký của họ.

---

## 5. LUỒNG DỮ LIỆU CHÍNH TRONG HỆ THỐNG (CORE DATA FLOWS)

Dưới đây là chi tiết kỹ thuật các luồng nghiệp vụ quan trọng được triển khai trong mã nguồn thực tế:

### 5.1. Luồng đăng ký tài khoản (Register)
Luồng này thiết lập danh tính người dùng trên cả hạ tầng PKI (CA/KDS) và hạ tầng Kerberos (Ticket Service).

```
  Client (client_core)      CA Service (:9000)          KDS (:9001)         Ticket Service (:9002)
     │                                │                       │                        │
     ├─ 1. Sinh RSA-2048 keypair      │                       │                        │
     ├─ 2. Tạo X.509 CSR              │                       │                        │
     ├─ 3. Gửi ca.sign_csr ──────────►│                       │                        │
     │  (CSR Base64)                  ├─ 4. Ký cert X.509v3   │                        │
     │◄───────────────────────────────┤  (Lưu ca.db)          │                        │
     │   (Cert PEM)                   │                       │                        │
     │                                │                       │                        │
     ├─ 5. Đẩy cert lên KDS ──────────┼──────────────────────►│                        │
     │  (kds.put_cert)                │                       │  (Lưu kds.db)          │
     │                                │                       │                        │
     ├─ 6. Băm mật khẩu (PBKDF2)      │                       │                        │
     │  → Sinh Kc và Salt             │                       │                        │
     ├─ 7. Đăng ký principal ─────────┼───────────────────────┼───────────────────────►│
     │  (ts.register_principal)       │                       │                        │  (Lưu ticket.db)
```

1. **Client** gọi `client_core.register()`, sinh cặp khóa RSA-2048 nội bộ trong bộ nhớ RAM.
2. Tạo yêu cầu ký chứng chỉ **CSR** chứa tên người dùng, địa chỉ email và khóa công khai (Public Key).
3. Client gửi CSR dạng Base64 qua TCP tới **CA Service** (`ca.sign_csr`).
4. CA Service giải mã, kiểm tra chữ ký của CSR. Nếu hợp lệ, CA dùng khóa bí mật của Root CA để ký xác nhận, tạo chứng chỉ X.509v3 với các trường mở rộng (Validity, Subject Alt Name là email, Key Usage). CA lưu thông tin vào `ca.db` và trả về Cert PEM cho Client.
5. Client gửi chứng chỉ PEM này tới **KDS** (`kds.put_cert`) để công khai hóa cho toàn bộ hệ thống tra cứu.
6. Client gọi `password_hash(password)` dùng PBKDF2 sinh ra khóa dài hạn $Kc$ (32 bytes) và Salt (16 bytes).
7. Client gửi Salt và $Kc$ lên **Ticket Service** (`ts.register_principal`) để đăng ký danh tính xác thực. Khóa riêng tư RSA của người dùng được mã hóa bằng mật khẩu dưới định dạng PEM rồi lưu trữ tại máy Client cục bộ.

### 5.2. Luồng đăng nhập và cấp vé TGT (Kerberos AS Exchange)
Giúp người dùng đăng nhập hệ thống một cách an toàn mà không cần truyền mật khẩu qua đường truyền vật lý.

```
  Client (client_core)                            Ticket Service (AS :9002)
     │                                                           │
     ├─ 1. Gửi ts.as_req {id_c, id_tgs, ts1} ───────────────────►│
     │                                                           ├─ 2. Đọc Salt, Kc của id_c từ DB
     │                                                           ├─ 3. Sinh session key K_c_tgs (32B)
     │                                                           ├─ 4. Đóng gói TGT = Enc(K_tgs, Payload)
     │                                                           ├─ 5. Tạo AS-REP = Enc(Kc, {K_c_tgs, TGT})
     │◄──────────────────────────────────────────────────────────┤
     │   (AS-REP Base64 + Salt)                                  │
     │                                                           │
     ├─ 6. Dùng mật khẩu + Salt tái tạo Kc (PBKDF2)              │
     ├─ 7. Giải mã AS-REP bằng Kc                                │
     └─ 8. Lấy ra K_c_tgs và TGT trong RAM                       │
```

1. **Client** gọi `client_core.login()`, gửi gói tin yêu cầu xác thực (`ts.as_req`) chứa ID người dùng (`id_c`), ID của dịch vụ TGS (`id_tgs`), và nhãn thời gian khởi tạo (`ts1`).
2. **AS Server** nhận yêu cầu, truy vấn `principals` table để lấy Salt và khóa $Kc$ tương ứng với `id_c`.
3. AS sinh một khóa phiên dịch vụ tạm thời $K_{c,tgs}$ dài 32 bytes ngẫu nhiên.
4. AS đóng gói vé **TGT (Ticket-Granting Ticket)** chứa: $K_{c,tgs}$, ID người dùng, địa chỉ mạng, thời hạn vé (8 giờ), vai trò (role) của người dùng. Toàn bộ vé TGT được niêm phong (mã hóa) bằng khóa bí mật của TGS ($K_{tgs}$) sử dụng AES-256-GCM với AAD là `ticket-v1`. Client không thể đọc hay chỉnh sửa vé này.
5. AS đóng gói gói tin phản hồi **AS-REP** chứa: $K_{c,tgs}$, ID dịch vụ, nhãn thời gian, TGT. AS mã hóa toàn bộ AS-REP bằng khóa lâu dài $Kc$ của người dùng (AES-256-GCM, AAD `as-rep-v1`). Gói tin được gửi về Client kèm theo Salt.
6. Client nhận phản hồi, dùng mật khẩu người dùng nhập vào kết hợp Salt để chạy PBKDF2 sinh lại khóa $Kc$.
7. Client dùng $Kc$ giải mã gói tin AS-REP. Nếu giải mã thành công (tức mật khẩu nhập đúng), Client lấy ra khóa phiên $K_{c,tgs}$ và vé TGT để lưu trữ vào phiên làm việc cục bộ trong RAM.

### 5.3. Luồng yêu cầu Vé Dịch Vụ (Kerberos TGS Exchange)
Sử dụng vé TGT để xin vé truy cập vào dịch vụ cụ thể (Mail Server).

```
  Client (client_core)                            Ticket Service (TGS :9002)
     │                                                           │
     ├─ 1. Tạo Authenticator = Enc(K_c_tgs, Payload)             │
     ├─ 2. Gửi ts.tgs_req {id_v, TGT, Authenticator} ───────────►│
     │                                                           ├─ 3. Giải mã TGT bằng K_tgs → Lấy K_c_tgs
     │                                                           ├─ 4. Giải mã Authenticator bằng K_c_tgs
     │                                                           ├─ 5. Kiểm tra Replay Cache & Expired
     │                                                           ├─ 6. Sinh session key K_c_v (32B)
     │                                                           ├─ 7. Tạo Service Ticket (ST) = Enc(K_v, Payload)
     │                                                           ├─ 8. Tạo TGS-REP = Enc(K_c_tgs, {K_c_v, ST})
     │◄──────────────────────────────────────────────────────────┤
     │   (TGS-REP Base64)                                        │
     │                                                           │
     └─ 9. Giải mã TGS-REP bằng K_c_tgs → Lấy K_c_v và ST        │
```

1. Khi cần tương tác với Mail Server, Client tạo một **Authenticator** chứa định danh client và nhãn thời gian hiện tại (`ts3`), được mã hóa bằng khóa phiên $K_{c,tgs}$ thu được từ bước đăng nhập.
2. Client gửi gói tin `ts.tgs_req` chứa ID dịch vụ Mail Server (`id_v`), vé TGT, và Authenticator lên **TGS Server**.
3. TGS Server dùng khóa bí mật của mình ($K_{tgs}$) giải mã vé TGT để lấy ra khóa phiên $K_{c,tgs}$ và thông tin người dùng.
4. TGS dùng khóa $K_{c,tgs}$ vừa lấy được để giải mã Authenticator.
5. TGS đối chiếu ID người dùng trong TGT và Authenticator xem có khớp nhau không. Đồng thời kiểm tra nhãn thời gian của Authenticator để đảm bảo không bị lệch quá 5 phút so với clock của server và tra cứu Replay Cache xem Authenticator này đã từng được gửi trước đó chưa.
6. Nếu hợp lệ, TGS sinh một khóa phiên làm việc mới $K_{c,v}$ (32 bytes) dùng cho Client và Mail Server.
7. TGS đóng gói vé dịch vụ **Service Ticket (ST / Ticket_v)** chứa: $K_{c,v}$, ID người dùng, địa chỉ mạng, vai trò, thời hạn vé (30 phút). Toàn bộ vé được mã hóa bằng khóa dịch vụ của Mail Server ($K_v$) sử dụng AES-256-GCM.
8. TGS đóng gói phản hồi **TGS-REP** chứa: $K_{c,v}$ và Service Ticket, mã hóa bằng $K_{c,tgs}$ gửi lại cho Client.
9. Client giải mã phản hồi bằng $K_{c,tgs}$, thu được vé dịch vụ và khóa phiên dịch vụ $K_{c,v}$.

### 5.4. Luồng gửi thư mã hóa S/MIME qua SMTP (STARTTLS + Kerberos Auth)
Đây là quy trình gửi thư phức tạp nhất, kết hợp bảo mật kênh truyền và bảo mật dữ liệu đầu cuối.

```
  Client (client_core)         Mail Server (SMTP :2525)               KDS (:9001)
     │                                │                                     │
     ├─ 1. Tải cert người nhận ───────┼────────────────────────────────────►│
     │◄───────────────────────────────┼─────────────────────────────────────┤
     │   (Cert X.509v3 Bob)           │                                     │
     │                                │                                     │
     ├─ 2. Xác minh Cert + CRL/OCSP   │                                     │
     ├─ 3. Tạo S/MIME Envelope        │                                     │
     │  - PSS Ký body bằng PrivKey_A  │                                     │
     │  - AES-128-CBC encrypt body    │                                     │
     │  - OAEP encrypt CEK bằng PubKey_B                                    │
     │                                │                                     │
     ├─ 4. Kết nối TCP & EHLO ───────►│                                     │
     │◄───────────────────────────────┤ (OK, STARTTLS support)              │
     │                                │                                     │
     ├─ 5. Lệnh STARTTLS ────────────►├─ 6. Trao đổi khóa Pre-master        │
     │◄───────────────────────────────┤    Dẫn xuất TLS Session Key (HKDF)  │
     │  [Từ đây, mọi frame truyền qua TCP được mã hóa AES-GCM qua TLS-lite] │
     │                                │                                     │
     ├─ 7. Lệnh AUTH (ST + Auth_c) ──►├─ 8. Giải mã ST bằng Kv → Lấy K_c_v  │
     │                                │    Giải mã Auth_c bằng K_c_v        │
     │                                │    Kiểm tra Replay Cache            │
     │◄───────────────────────────────┤─ 9. Mutual Auth: Reply Enc(K_c_v, ts+1)
     │                                │                                     │
     ├─ 10. Gửi MAIL FROM / RCPT TO ─►│                                     │
     ├─ 11. Gửi DATA (S/MIME Env) ───►├─ 12. Kiểm tra SPF/DKIM/DMARC        │
     │                                │─ 13. Ký DKIM-lite của MTA           │
     │                                │─ 14. Lưu mail store (SQLite)        │
```

1. **Chuẩn bị S/MIME:** Client A (Alice) muốn gửi thư cho Bob. Alice gọi KDS tra cứu chứng chỉ của Bob. Alice thực hiện verify chuỗi chứng chỉ của Bob về Root CA, kiểm tra xem có bị thu hồi trong CRL hay OCSP không.
2. Alice tạo S/MIME envelope:
   - Dùng khóa riêng tư của mình ký lên nội dung thư (Plaintext) bằng thuật toán RSA-PSS + SHA-256 thu được chữ ký `sig`.
   - Sinh khóa đối xứng ngẫu nhiên **CEK** (16 bytes). Đóng gói `{body, sig, cert_alice}` và mã hóa đối xứng bằng CEK (AES-128-CBC).
   - Dùng khóa công khai trích xuất từ chứng chỉ của Bob để mã hóa CEK bằng RSA-OAEP.
   - Đóng gói tất cả thành một cấu trúc JSON S/MIME envelope.
3. **Thiết lập STARTTLS-lite:** Client kết nối SMTP Server, gửi lệnh `EHLO`. Nhận phản hồi, gửi lệnh `STARTTLS`. Hai bên thực hiện handshake: Server gửi cert của mình, Client verify, Client sinh Pre-master secret mã hóa bằng khóa công khai của Server gửi đi. Cả hai dẫn xuất khóa phiên TLS qua HKDF-SHA256. Từ thời điểm này, mọi dữ liệu gửi/nhận trên Socket TCP được bọc mã hóa AES-256-GCM.
4. **Xác thực Kerberos (AUTH):** Client gửi yêu cầu `AUTH` chứa Service Ticket đã xin từ TGS và một Authenticator mới mã hóa bằng $K_{c,v}$. SMTP Server dùng khóa dịch vụ $K_v$ giải mã vé để lấy $K_{c,v}$ và phân quyền vai trò (role). Server giải mã Authenticator bằng $K_{c,v}$, kiểm tra replay. Server thực hiện xác thực hai chiều (Mutual Auth - A7) bằng cách mã hóa nhãn thời gian của client cộng thêm 1 gửi lại. Client giải mã kiểm tra đúng thì chính thức hoàn tất AUTH.
5. **Truyền nhận thư (DATA):** Client gửi thông tin người gửi, người nhận (`MAIL FROM`, `RCPT TO`) và nội dung S/MIME envelope (`DATA`).
6. **MTA xử lý chính sách:** SMTP Server kiểm tra SPF (xác minh IP client gửi có được cấu hình trong DB SPF của domain gửi không), kiểm tra chữ ký DKIM của client nếu có. Áp dụng chính sách DMARC của tên miền (none/quarantine/reject). Nếu không bị từ chối, MTA có thể ký thêm chữ ký DKIM của chính máy chủ gửi thư lên email trước khi lưu vào CSDL `mailstore.db`.

---

## 6. CÁC KỊCH BẢN KIỂM THỬ AN TOÀN (DEMO SCENARIOS & VERIFICATION)

Mã nguồn kiểm thử tự động của hệ thống tại [run_demo](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail/run_demo) triển khai 8 kịch bản (Scenario) thực tế nhằm kiểm thử độ an toàn của hệ thống:

| # | Kịch bản (Scenario) | Mục tiêu chứng minh | Logic kiểm thử trong mã nguồn |
|---|---|---|---|
| 1 | **Normal Encrypted & Signed Email** | Luồng hoạt động hoàn hảo (Happy Path) của hệ thống S/MIME. | Alice gửi thư cho Bob. Thư được ký số PSS và mã hóa CBC. Bob tải thư qua POP3, giải mã và xác minh chữ ký thành công. |
| 2 | **MITM / Public-key Substitution** | Chống tấn công giả mạo khóa công khai trên KDS. | Eve sinh cặp khóa giả mạo tự ký dưới danh nghĩa Bob và đẩy lên KDS. Khi Alice gửi thư, Alice lấy cert giả này về chạy `verify_chain`. Bộ kiểm tra phát hiện chứng chỉ không được ký bởi Root CA nên từ chối mã hóa gửi thư, chặn đứng MITM. |
| 3 | **Replay Attack** | Chống lại tấn công phát lại mã xác thực. | Kẻ tấn công đánh cắp Authenticator của Alice gửi lên SMTP. Khi gửi lần thứ hai, bộ kiểm tra Replay Cache phát hiện Nonce và Timestamp đã tồn tại trong RAM nên từ chối yêu cầu AUTH. |
| 4 | **Revoked Certificate** | Ngăn chặn sử dụng chứng chỉ đã bị thu hồi. | Chứng chỉ của Alice bị CA thu hồi (`ca.revoke`) và cập nhật CRL lên KDS. Khi Bob muốn gửi thư cho Alice, Client tải CRL về phát hiện chứng chỉ Alice nằm trong danh sách đen nên từ chối gửi thư. |
| 5 | **Spoofed Sender** | Ngăn chặn giả mạo địa chỉ người gửi (Spoofing). | Kẻ mạo danh gửi mail bằng SMTP từ một IP không được đăng ký trong bảng SPF hoặc identity người gửi không khớp với identity ghi trên Service Ticket của Kerberos. Hệ thống SMTP Server chạy DMARC engine phát hiện và đánh dấu hành động `quarantine` hoặc `reject`. |
| 6 | **Reusable Ticket** | Tính tiện dụng và tối ưu hiệu năng của Kerberos Ticket. | Alice đăng nhập 1 lần lấy Service Ticket (ST). Alice thực hiện gửi 5 email liên tiếp bằng cách tái sử dụng ST đó nhưng tạo **Authenticator mới** cho mỗi lần gửi. Hệ thống SMTP chấp nhận cả 5 lần mà Alice không cần phải gõ lại mật khẩu. |
| 7 | **Key Recovery (Shamir 2-of-3)** | Khôi phục khóa mật mã khi gặp sự cố. | CA khôi phục lại khóa riêng tư giải mã của Bob bằng cách ghép các mảnh file lưu trữ `share1.bin`, `share2.bin`, `share3.bin`. Hệ thống chứng minh chỉ cần tối thiểu 2 trong 3 mảnh là khôi phục chính xác 100% khóa gốc. |
| 8 | **HKDF Subsession Key** | Tính bảo mật phân cấp khóa cho từng email. | Sinh khóa con cho từng email dựa trên khóa phiên chính $K_{c,v}$ và số thứ tự email. Kiểm thử chứng minh các khóa con của các email khác nhau là hoàn toàn độc lập và không thể suy ngược ra khóa chính. |

---

## 7. KẾ HOẠCH TRIỂN KHAI & PHÂN CÔNG (IMPLEMENTATION PLAN)

Dự án được đề xuất triển khai trong khoảng thời gian **6 tuần** với sự tham gia của nhóm phát triển gồm 4 thành viên (Thành viên 1 đến Thành viên 4):

```mermaid
gantt
    title Kế hoạch triển khai dự án SecureMail (6 tuần)
    dateFormat  W
    axisFormat W%V
    
    section Tuần 1: Nền tảng
    Thiết lập môi trường & socket TCP :active, w1, 01, 1w
    Xây dựng SMTP/POP3 socket thô    : w1, 02, 1w
    Thiết lập SQLite mailstore       : w1, 03, 1w
    
    section Tuần 2: PKI & KDS
    Xây dựng CA Service (Root CA, CSR) : w2, 04, 1w
    Xây dựng KDS & CRL Engine          : w2, 05, 1w
    
    section Tuần 3: S/MIME & Crypto
    Cài đặt RSA-PSS/OAEP & AES-CBC     : w3, 06, 1w
    Xây dựng cấu trúc S/MIME JSON      : w3, 07, 1w
    
    section Tuần 4: Kerberos & TLS
    Thiết lập Ticket Service (AS/TGS)  : w4, 08, 1w
    Tích hợp Authenticator, Replay Cache: w4, 09, 1w
    STARTTLS-lite & HKDF               : w4, 10, 1w
    
    section Tuần 5: Bảo vệ & Mở rộng
    SPF-lite & DMARC-lite              : w5, 11, 1w
    Ký quỹ khóa Shamir (Key Escrow)   : w5, 12, 1w
    DKIM-lite Engine                   : w5, 13, 1w
    
    section Tuần 6: Tích hợp & Nghiệm thu
    Kiểm thử tích hợp 8 kịch bản       : w6, 14, 1w
    Viết tài liệu báo cáo, slide       : w6, 15, 1w
```

### Bảng phân công chi tiết công việc:

| Tuần | Nội dung công việc | Phân công thực hiện | Đầu ra (Deliverable) |
|---|---|---|---|
| **Tuần 1** | - Khởi tạo cấu trúc dự án Python và cài đặt thư viện.<br>- Viết khung kết nối TCP socket đa luồng (`threading`).<br>- Thiết kế SQLite schema cho lưu trữ email. | **Thành viên 1 + 2** | - Khung mã nguồn SMTP/POP3 socket thô.<br>- CSDL SQLite khởi tạo ban đầu. |
| **Tuần 2** | - Viết lõi CA: sinh Root Key, ký CSR, quản lý danh sách thu hồi cert.<br>- Xây dựng KDS Server quản lý lưu trữ chứng chỉ người dùng và CRL cache. | **Thành viên 3 + 4** | - CA Server và KDS Server chạy độc lập.<br>- Khả năng cấp phát cert thông qua CLI. |
| **Tuần 3** | - Triển khai các thư viện mật mã RSA-OAEP, RSA-PSS, AES-128-CBC.<br>- Xây dựng bộ đóng gói/giải mã S/MIME JSON envelope (Sign-then-Encrypt). | **Thành viên 1 + 3** | - Module [rsa_handler] và [smime_handler] hoàn thiện. |
| **Tuần 4** | - Xây dựng lõi Ticket Service (AS/TGS) cấp vé TGT, ST và sinh Session Key.<br>- Tích hợp Authenticator và Replay Cache chống tấn công phát lại.<br>- Viết module TLS-lite mã hóa kênh truyền STARTTLS. | **Thành viên 2 + 4** | - Ticket Service Server hoạt động.<br>- Giao thức xác thực Kerberos hoạt động trên SMTP/POP3. |
| **Tuần 5** | - Viết chính sách chống mạo danh SPF-lite, DMARC-lite và DKIM-lite.<br>- Triển khai thuật toán Shamir Secret Sharing phục vụ ký quỹ khóa giải mã. | **Thành viên 1 + 2** | - Bộ lọc SPF/DKIM/DMARC tại SMTP.<br>- Tính năng chia tách và phục hồi khóa private key. |
| **Tuần 6** | - Viết mã kịch bản chạy thử nghiệm tích hợp E2E.<br>- Sửa lỗi hệ thống, tối ưu hóa hiệu năng.<br>- Hoàn thiện tài liệu dự án, Slide thuyết trình và quay Video demo. | **Cả nhóm** | - File [run_demo] chạy thành công 8 kịch bản.<br>- Báo cáo kỹ thuật chi tiết. |

---

## 8. ĐÁNH GIÁ VÀ HƯỚNG PHÁT TRIỂN (EVALUATION & FUTURE WORK)

### 8.1. Đánh giá ưu điểm
- **An toàn tuyệt đối ở tầng ứng dụng (E2EE):** Nội dung email được mã hóa từ client gửi và chỉ giải mã ở client nhận. Kể cả khi toàn bộ cơ sở dữ liệu Mail Server bị lộ, kẻ tấn công cũng chỉ thu được các bản mã AES-CBC không thể đọc được.
- **Không truyền mật khẩu trực tiếp:** Sử dụng cơ chế PBKDF2 sinh khóa Kc giúp Client đăng nhập Kerberos mà không cần gửi plaintext password qua mạng, tránh rủi ro bị nghe lén (Sniffing).
- **Chống replay triệt để:** Việc áp dụng kết hợp cơ chế Replay Cache (lưu trữ nonce và timestamp trong cửa sổ 5 phút) ngăn chặn kẻ tấn công chụp lại gói tin xác thực mạng.
- **Ngăn ngừa mạo danh doanh nghiệp hiệu quả:** Nhờ sự kết hợp chặt chẽ giữa vé dịch vụ Kerberos và chính sách lọc thư SPF/DKIM/DMARC tại SMTP server.

### 8.2. Nhược điểm và Giới hạn
- **Đồng bộ thời gian (Clock Synchronization):** Kerberos phụ thuộc nhiều vào thời gian để kiểm tra tính hợp lệ của vé và authenticator. 
- **Quản lý khóa CA thủ công:** Khóa riêng tư của Root CA hiện đang được lưu trong file PEM mã hóa bằng passphrase cứng trên đĩa.


