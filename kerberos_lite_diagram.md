# Biểu Đồ Mermaid cho Kerberos-Lite trong SecureMail

Tài liệu này chứa các biểu đồ Mermaid thể hiện cấu trúc và luồng hoạt động của giao thức **Kerberos-lite** được triển khai trong dự án SecureMail, bao gồm các dịch vụ **Authentication Service (AS)**, **Ticket-Granting Service (TGS)** và các giao tiếp với **Mail Server (SMTP/POP3)**.

---

## 1. Kiến Trúc Tổng Quan (Component Diagram)

Biểu đồ dưới đây thể hiện các thành phần tham gia vào luồng Kerberos-lite và mối quan hệ giữa chúng.

```mermaid
graph TB
    subgraph CLIENT["🖥️ Client (client_core.py)"]
        REG["register()"]
        LOGIN["login()"]
        GST["get_service_ticket()"]
        SEND["send_secure_email()"]
        FETCH["fetch_inbox()"]
    end

    subgraph TS["🎫 Ticket Service :9002 (as_tgs_server.py)"]
        direction TB
        AS["Authentication Service<br/>handle_as_req()"]
        TGS["Ticket-Granting Service<br/>handle_tgs_req()"]
        SK["Service Key Manager<br/>_get_or_create_service_key()"]
        RC["Replay Cache<br/>ReplayCache (in-memory)"]
        AUDIT["Audit Logger<br/>_audit()"]

        subgraph DB["🗄️ SQLite (ticket.db)"]
            P_TABLE["principals<br/>(id_c, salt, kc, role)"]
            SK_TABLE["service_keys<br/>(id_v, kv)"]
            REV_TABLE["revoked_tgts<br/>(tgt_hash, revoked_at)"]
            LOG_TABLE["audit_log<br/>(ts, event, details)"]
        end
    end

    subgraph CRYPTO["🔐 Crypto Layer (crypto/)"]
        AES["AES-256-GCM<br/>aes_handler.py"]
        PBKDF2["PBKDF2-HMAC-SHA256<br/>hmac_utils.password_hash()"]
    end

    subgraph TICKETS["🎟️ Ticket Structs (ticket.py)"]
        TGT["TGT = E(K_tgs,<br/>  session_key || IDc ||<br/>  ADc || id_srv || ts ||<br/>  lifetime || role)"]
        SVC["ServiceTicket = E(K_v,<br/>  session_key || IDc ||<br/>  ADc || id_srv || ts ||<br/>  lifetime || role)"]
    end

    subgraph AUTH_MOD["🔏 Authenticator (authenticator.py)"]
        BUILD["build(key, idc, ad_c)<br/>→ E(K_c,x, IDc||ADc||ts||nonce)"]
        OPEN["open_auth(key, blob)"]
        REPLAY["ReplayCache<br/>(IDc+nonce, window=300s)"]
    end

    subgraph SERVICES["📨 Mail Services"]
        SMTP["SMTP Server :2525"]
        POP3["POP3 Server :1100"]
    end

    LOGIN --> AS
    GST --> TGS
    REG --> P_TABLE

    AS --> P_TABLE
    AS --> SK
    AS --> AES
    AS --> PBKDF2
    AS --> AUDIT

    TGS --> SK_TABLE
    TGS --> RC
    TGS --> AES
    TGS --> AUDIT

    SK --> SK_TABLE

    SEND --> GST
    SEND --> SMTP
    FETCH --> GST
    FETCH --> POP3

    SMTP --> SK_TABLE
    POP3 --> SK_TABLE
```

---

## 2. Giao Thức Đăng Nhập & Lấy TGT (AS Exchange)

Luồng trao đổi giữa Client và Authentication Service (AS) để lấy **Ticket-Granting Ticket (TGT)**.

```mermaid
sequenceDiagram
    autonumber
    actor C as Client CLI
    participant TSC as ts_client.py
    participant AS as AS Server (:9002)
    participant DB as SQLite (ticket.db)
    participant TK as ticket.py (seal)

    C->>TSC: login(email, password)
    
    Note over TSC,AS: Gửi yêu cầu AS-REQ
    TSC->>AS: TCP {op: "ts.as_req", id_c: email, id_tgs: "tgs/securemail", ts1: timestamp}
    
    AS->>DB: Truy vấn thông tin người dùng (id_c)
    DB-->>AS: Trả về {salt, kc, role}
    
    Note over AS: Sinh Session Key tạm thời K_c_tgs (32 bytes)<br/>và tạo payload cho TGT
    
    AS->>DB: Lấy/Tạo khóa dịch vụ TGS (K_tgs)
    DB-->>AS: K_tgs
    
    AS->>TK: seal_ticket(K_tgs, TGT_payload)
    Note over TK: Mã hóa AES-256-GCM với AAD 'ticket-v1'
    TK-->>AS: TGT (Base64)
    
    Note over AS: Tạo AS-REP chứa K_c_tgs và TGT,<br/>Mã hóa bằng khóa lâu dài Kc của người dùng
    
    AS->>AS: Mã hóa AS-REP bằng Kc (AES-256-GCM, AAD 'as-rep-v1')
    AS->>DB: Ghi log sự kiện AS_REQ_OK
    AS-->>TSC: Trả về {ok: true, as_rep_b64, salt_b64}
    
    Note over TSC: Khôi phục khóa Kc từ password và salt (PBKDF2)<br/>Giải mã AS-REP bằng Kc
    TSC->>TSC: Giải mã AS-REP -> Lấy K_c_tgs và TGT
    TSC-->>C: Đăng nhập thành công, lưu K_c_tgs và TGT vào session
```

---

## 3. Giao Thức Yêu Cầu Vé Dịch Vụ (TGS Exchange)

Luồng trao đổi giữa Client và Ticket-Granting Service (TGS) để lấy **Service Ticket (Ticket_v)**.

```mermaid
sequenceDiagram
    autonumber
    actor C as Client CLI
    participant TSC as ts_client.py
    participant TGS as TGS Server (:9002)
    participant RC as Replay Cache
    participant DB as SQLite (ticket.db)
    participant TK as ticket.py (open/seal)

    C->>TSC: get_service_ticket(id_v = "mail/securemail")
    
    Note over TSC: Tạo Authenticator bằng K_c_tgs:<br/>E(K_c_tgs, [id_c, ad_c, ts, nonce]) với AAD 'authenticator-v1'
    
    TSC->>TGS: TCP {op: "ts.tgs_req", id_v, tgt, authenticator}
    
    TGS->>DB: Lấy khóa dịch vụ TGS (K_tgs)
    DB-->>TGS: K_tgs
    
    TGS->>TK: open_ticket(K_tgs, tgt)
    TK-->>TGS: Trả về TGT_payload (chứa K_c_tgs, id_c, role, ...)
    
    Note over TGS: Kiểm tra thời hạn TGT (Expired check)
    
    TGS->>TGS: Giải mã Authenticator bằng K_c_tgs
    
    Note over TGS: Kiểm tra id_c trong Authenticator khớp với TGT
    
    TGS->>RC: check_and_add(id_c + "@tgs", nonce, ts)
    Note over RC: Kiểm tra trùng lặp (Replay attack)<br/>và thời gian lệch (Clock skew < 5 phút)
    RC-->>TGS: Hợp lệ (True)
    
    Note over TGS: Sinh Service Session Key K_c_v (32 bytes)<br/>và tạo payload cho Service Ticket (Ticket_v)
    
    TGS->>DB: Lấy/Tạo khóa dịch vụ Mail Server (K_v)
    DB-->>TGS: K_v
    
    TGS->>TK: seal_ticket(K_v, Ticket_v_payload)
    TK-->>TGS: Ticket_v (Base64)
    
    Note over TGS: Tạo TGS-REP chứa K_c_v và Ticket_v,<br/>Mã hóa bằng K_c_tgs (AES-256-GCM, AAD 'tgs-rep-v1')
    
    TGS->>DB: Ghi log sự kiện TGS_REQ_OK
    TGS-->>TSC: Trả về {ok: true, tgs_rep_b64}
    
    TSC->>TSC: Giải mã TGS-REP bằng K_c_tgs -> Lấy K_c_v và Ticket_v
    TSC-->>C: Trả về {k_c_v, ticket_v}
```

---

## 4. Xác Thực Hai Chiều Với Mail Server (Service Exchange - Mutual Auth)

Luồng xác thực giữa Client và Mail Server sử dụng Service Ticket đã lấy từ TGS.

```mermaid
sequenceDiagram
    autonumber
    actor C as Client CLI
    participant CC as client_core.py
    participant MS as Mail Server (:2525/:1100)
    participant TS as Ticket Service (:9002)
    participant RC as Replay Cache (Server)

    C->>CC: Thực hiện gửi/nhận email
    CC->>CC: Lấy {k_c_v, ticket_v} của Mail Server
    
    Note over CC: Tạo Authenticator bằng K_c_v:<br/>E(K_c_v, [id_c, ad_c, ts, nonce]) với AAD 'authenticator-v1'
    
    CC->>MS: TCP {op: "AUTH", ticket_v, authenticator}
    
    MS->>TS: TCP {op: "ts.get_service_key", id_v: "mail/securemail"}
    TS-->>MS: Khóa dịch vụ K_v
    
    Note over MS: Giải mã và xác minh Ticket_v bằng K_v<br/>Lấy K_c_v, id_c, role từ Ticket_v
    Note over MS: Giải mã Authenticator bằng K_c_v<br/>Kiểm tra id_c khớp nhau
    
    MS->>RC: check_and_add(id_c + "@mail", nonce, ts)
    RC-->>MS: Hợp lệ (True)
    
    Note over MS: Tạo phản hồi xác thực hai chiều (Mutual Auth):<br/>Mã hóa ts_plus_1 = ts + 1 bằng K_c_v
    
    MS-->>CC: Trả về {ok: true, mutual_b64: E(K_c_v, ts+1), role}
    
    Note over CC: Giải mã mutual_b64 bằng K_c_v,<br/>Xác nhận ts_plus_1 == ts + 1
    
    Note over CC,MS: Xác thực thành công từ cả hai phía!<br/>Sử dụng K_c_v làm khóa phiên bảo vệ SMTP/POP3.
```

---

## 5. Dẫn Xuất Khóa Phiên Phân Cấp (Hierarchical Key - HKDF)

Để tăng cường bảo mật, hệ thống không sử dụng trực tiếp $K_{c,v}$ cho mọi email. Thay vào đó, một **Subsession Key** được dẫn xuất cho mỗi email riêng biệt:

```mermaid
graph TD
    K_CV["🔑 K_c,v (Mail Service Session Key - 32 bytes)"] --> HKDF["⚙️ HKDF-SHA256 Extract & Expand"]
    INFO["ℹ️ context info = 'mail#' + seq_i"] --> HKDF
    HKDF --> K_SUB["🔑 K_sub (Subsession Key cho email i)"]
    K_SUB --> AES["🔐 Mã hóa/Giải mã Email i"]
    
    style K_CV fill:#2E4057,color:#fff
    style K_SUB fill:#1A5276,color:#fff
    style K_SUB stroke:#333,stroke-width:2px
```

---

## 6. Sơ Đồ Phân Cấp Khóa (Key Hierarchy)

Tất cả các khóa được sử dụng trong Kerberos-lite và mối liên hệ giữa chúng.

```mermaid
graph TD
    PASS["🔑 Mật khẩu người dùng (Password)"] --> PBKDF2["⚙️ PBKDF2-HMAC-SHA256<br/>200,000 vòng lặp + Salt"]
    PBKDF2 --> KC["🔑 Long-term Key Kc<br/>(Lưu trong principals.kc)"]
    
    K_TGS["🔑 Service Key K_tgs<br/>(Lưu trong service_keys)"]
    K_V["🔑 Service Key K_v<br/>(Lưu trong service_keys)"]
    
    RAND_TGS["🎲 Sinh ngẫu nhiên (32 bytes)"] --> KC_TGS["🔑 Session Key K_c,tgs<br/>(Liên kết Client <-> TGS)"]
    RAND_V["🎲 Sinh ngẫu nhiên (32 bytes)"] --> KC_V["🔑 Session Key K_c,v<br/>(Liên kết Client <-> Mail Server)"]
    
    KC_TGS --> TGT_PAY["TGT Payload"]
    K_TGS --> TGT["🎟️ TGT = Enc(K_tgs, TGT_Payload)"]
    
    KC_V --> TICKET_V_PAY["Ticket_v Payload"]
    K_V --> TICKET_V["🎟️ Ticket_v = Enc(K_v, Ticket_v_Payload)"]
    
    KC --> AS_REP["📦 AS-REP = Enc(Kc, {K_c_tgs, TGT})"]
    KC_TGS --> TGS_REP["📦 TGS-REP = Enc(K_c_tgs, {K_c_v, Ticket_v})"]

    style KC fill:#8B4513,color:#fff
    style KC_TGS fill:#2E4057,color:#fff
    style KC_V fill:#1A5276,color:#fff
    style K_TGS fill:#1E8449,color:#fff
    style K_V fill:#1E8449,color:#fff
    style TGT fill:#7D3C98,color:#fff
    style TICKET_V fill:#7D3C98,color:#fff
```
