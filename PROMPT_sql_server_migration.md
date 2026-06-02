# AI Prompt: Migrate SecureMail Database from SQLite / Files to Microsoft SQL Server (MSSQL)

## Context & Objective

You are refactoring the database layer of the `Secure_Mail` project — an academic demonstration of applied cryptography concepts (S/MIME, Kerberos-lite, SPF, DKIM, DMARC, and Shamir Key Escrow). 

Currently, the services store data across multiple local SQLite databases and flat binary files:
- **CA Service**: `data/ca/ca.db` + Shamir shares in `data/ca/escrow/*.bin`
- **KDS Service**: `data/kds/kds.db`
- **Ticket Service**: `data/ticket/ticket.db`
- **Policy Service**: `data/policy/policy.db`
- **Mail Server**: `data/mail/mailstore.db`

Your goal is to centralize and migrate all database and file storage operations to a **Microsoft SQL Server (MSSQL)** database named `SecureMail`, using the relational schema defined in [securemail_sqlserver.sql](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail_sqlserver.sql). 

Connection settings must be loaded dynamically from a root `.env` file:
```ini
DB_HOST=localhost
DB_PORT=1433
DB_NAME=SecureMail
DB_USER=sa
DB_PASSWORD=123
DB_TYPE=mssql
```

---

## SQL Server Adaptation Rules

To successfully migrate from SQLite to SQL Server in Python, adhere to the following rules:

1. **Use Schema Prefixes**: SQL Server tables are organized under custom schemas. You must update all table names in SQL statements to include their schema prefix:
   - CA Service: `ca.issued`, `ca.escrow_shares`, `ca.audit_log`
   - KDS: `kds.certs`, `kds.crl_cache`, `kds.audit_log`
   - Ticket Service: `ticket.principals`, `ticket.service_keys`, `ticket.revoked_tgts`, `ticket.audit_log`
   - Policy Service: `policy.spf`, `policy.dmarc`
   - Mail Server: `mail.mailbox`, `mail.server_log`

2. **Handle SQL Server SQL Dialect Changes**:
   - **No `ON CONFLICT` / `INSERT OR REPLACE`**: SQL Server does not support SQLite's `ON CONFLICT DO UPDATE` or `INSERT OR REPLACE`. Use `MERGE` or `IF EXISTS ... UPDATE ... ELSE INSERT` instead.
   - **No `INSERT OR IGNORE`**: Use `IF NOT EXISTS (SELECT 1 ...) INSERT ...` instead.
   - **Identity Retrieval**: SQLite's `cursor.lastrowid` is not supported in SQL Server. Use `OUTPUT INSERTED.id` in the `INSERT` query or fetch `SELECT SCOPE_IDENTITY()` to retrieve auto-generated primary keys.
   - **Data Types**: Use bytes for `VARBINARY(MAX)` (corresponds to SQLite `BLOB`), `datetime` objects for `DATETIMEOFFSET` (corresponds to SQLite `TEXT` ISO date strings), and booleans for `BIT` columns.

3. **Driver Choice & Placeholder Formatting**:
   - In Python, we will support both `pymssql` and `pyodbc`.
   - **`pymssql`** uses `%s` as the parameter placeholder (e.g. `SELECT * FROM table WHERE col = %s`).
   - **`pyodbc`** uses `?` as the parameter placeholder (e.g. `SELECT * FROM table WHERE col = ?`).
   - Implement parameter selection dynamically based on the configured database driver, or standardize on **`pymssql`** using `%s` placeholders (since it does not require installing native ODBC drivers).

---

## Refactoring Tasks

---

### Task 1: Add Dependencies & Create Environment Configuration

1. **Update Dependencies**:
   - Add `pymssql` and `python-dotenv` to [requirements.txt](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail/requirements.txt).
2. **Create Template**:
   - Create a `.env` file at the project root matching the template:
     ```ini
     DB_HOST=localhost
     DB_PORT=1433
     DB_NAME=SecureMail
     DB_USER=sa
     DB_PASSWORD=123
     DB_TYPE=mssql
     ```

---

### Task 2: Create Database Connection Utility

**New File:** [db_conn.py](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail/db_conn.py)

**Implementation Details:**
- Load environment variables from `.env` using `python-dotenv`.
- Implement a helper function `get_conn()` that returns an active connection to the SQL Server database.
- Handle connection pooling or reuse if needed, or simply return a fresh connection client.
- Provide a helper `get_placeholder()` or abstract query execution so that other services do not have to hardcode driver-specific placeholders (`%s` for `pymssql` or `?` for `pyodbc`).
- Ensure auto-commit is configured properly or that transactions are committed automatically for write queries.

---

### Task 3: Refactor Certificate Authority (CA) Database Layer

**Files:**
- [ca_core.py](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail/ca_service/ca_core.py)
- [ca_server.py](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail/ca_service/ca_server.py)
- [key_escrow.py](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail/ca_service/key_escrow.py)

**Refactoring Instructions:**
1. Replace `sqlite3.connect(CA_DB)` with the database connection utility.
2. Update table references to prefix them with `ca.` (e.g. `ca.issued`, `ca.audit_log`).
3. Convert ISO timestamps from SQLite (`dt.datetime.now().isoformat()`) to Python `datetime` objects so they map correctly to `DATETIMEOFFSET` in SQL Server.
4. **Key Escrow Migration (`key_escrow.py`)**:
   - Currently, Shamir shares are saved as files: `data/ca/escrow/{email}.share{idx}.bin`.
   - Modify `escrow_key` and `recover_key` to write/read shares from the database table `ca.escrow_shares (email, share_index, share_data)` instead of saving local binary files.
   - For `escrow_key(email, key)`: Insert 3 shares into `ca.escrow_shares` using parameterized queries.
   - For `recover_key(email, indices)`: Retrieve the selected shares from `ca.escrow_shares` and reconstruct the key.

---

### Task 4: Refactor Key Distribution Server (KDS) Database Layer

**File:** [key_store.py](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail/kds/key_store.py)

**Refactoring Instructions:**
1. Replace `sqlite3.connect(KDS_DB)` with the database connection utility.
2. Prefix all table references with `kds.` (e.g. `kds.certs`, `kds.crl_cache`, `kds.audit_log`).
3. Replace the SQLite UPSERT statements (`ON CONFLICT(email) DO UPDATE...`) with SQL Server compatible queries (e.g., using `MERGE` or checking `IF EXISTS` before writing):
   - For `put_cert(email, serial, cert_pem)`:
     ```sql
     MERGE INTO kds.certs AS target
     USING (SELECT %s AS email) AS source
     ON target.email = source.email
     WHEN MATCHED THEN
         UPDATE SET serial = %s, cert_pem = %s, registered_at = GETUTCDATE()
     WHEN NOT MATCHED THEN
         INSERT (email, serial, cert_pem, registered_at) VALUES (%s, %s, %s, GETUTCDATE());
     ```
   - For `put_crl(crl_pem)`: Use similar SQL Server `MERGE` logic targeting `kds.crl_cache` where `id = 1`.

---

### Task 5: Refactor Ticket Service (AS + TGS) Database Layer

**File:** [as_tgs_server.py](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail/ticket_service/as_tgs_server.py)

**Refactoring Instructions:**
1. Replace `sqlite3.connect(TS_DB)` with the database connection utility.
2. Prefix all table references with `ticket.` (e.g., `ticket.principals`, `ticket.service_keys`, `ticket.revoked_tgts`, `ticket.audit_log`).
3. Replace SQLite UPSERT statements:
   - For `register_principal(id_c, salt, kc, role)`: Use a `MERGE` query on `ticket.principals` instead of `ON CONFLICT(id_c) DO UPDATE`.
   - For `_get_or_create_service_key(id_v)`: Use a conditional query to check existence first, and insert if not found.

---

### Task 6: Refactor Policy Service Database Layer

**Files:**
- [spf_checker.py](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail/policy/spf_checker.py)
- [dmarc_engine.py](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail/policy/dmarc_engine.py)

**Refactoring Instructions:**
1. Replace `sqlite3.connect(POLICY_DB)` with the database connection utility.
2. Prefix all table references with `policy.` (e.g., `policy.spf`, `policy.dmarc`).
3. Replace SQLite-specific query components:
   - For `spf_checker.py`'s `add_spf(domain, ip)`: Replace `INSERT OR IGNORE` with an `IF NOT EXISTS` insert block.
   - For `dmarc_engine.py`'s `set_policy(domain, policy)`: Replace `ON CONFLICT(domain) DO UPDATE` with a SQL Server `MERGE` statement.

---

### Task 7: Refactor Mail Server (SMTP + POP3) Database Layer

**Files:**
- [smtp_server.py](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail/network/smtp_server.py)
- [pop3_server.py](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail/network/pop3_server.py)

**Refactoring Instructions:**
1. Replace `sqlite3.connect(MAIL_DB)` with the database connection utility.
2. Prefix all table references with `mail.` (e.g., `mail.mailbox`, `mail.server_log`).
3. Update POP3 query statements (such as `LIST`, `RETR`, `DELE`) to refer to `mail.mailbox`. Note that the `fetched` column in SQLite was configured as `INTEGER DEFAULT 0`, but in SQL Server it is `BIT NOT NULL DEFAULT 0`. Ensure query filters (`WHERE fetched=0`) remain compatible (SQL Server drivers handle `0`/`False` or `1`/`True` transparently).
4. **Retrieve Inserted Mail ID**:
   - In `smtp_server.py`'s `store_mail(...)` function: Replace SQLite's `cur.lastrowid` logic. Use `OUTPUT INSERTED.id` inside the `INSERT INTO mail.mailbox` statement:
     ```sql
     INSERT INTO mail.mailbox (recipient, sender, received_at, envelope, headers_json, dmarc_action, spf_result, dkim_result, fetched)
     OUTPUT INSERTED.id
     VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 0)
     ```
     Execute this statement and fetch the returned ID directly from the cursor result.

---

### Task 8: Refactor Logging & Demo Seeding Utilities

**Files:**
- [view_logs.py](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/view_logs.py)
- [main_ca.py](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail/main_ca.py)
- [run_demo.py](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail/run_demo.py)
- [interactive_demo.py](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail/interactive_demo.py)

**Refactoring Instructions:**
1. Remove direct imports of `sqlite3` from these files.
2. **Log Viewer (`view_logs.py`)**:
   - Modify the file to query the database schemas in SQL Server (`ca.audit_log`, `ticket.audit_log`, `kds.audit_log`, `mail.server_log`) using the central database connection helper rather than loading local `.db` files.
3. **Demo Scripts (`run_demo.py` & `interactive_demo.py`)**:
   - Inside `scenario_5_spoofed_sender()`, direct database edits are executed manually to manipulate SPF records. Update these direct SQLite calls (`sqlite3.connect`) to use the database connection helper and target `policy.spf` in SQL Server.
4. **CA CLI (`main_ca.py`)**:
   - Update the `list` command to use the SQL Server connection helper to list certificates from `ca.issued`.

---

## Verification & Testing Plan

1. **Database Setup**:
   - Start your local SQL Server instance.
   - Run the [securemail_sqlserver.sql](file:///e:/STUDY/MA_HOA_UNG_DUNG/Project/Secure_Mail/securemail_sqlserver.sql) migration script to set up the databases, schemas, tables, indices, and constraints.
2. **Run Services**:
   - Set up the environment variables in `.env` with valid connection credentials.
   - Boot up all system services (CA, KDS, Ticket Server, and Mail Server) using the script or background commands.
3. **Seeding & Demonstration**:
   - Execute the bootstrap phase to register services and demo users:
     ```bash
     python -m securemail.run_demo bootstrap
     ```
     Verify that entries are populated in `kds.certs`, `ticket.principals`, `policy.spf`, and escrow shares in `ca.escrow_shares`.
   - Run the verification scenarios:
     ```bash
     python -m securemail.run_demo all
     ```
     Verify that all 8 scenarios complete successfully and that all operations write directly to your SQL Server database.
