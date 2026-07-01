-- =========================================================================
-- SECUREMAIL - SQL SERVER DATABASE SCHEMA MIGRATION SCRIPT
-- This script creates the relational schema in SQL Server for all services.
-- It organizes tables using Schemas (ca, kds, ticket, policy, mail).
-- =========================================================================

USE master;
GO

-- Create database if not exists
IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = 'SecureMail')
BEGIN
    CREATE DATABASE SecureMail;
END
GO

USE SecureMail;
GO

-- =========================================================================
-- 0. SCHEMA DECLARATIONS
-- =========================================================================
IF NOT EXISTS (SELECT * FROM sys.schemas WHERE name = 'ca')
    EXEC('CREATE SCHEMA ca');
GO

IF NOT EXISTS (SELECT * FROM sys.schemas WHERE name = 'kds')
    EXEC('CREATE SCHEMA kds');
GO

IF NOT EXISTS (SELECT * FROM sys.schemas WHERE name = 'ticket')
    EXEC('CREATE SCHEMA ticket');
GO

IF NOT EXISTS (SELECT * FROM sys.schemas WHERE name = 'policy')
    EXEC('CREATE SCHEMA policy');
GO

IF NOT EXISTS (SELECT * FROM sys.schemas WHERE name = 'mail')
    EXEC('CREATE SCHEMA mail');
GO


-- =========================================================================
-- 1. CERTIFICATE AUTHORITY (CA) SERVICE
-- =========================================================================

-- Table: ca.issued (Tracks all issued certificates)
IF OBJECT_ID('ca.issued', 'U') IS NULL
BEGIN
    CREATE TABLE ca.issued (
        serial VARCHAR(64) NOT NULL CONSTRAINT PK_ca_issued PRIMARY KEY, -- Hex representation, e.g. "0x1234..."
        email VARCHAR(256) NOT NULL,
        subject NVARCHAR(512) NOT NULL,
        not_before DATETIMEOFFSET NOT NULL,
        not_after DATETIMEOFFSET NOT NULL,
        cert_pem VARBINARY(MAX) NOT NULL, -- Certificate raw bytes or PEM
        status VARCHAR(20) NOT NULL CONSTRAINT DF_ca_issued_status DEFAULT 'good',
        revoked_at DATETIMEOFFSET NULL,
        CONSTRAINT CK_ca_issued_status CHECK (status IN ('good', 'revoked'))
    );
    
    -- Index to speed up checks by email
    CREATE INDEX idx_ca_issued_email ON ca.issued(email);
END
GO

-- Table: ca.escrow_shares (Migrated from files data/ca/escrow/*.bin)
IF OBJECT_ID('ca.escrow_shares', 'U') IS NULL
BEGIN
    CREATE TABLE ca.escrow_shares (
        email VARCHAR(256) NOT NULL,
        share_index INT NOT NULL,
        share_data VARBINARY(MAX) NOT NULL,
        CONSTRAINT PK_ca_escrow_shares PRIMARY KEY (email, share_index)
    );
END
GO

-- Table: ca.audit_log
IF OBJECT_ID('ca.audit_log', 'U') IS NULL
BEGIN
    CREATE TABLE ca.audit_log (
        id INT IDENTITY(1,1) CONSTRAINT PK_ca_audit_log PRIMARY KEY,
        ts DATETIMEOFFSET NOT NULL CONSTRAINT DF_ca_audit_log_ts DEFAULT SYSDATETIMEOFFSET(),
        event VARCHAR(100) NOT NULL,
        details NVARCHAR(MAX) NULL
    );
END
GO


-- =========================================================================
-- 2. KEY DISTRIBUTION SERVER (KDS)
-- =========================================================================

-- Table: kds.certs (Public key registry — supports dual cert types per user)
IF OBJECT_ID('kds.certs', 'U') IS NULL
BEGIN
    CREATE TABLE kds.certs (
        email VARCHAR(256) NOT NULL,
        cert_type VARCHAR(10) NOT NULL CONSTRAINT DF_kds_certs_cert_type DEFAULT 'sign',
        serial VARCHAR(64) NOT NULL,
        cert_pem VARBINARY(MAX) NOT NULL,
        registered_at DATETIMEOFFSET NOT NULL CONSTRAINT DF_kds_certs_registered_at DEFAULT SYSDATETIMEOFFSET(),
        CONSTRAINT PK_kds_certs PRIMARY KEY (email, cert_type),
        CONSTRAINT CK_kds_certs_cert_type CHECK (cert_type IN ('sign', 'enc'))
    );
    CREATE INDEX idx_kds_certs_email ON kds.certs(email);
END
ELSE
BEGIN
    -- Migration: add cert_type column if upgrading from single-keypair schema
    IF NOT EXISTS (
        SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA='kds' AND TABLE_NAME='certs' AND COLUMN_NAME='cert_type'
    )
    BEGIN
        -- Step 1: Drop old PRIMARY KEY on email
        DECLARE @pk_name NVARCHAR(200);
        SELECT @pk_name = name FROM sys.key_constraints
        WHERE type = 'PK' AND parent_object_id = OBJECT_ID('kds.certs');
        IF @pk_name IS NOT NULL
            EXEC('ALTER TABLE kds.certs DROP CONSTRAINT ' + @pk_name);

        -- Step 2: Add cert_type column with default
        ALTER TABLE kds.certs
            ADD cert_type VARCHAR(10) NOT NULL
            CONSTRAINT DF_kds_certs_cert_type DEFAULT 'sign'
            WITH VALUES;

        -- Step 3: Add check constraint
        ALTER TABLE kds.certs
            ADD CONSTRAINT CK_kds_certs_cert_type CHECK (cert_type IN ('sign', 'enc'));

        -- Step 4: Add new composite PK
        ALTER TABLE kds.certs
            ADD CONSTRAINT PK_kds_certs PRIMARY KEY (email, cert_type);

        -- Step 5: Add index on email for fast lookups
        IF NOT EXISTS (
            SELECT 1 FROM sys.indexes WHERE name='idx_kds_certs_email'
              AND object_id = OBJECT_ID('kds.certs')
        )
            CREATE INDEX idx_kds_certs_email ON kds.certs(email);

        PRINT '[Migration] kds.certs upgraded to dual-cert schema (email, cert_type)';
    END
END
GO


-- Table: kds.crl_cache (Cached Certificate Revocation List)
IF OBJECT_ID('kds.crl_cache', 'U') IS NULL
BEGIN
    CREATE TABLE kds.crl_cache (
        id INT NOT NULL CONSTRAINT PK_kds_crl_cache PRIMARY KEY CONSTRAINT CK_kds_crl_cache_id CHECK (id = 1),
        crl_pem VARBINARY(MAX) NOT NULL,
        updated_at DATETIMEOFFSET NOT NULL CONSTRAINT DF_kds_crl_cache_updated_at DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

-- Table: kds.audit_log
IF OBJECT_ID('kds.audit_log', 'U') IS NULL
BEGIN
    CREATE TABLE kds.audit_log (
        id INT IDENTITY(1,1) CONSTRAINT PK_kds_audit_log PRIMARY KEY,
        ts DATETIMEOFFSET NOT NULL CONSTRAINT DF_kds_audit_log_ts DEFAULT SYSDATETIMEOFFSET(),
        event VARCHAR(100) NOT NULL,
        details NVARCHAR(MAX) NULL
    );
END
GO


-- =========================================================================
-- 3. TICKET SERVICE (AS + TGS / KERBEROS)
-- =========================================================================

-- Table: ticket.principals (Kerberos principals / users / services identity keys)
IF OBJECT_ID('ticket.principals', 'U') IS NULL
BEGIN
    CREATE TABLE ticket.principals (
        id_c VARCHAR(256) NOT NULL CONSTRAINT PK_ticket_principals PRIMARY KEY, -- User or Service Identifier
        salt VARBINARY(MAX) NOT NULL,
        kc VARBINARY(MAX) NOT NULL, -- Client secret key
        role VARCHAR(50) NOT NULL CONSTRAINT DF_ticket_principals_role DEFAULT 'user',
        CONSTRAINT CK_ticket_principals_role CHECK (role IN ('user', 'admin', 'mailing_list_manager'))
    );
END
GO

-- Table: ticket.service_keys (Shared symmetric keys for services)
IF OBJECT_ID('ticket.service_keys', 'U') IS NULL
BEGIN
    CREATE TABLE ticket.service_keys (
        id_v VARCHAR(256) NOT NULL CONSTRAINT PK_ticket_service_keys PRIMARY KEY, -- Service name (e.g., mail/securemail)
        kv VARBINARY(MAX) NOT NULL -- Service symmetric key
    );
END
GO

-- Table: ticket.revoked_tgts (Revocation list for Ticket Granting Tickets)
IF OBJECT_ID('ticket.revoked_tgts', 'U') IS NULL
BEGIN
    CREATE TABLE ticket.revoked_tgts (
        tgt_hash VARCHAR(64) NOT NULL CONSTRAINT PK_ticket_revoked_tgts PRIMARY KEY,
        revoked_at DATETIMEOFFSET NOT NULL CONSTRAINT DF_ticket_revoked_tgts_revoked_at DEFAULT SYSDATETIMEOFFSET()
    );
END
GO

-- Table: ticket.audit_log
IF OBJECT_ID('ticket.audit_log', 'U') IS NULL
BEGIN
    CREATE TABLE ticket.audit_log (
        id INT IDENTITY(1,1) CONSTRAINT PK_ticket_audit_log PRIMARY KEY,
        ts DATETIMEOFFSET NOT NULL CONSTRAINT DF_ticket_audit_log_ts DEFAULT SYSDATETIMEOFFSET(),
        event VARCHAR(100) NOT NULL,
        details NVARCHAR(MAX) NULL
    );
END
GO


-- =========================================================================
-- 4. POLICY SERVICE (SPF + DMARC)
-- =========================================================================

-- Table: policy.spf (Allowed IP addresses per domain)
IF OBJECT_ID('policy.spf', 'U') IS NULL
BEGIN
    CREATE TABLE policy.spf (
        domain VARCHAR(256) NOT NULL,
        ip VARCHAR(45) NOT NULL, -- Standard IPv4 or IPv6 representation length
        CONSTRAINT PK_policy_spf PRIMARY KEY (domain, ip)
    );
END
GO

-- Table: policy.dmarc (DMARC policy rules per domain)
IF OBJECT_ID('policy.dmarc', 'U') IS NULL
BEGIN
    CREATE TABLE policy.dmarc (
        domain VARCHAR(256) NOT NULL CONSTRAINT PK_policy_dmarc PRIMARY KEY,
        policy VARCHAR(20) NOT NULL,
        CONSTRAINT CK_policy_dmarc_policy CHECK (policy IN ('none', 'quarantine', 'reject'))
    );
END
GO


-- =========================================================================
-- 5. MAIL SERVER (MTA / SMTP / POP3)
-- =========================================================================

-- Table: mail.mailbox (Stores user messages)
IF OBJECT_ID('mail.mailbox', 'U') IS NULL
BEGIN
    CREATE TABLE mail.mailbox (
        id INT IDENTITY(1,1) CONSTRAINT PK_mail_mailbox PRIMARY KEY,
        recipient VARCHAR(256) NOT NULL,
        sender VARCHAR(256) NULL,
        received_at DATETIMEOFFSET NOT NULL CONSTRAINT DF_mail_mailbox_received_at DEFAULT SYSDATETIMEOFFSET(),
        envelope VARBINARY(MAX) NOT NULL, -- Encrypted S/MIME message content
        headers_json NVARCHAR(MAX) NULL,  -- Headers serialized as JSON
        dmarc_action VARCHAR(20) NULL,
        spf_result VARCHAR(20) NULL,
        dkim_result VARCHAR(50) NULL,
        folder NVARCHAR(20) NOT NULL CONSTRAINT DF_mail_mailbox_folder DEFAULT 'inbox',
        fetched BIT NOT NULL CONSTRAINT DF_mail_mailbox_fetched DEFAULT 0,
        CONSTRAINT CK_mail_mailbox_dmarc_action CHECK (dmarc_action IN ('accept', 'quarantine', 'reject', 'none')),
        CONSTRAINT CK_mail_mailbox_spf_result CHECK (spf_result IN ('pass', 'fail', 'none')),
        CONSTRAINT CK_mail_mailbox_folder CHECK (folder IN ('inbox', 'sent'))
    );
    
    -- Composite index to speed up POP3 Inbox/Sent fetches for a recipient.
    CREATE INDEX idx_mailbox_recipient_folder ON mail.mailbox(recipient, folder, fetched);
END
GO

-- Table: mail.server_log
IF OBJECT_ID('mail.server_log', 'U') IS NULL
BEGIN
    CREATE TABLE mail.server_log (
        id INT IDENTITY(1,1) CONSTRAINT PK_mail_server_log PRIMARY KEY,
        ts DATETIMEOFFSET NOT NULL CONSTRAINT DF_mail_server_log_ts DEFAULT SYSDATETIMEOFFSET(),
        event VARCHAR(100) NOT NULL,
        details NVARCHAR(MAX) NULL
    );
END
GO
