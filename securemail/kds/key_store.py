"""SQL Server CRUD cho certificates + CRL cache."""
import datetime as dt

from securemail.db_conn import get_conn


def _audit(event: str, details: str = ""):
    """Ghi một dòng audit log vào SQL Server."""
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO kds.audit_log(ts, event, details) VALUES (%s, %s, %s)",
        (dt.datetime.now(dt.timezone.utc), event, details),
    )
    conn.close()


def put_cert(email: str, serial_hex: str, cert_pem: bytes):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        """MERGE INTO kds.certs AS target
        USING (SELECT %s AS email) AS source
        ON target.email = source.email
        WHEN MATCHED THEN
            UPDATE SET serial = %s, cert_pem = %s, registered_at = %s
        WHEN NOT MATCHED THEN
            INSERT (email, serial, cert_pem, registered_at) VALUES (%s, %s, %s, %s);""",
        (email,
         serial_hex, bytearray(cert_pem), dt.datetime.now(dt.timezone.utc),
         email, serial_hex, bytearray(cert_pem), dt.datetime.now(dt.timezone.utc)),
    )
    conn.close()
    _audit("PUT_CERT", f"email={email} serial={serial_hex}")


def get_cert(email: str) -> dict | None:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT email, serial, cert_pem FROM kds.certs WHERE email=%s", (email,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {"email": row[0], "serial": row[1], "cert_pem": bytes(row[2])}


def list_emails() -> list[str]:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM kds.certs")
    rows = cursor.fetchall()
    conn.close()
    return [r[0] for r in rows]


def put_crl(crl_pem: bytes):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        """MERGE INTO kds.crl_cache AS target
        USING (SELECT 1 AS id) AS source
        ON target.id = source.id
        WHEN MATCHED THEN
            UPDATE SET crl_pem = %s, updated_at = %s
        WHEN NOT MATCHED THEN
            INSERT (id, crl_pem, updated_at) VALUES (1, %s, %s);""",
        (bytearray(crl_pem), dt.datetime.now(dt.timezone.utc),
         bytearray(crl_pem), dt.datetime.now(dt.timezone.utc)),
    )
    conn.close()
    _audit("SYNC_CRL", "")


def get_crl() -> bytes | None:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT crl_pem FROM kds.crl_cache WHERE id=1")
    row = cursor.fetchone()
    conn.close()
    return bytes(row[0]) if row else None
