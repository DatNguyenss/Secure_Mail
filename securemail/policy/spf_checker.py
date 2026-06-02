"""SPF-lite: mỗi domain đăng ký danh sách IP được phép gửi."""
from securemail.db_conn import get_conn


def add_spf(domain: str, ip: str):
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        "IF NOT EXISTS (SELECT 1 FROM policy.spf WHERE domain=%s AND ip=%s) "
        "INSERT INTO policy.spf(domain, ip) VALUES (%s, %s)",
        (domain, ip, domain, ip),
    )
    conn.close()


def check(domain: str, ip: str) -> bool:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM policy.spf WHERE domain=%s AND ip=%s", (domain, ip))
    row = cursor.fetchone()
    conn.close()
    return row is not None


def domain_has_spf(domain: str) -> bool:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM policy.spf WHERE domain=%s", (domain,))
    row = cursor.fetchone()
    conn.close()
    return row is not None
