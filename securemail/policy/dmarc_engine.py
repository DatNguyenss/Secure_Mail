"""DMARC-lite: kết hợp SPF + DKIM → áp policy none/quarantine/reject."""
from securemail.db_conn import get_conn


def set_policy(domain: str, policy: str):
    assert policy in ("none", "quarantine", "reject")
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        """MERGE INTO policy.dmarc AS target
        USING (SELECT %s AS domain) AS source
        ON target.domain = source.domain
        WHEN MATCHED THEN
            UPDATE SET policy = %s
        WHEN NOT MATCHED THEN
            INSERT (domain, policy) VALUES (%s, %s);""",
        (domain, policy, domain, policy),
    )
    conn.close()


def get_policy(domain: str) -> str:
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT policy FROM policy.dmarc WHERE domain=%s", (domain,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else "none"


def decide(spf_pass: bool, dkim_pass: bool, policy: str) -> str:
    """Return 'accept' | 'quarantine' | 'reject'."""
    if spf_pass and dkim_pass:
        return "accept"
    # At least one failed
    if policy == "none":
        return "accept"
    if policy == "quarantine":
        return "quarantine"
    return "reject"
