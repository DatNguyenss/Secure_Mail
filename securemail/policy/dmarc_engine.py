"""DMARC-lite: kết hợp SPF + DKIM → áp policy none/quarantine/reject."""
import sqlite3
from .spf_checker import POLICY_DB, _ensure_db


def set_policy(domain: str, policy: str):
    assert policy in ("none", "quarantine", "reject")
    _ensure_db()
    conn = sqlite3.connect(POLICY_DB)
    conn.execute(
        "INSERT INTO dmarc(domain, policy) VALUES (?, ?) "
        "ON CONFLICT(domain) DO UPDATE SET policy=excluded.policy",
        (domain, policy),
    )
    conn.commit()
    conn.close()


def get_policy(domain: str) -> str:
    _ensure_db()
    conn = sqlite3.connect(POLICY_DB)
    row = conn.execute("SELECT policy FROM dmarc WHERE domain=?", (domain,)).fetchone()
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
