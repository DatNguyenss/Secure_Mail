"""Centralized SQL Server database connection helper for SecureMail.

Reads connection parameters from the project-root `.env` file and provides
simple helper functions so that every service module can obtain a connection
without duplicating configuration logic.

Usage in any service module:
    from securemail.db_conn import get_conn

    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ca.issued WHERE serial = %s", (serial_hex,))
    row = cursor.fetchone()
    conn.close()
"""

import os
from pathlib import Path

import pymssql
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Load .env once at module import time.
# Walk upward from this file to find the project-root .env.
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent  # securemail/ -> project root
_ENV_PATH = _PROJECT_ROOT / ".env"

load_dotenv(_ENV_PATH)

DB_HOST: str = os.environ.get("DB_HOST", "localhost")
DB_PORT: str = os.environ.get("DB_PORT", "1433")
DB_NAME: str = os.environ.get("DB_NAME", "SecureMail")
DB_USER: str = os.environ.get("DB_USER", "sa")
DB_PASSWORD: str = os.environ.get("DB_PASSWORD", "123")


def get_conn() -> pymssql.Connection:
    """Return a new pymssql connection to the configured SQL Server instance.

    The caller is responsible for closing the connection when done.
    pymssql uses ``%s`` as the parameter placeholder in queries.
    """
    return pymssql.connect(
        server=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        autocommit=True,
    )
