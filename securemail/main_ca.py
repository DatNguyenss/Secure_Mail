"""Entry point CA Service + Admin CLI.

Usage:
  python -m securemail.main_ca serve                        # chạy CA server
  python -m securemail.main_ca revoke <serial_hex>          # thu hồi cert
  python -m securemail.main_ca list                         # liệt kê cert
  python -m securemail.main_ca escrow <email>               # xem 3 share trong data/ca/escrow
"""
import sys
import sqlite3

from securemail.ca_service import ca_server, ca_core, key_escrow


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == "serve":
        ca_server.serve()
    elif cmd == "revoke":
        ca_core.revoke_cert(sys.argv[2])
    elif cmd == "list":
        ca_core._ensure_db()
        conn = sqlite3.connect(ca_core.CA_DB)
        for row in conn.execute(
            "SELECT serial, email, status, not_after FROM issued"
        ).fetchall():
            print(f"  {row[0]:20s} {row[1]:30s} {row[2]:10s} {row[3]}")
        conn.close()
    elif cmd == "escrow":
        email = sys.argv[2]
        recovered = key_escrow.recover_key(email, [1, 2])
        print(f"Recovered {len(recovered)} bytes (shares 1+2). First 100 bytes:")
        print(recovered[:100].decode("utf-8", errors="replace"))
    else:
        print(f"unknown command: {cmd}")


if __name__ == "__main__":
    main()
