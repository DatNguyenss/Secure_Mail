"""Mail Server entry point: SMTP-lite + POP3-lite trong 2 threads."""
import threading
import sys
import time
from pathlib import Path

from securemail.network import smtp_server, pop3_server


def _prepare_server_identity():
    """Đảm bảo server có RSA key + cert (được ký từ CA, tra qua KDS).

    Trong demo, script run_demo.py tạo sẵn bằng CSR tới CA với email mail@mail.local.
    """
    required = [
        Path("data/server/mail_key.pem"),
        Path("data/server/mail_cert.pem"),
    ]
    for p in required:
        if not p.exists():
            print(f"[MailSrv] Missing {p}. Run run_demo.py bootstrap first.")
            sys.exit(1)


def serve():
    _prepare_server_identity()
    t1 = threading.Thread(target=smtp_server.serve, daemon=True)
    t2 = threading.Thread(target=pop3_server.serve, daemon=True)
    t1.start()
    t2.start()
    print("[MailSrv] SMTP+POP3 running. Ctrl+C to quit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[MailSrv] bye")


if __name__ == "__main__":
    serve()
