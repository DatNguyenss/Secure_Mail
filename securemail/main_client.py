"""CLI cho Mail Client.

Usage:
  python -m securemail.main_client register <email> <password> [<display>]
  python -m securemail.main_client login <email> <password>     # test
  python -m securemail.main_client send <email> <password> <to> <subject>
      (body đọc từ stdin, kết thúc bằng ctrl-d / ctrl-z)
  python -m securemail.main_client fetch <email> <password>
"""
import sys

from securemail import client_core


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]

    if cmd == "register":
        email, password = sys.argv[2], sys.argv[3]
        display = sys.argv[4] if len(sys.argv) > 4 else ""
        client_core.register(email, password, display)

    elif cmd == "login":
        email, password = sys.argv[2], sys.argv[3]
        ctx = client_core.login(email, password)
        print(f"OK — TGT length={len(ctx['tgt'])}")

    elif cmd == "send":
        email, password, to, subject = sys.argv[2:6]
        body = sys.stdin.read()
        ctx = client_core.login(email, password)
        r = client_core.send_secure_email(ctx, [to], subject, body)
        print(f"Sent: {r['envelope_len']} bytes envelope")
        for rcpt, resp in r["results"]:
            print(f"  {rcpt}: {resp}")

    elif cmd == "fetch":
        email, password = sys.argv[2], sys.argv[3]
        ctx = client_core.login(email, password)
        msgs = client_core.fetch_inbox(ctx)
        print(f"=== Inbox of {email} — {len(msgs)} new ===")
        for m in msgs:
            print(f"\n--- id={m['id']} from={m['sender']} ---")
            print(f"  Subject: {m.get('subject','')}")
            print(f"  Date: {m.get('date','')}")
            print(f"  Signature: {'VALID' if m.get('signature_valid') else 'INVALID'}")
            if m.get("signer_subject"):
                print(f"  Signer: {m['signer_subject']}")
            print(f"  DMARC: {m.get('dmarc_action')} | SPF: {m.get('spf_result')} | DKIM: {m.get('dkim_result')}")
            if m.get("error"):
                print(f"  ERROR: {m['error']}")
            else:
                print(f"  --- Body ---")
                print(m.get("body", ""))

    else:
        print(f"unknown: {cmd}")


if __name__ == "__main__":
    main()
