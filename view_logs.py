"""Log Viewer Utility for SecureMail.

Allows interactive viewing of individual service logs or a combined chronological view.
"""
import sqlite3
import datetime as dt
from pathlib import Path

# Paths to databases
CA_DB = Path("data/ca/ca.db")
TICKET_DB = Path("data/ticket/ticket.db")
KDS_DB = Path("data/kds/kds.db")
MAIL_DB = Path("data/mail/mailstore.db")

def format_ts(ts_str: str) -> str:
    """Format ISO timestamp to a human-readable local-like format."""
    try:
        # Parse ISO format (e.g. 2026-05-19T03:50:30.741784+00:00)
        t = dt.datetime.fromisoformat(ts_str)
        return t.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts_str[:19].replace("T", " ")

def get_logs(db_path: Path, table_name: str, service_name: str) -> list[dict]:
    """Retrieve logs from a specific database table."""
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Check if table exists
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'")
        if not cursor.fetchone():
            conn.close()
            return []
        
        rows = cursor.execute(f"SELECT ts, event, details FROM {table_name} ORDER BY ts ASC").fetchall()
        conn.close()
        return [{"ts": r[0], "service": service_name, "event": r[1], "details": r[2]} for r in rows]
    except Exception as e:
        print(f"Error reading {service_name} logs: {e}")
        return []

def print_log_table(logs: list[dict], title: str):
    """Print logs in a beautifully aligned terminal table."""
    print(f"\n{'='*95}")
    print(f"  {title} ({len(logs)} records)")
    print('='*95)
    
    if not logs:
        print("  No log records found.")
        print('='*95)
        return

    # Column widths
    w_ts = 20
    w_srv = 12
    w_evt = 22
    w_det = 35
    
    header = f"{'Timestamp'.ljust(w_ts)}| {'Service'.ljust(w_srv)}| {'Event'.ljust(w_evt)}| {'Details'}"
    print(header)
    print("-" * 95)
    
    for log in logs:
        ts = format_ts(log["ts"]).ljust(w_ts)
        srv = log["service"].ljust(w_srv)
        evt = log["event"].ljust(w_evt)
        det = log["details"]
        print(f"{ts}| {srv}| {evt}| {det}")
    print('='*95)

def main():
    while True:
        print("\n" + "=" * 50)
        print("           SECUREMAIL AUDIT LOG VIEWER          ")
        print("=" * 50)
        print("  1. View CA Service Logs (ca.db)")
        print("  2. View Ticket Service Logs (ticket.db)")
        print("  3. View Key Distribution Service Logs (kds.db)")
        print("  4. View Mail Server Logs (SMTP & POP3 - mailstore.db)")
        print("  5. View ALL Logs (Merged Chronologically)")
        print("  6. Exit")
        print("=" * 50)
        
        choice = input("Enter your choice (1-6): ").strip()
        
        if choice == '1':
            logs = get_logs(CA_DB, "audit_log", "CA")
            print_log_table(logs, "CA SERVICE AUDIT LOGS")
        elif choice == '2':
            logs = get_logs(TICKET_DB, "audit_log", "TICKET")
            print_log_table(logs, "TICKET SERVICE AUDIT LOGS")
        elif choice == '3':
            logs = get_logs(KDS_DB, "audit_log", "KDS")
            print_log_table(logs, "KEY DISTRIBUTION SERVICE AUDIT LOGS")
        elif choice == '4':
            logs = get_logs(MAIL_DB, "server_log", "MAIL")
            print_log_table(logs, "MAIL SERVER (SMTP/POP3) LOGS")
        elif choice == '5':
            # Merge and sort chronologically
            all_logs = []
            all_logs.extend(get_logs(CA_DB, "audit_log", "CA"))
            all_logs.extend(get_logs(TICKET_DB, "audit_log", "TICKET"))
            all_logs.extend(get_logs(KDS_DB, "audit_log", "KDS"))
            all_logs.extend(get_logs(MAIL_DB, "server_log", "MAIL"))
            
            # Sort by timestamp string
            all_logs.sort(key=lambda x: x["ts"])
            print_log_table(all_logs, "ALL SERVICE SYSTEM-WIDE MERGED LOGS")
        elif choice == '6':
            print("Goodbye!")
            break
        else:
            print("Invalid choice, please enter a number from 1 to 6.")

if __name__ == "__main__":
    main()
