"""Log Viewer Utility for SecureMail.

Allows interactive viewing of individual service logs or a combined chronological view.
Reads from SQL Server instead of local SQLite databases.
"""
import datetime as dt

from securemail.db_conn import get_conn

# Table mapping: (schema.table, service_label)
LOG_TABLES = [
    ("ca.audit_log",      "CA"),
    ("ticket.audit_log",  "TICKET"),
    ("kds.audit_log",     "KDS"),
    ("mail.server_log",   "MAIL"),
]

def format_ts(ts_val) -> str:
    """Format a timestamp (datetime or string) to a human-readable format."""
    try:
        if isinstance(ts_val, dt.datetime):
            return ts_val.strftime("%Y-%m-%d %H:%M:%S")
        ts_str = str(ts_val)
        t = dt.datetime.fromisoformat(ts_str)
        return t.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts_val)[:19].replace("T", " ")

def get_logs(table: str, service_name: str) -> list[dict]:
    """Retrieve logs from a specific SQL Server table."""
    try:
        conn = get_conn()
        cursor = conn.cursor()
        cursor.execute(f"SELECT ts, event, details FROM {table} ORDER BY ts ASC")
        rows = cursor.fetchall()
        conn.close()
        return [{"ts": r[0], "service": service_name, "event": r[1], "details": r[2] or ""} for r in rows]
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
        print("  1. View CA Service Logs (ca.audit_log)")
        print("  2. View Ticket Service Logs (ticket.audit_log)")
        print("  3. View Key Distribution Service Logs (kds.audit_log)")
        print("  4. View Mail Server Logs (SMTP & POP3 - mail.server_log)")
        print("  5. View ALL Logs (Merged Chronologically)")
        print("  6. Exit")
        print("=" * 50)
        
        choice = input("Enter your choice (1-6): ").strip()
        
        if choice == '1':
            logs = get_logs("ca.audit_log", "CA")
            print_log_table(logs, "CA SERVICE AUDIT LOGS")
        elif choice == '2':
            logs = get_logs("ticket.audit_log", "TICKET")
            print_log_table(logs, "TICKET SERVICE AUDIT LOGS")
        elif choice == '3':
            logs = get_logs("kds.audit_log", "KDS")
            print_log_table(logs, "KEY DISTRIBUTION SERVICE AUDIT LOGS")
        elif choice == '4':
            logs = get_logs("mail.server_log", "MAIL")
            print_log_table(logs, "MAIL SERVER (SMTP/POP3) LOGS")
        elif choice == '5':
            # Merge and sort chronologically
            all_logs = []
            for table, label in LOG_TABLES:
                all_logs.extend(get_logs(table, label))
            
            # Sort by timestamp
            all_logs.sort(key=lambda x: str(x["ts"]))
            print_log_table(all_logs, "ALL SERVICE SYSTEM-WIDE MERGED LOGS")
        elif choice == '6':
            print("Goodbye!")
            break
        else:
            print("Invalid choice, please enter a number from 1 to 6.")

if __name__ == "__main__":
    main()
