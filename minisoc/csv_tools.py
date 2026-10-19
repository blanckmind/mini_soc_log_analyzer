import csv
from datetime import datetime
from .database import insert_logs, connect_db

REQUIRED_COLUMNS = {
    "timestamp", "source_ip", "username",
    "event_type", "status", "details"
}


def import_log_csv(filepath):
    events = []
    with open(filepath, "r", newline="", encoding="utf-8-sig") as source:
        reader = csv.DictReader(source)
        if not reader.fieldnames:
            raise ValueError("The CSV file is empty.")

        reader.fieldnames = [name.strip().lower() for name in reader.fieldnames]
        missing = REQUIRED_COLUMNS - set(reader.fieldnames)
        if missing:
            raise ValueError("Missing CSV columns: " + ", ".join(sorted(missing)))

        for line_number, raw in enumerate(reader, start=2):
            event = {
                key.strip().lower(): (value or "").strip()
                for key, value in raw.items() if key is not None
            }
            if not all(event.get(key) for key in REQUIRED_COLUMNS):
                raise ValueError(f"Missing field in CSV row {line_number}.")
            try:
                datetime.fromisoformat(event["timestamp"])
            except ValueError:
                raise ValueError(
                    f"Invalid timestamp in row {line_number}. "
                    "Use YYYY-MM-DD HH:MM:SS."
                )
            event["event_type"] = event["event_type"].upper()
            event["status"] = event["status"].upper()
            events.append(event)

    inserted = insert_logs(events)
    return inserted, len(events) - inserted


def export_alerts_csv(filepath):
    with connect_db() as conn:
        rows = conn.execute("""
            SELECT id, created_at, source_ip, severity, rule_name,
                   description, evidence, status
            FROM alerts ORDER BY id DESC
        """).fetchall()

    with open(filepath, "w", newline="", encoding="utf-8") as target:
        writer = csv.writer(target)
        writer.writerow([
            "ID", "Timestamp", "Source IP", "Severity", "Rule",
            "Description", "Evidence", "Status"
        ])
        writer.writerows([tuple(row) for row in rows])

    return len(rows)
