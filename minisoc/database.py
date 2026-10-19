from pathlib import Path
import sqlite3
from datetime import datetime, timedelta

DB_PATH = Path(__file__).resolve().parent.parent / "minisoc.db"


def connect_db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    with connect_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            username TEXT NOT NULL,
            event_type TEXT NOT NULL,
            status TEXT NOT NULL,
            details TEXT NOT NULL,
            fingerprint TEXT NOT NULL UNIQUE
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            severity TEXT NOT NULL,
            rule_key TEXT NOT NULL UNIQUE,
            rule_name TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open'
                CHECK(status IN ('Open', 'Investigating', 'Resolved'))
        );
        """)


def seed_demo_data():
    """Insert safe, synthetic demonstration events only into an empty log table."""
    now = datetime.now().replace(microsecond=0)
    demo = []

    for index in range(10):
        timestamp = now - timedelta(minutes=45 - index * 3)
        demo.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": f"192.168.1.{20 + index}",
            "username": ["alice", "bob", "charlie", "david"][index % 4],
            "event_type": "LOGIN",
            "status": "SUCCESS",
            "details": "Successful user authentication",
        })

    for index in range(7):
        timestamp = now - timedelta(minutes=9 - index)
        demo.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": "203.0.113.25",
            "username": "admin",
            "event_type": "LOGIN",
            "status": "FAILED",
            "details": "Invalid password",
        })

    demo.append({
        "timestamp": (now - timedelta(minutes=2)).strftime("%Y-%m-%d %H:%M:%S"),
        "source_ip": "198.51.100.42",
        "username": "root",
        "event_type": "LOGIN",
        "status": "FAILED",
        "details": "Invalid password",
    })

    with connect_db() as conn:
        existing = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        if existing:
            return
        for event in demo:
            _insert_log(conn, event)


def _insert_log(conn, event):
    canonical = "|".join(str(event[key]).strip() for key in (
        "timestamp", "source_ip", "username", "event_type", "status", "details"
    ))
    import hashlib
    fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    cursor = conn.execute("""
        INSERT OR IGNORE INTO logs
        (timestamp, source_ip, username, event_type, status, details, fingerprint)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        event["timestamp"], event["source_ip"], event["username"],
        event["event_type"], event["status"], event["details"], fingerprint
    ))
    return cursor.rowcount


def insert_logs(events):
    inserted = 0
    with connect_db() as conn:
        for event in events:
            inserted += _insert_log(conn, event)
    return inserted
