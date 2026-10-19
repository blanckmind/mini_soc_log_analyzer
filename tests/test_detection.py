import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timedelta

from minisoc.database import connect_db, initialize_database, insert_logs
from minisoc.detection import run_detection


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"

        # Patch the database path used by the database module.
        import minisoc.database as database
        self.original_path = database.DB_PATH
        database.DB_PATH = self.db_path
        initialize_database()

    def tearDown(self):
        import minisoc.database as database
        database.DB_PATH = self.original_path
        self.temp_dir.cleanup()

    def test_repeated_failures_generate_high_alert(self):
        now = datetime(2026, 10, 19, 9, 0, 0)
        events = []
        for i in range(5):
            events.append({
                "timestamp": (now + timedelta(minutes=i)).strftime("%Y-%m-%d %H:%M:%S"),
                "source_ip": "203.0.113.10",
                "username": "guest",
                "event_type": "LOGIN",
                "status": "FAILED",
                "details": "Bad password",
            })
        insert_logs(events)
        self.assertGreaterEqual(run_detection(now=now + timedelta(minutes=10)), 1)
        with connect_db() as conn:
            alert = conn.execute(
                "SELECT * FROM alerts WHERE severity = 'HIGH'"
            ).fetchone()
        self.assertIsNotNone(alert)

    def test_privileged_failed_login_generates_alert(self):
        insert_logs([{
            "timestamp": "2026-10-19 09:00:00",
            "source_ip": "198.51.100.20",
            "username": "root",
            "event_type": "LOGIN",
            "status": "FAILED",
            "details": "Bad password",
        }])
        run_detection()
        with connect_db() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE rule_name = 'Privileged account login attempt'"
            ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_detection_is_idempotent(self):
        events = []
        for i in range(5):
            events.append({
                "timestamp": f"2026-10-19 09:0{i}:00",
                "source_ip": "203.0.113.11",
                "username": "guest",
                "event_type": "LOGIN",
                "status": "FAILED",
                "details": "Bad password",
            })
        insert_logs(events)
        run_detection()
        run_detection()
        with connect_db() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE rule_name = 'Repeated failed logins'"
            ).fetchone()[0]
        self.assertEqual(count, 1)


if __name__ == "__main__":
    unittest.main()
