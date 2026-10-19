from datetime import datetime, timedelta
from .database import connect_db

FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW_MINUTES = 10
SUCCESS_AFTER_FAILURE_WINDOW_MINUTES = 5
PRIVILEGED_USERS = {"root", "admin", "administrator"}


def run_detection(now=None):
    """Run transparent, rule-based detections over stored events.

    These heuristics identify events worth reviewing; they do not prove compromise.
    Returns the number of newly created alerts.
    """
    now = now or datetime.now()
    created = 0

    with connect_db() as conn:
        events = conn.execute("""
            SELECT id, timestamp, source_ip, username, event_type, status, details
            FROM logs
            WHERE UPPER(event_type) = 'LOGIN'
            ORDER BY timestamp ASC, id ASC
        """).fetchall()

        # Rule 1: repeated failures from one IP within a rolling time window.
        by_ip = {}
        for event in events:
            if event["status"].upper() != "FAILED":
                continue
            try:
                stamp = datetime.fromisoformat(event["timestamp"])
            except ValueError:
                continue
            by_ip.setdefault(event["source_ip"], []).append((stamp, event))

        for ip, failures in by_ip.items():
            for index, (stamp, event) in enumerate(failures):
                window_start = stamp - timedelta(minutes=FAILED_LOGIN_WINDOW_MINUTES)
                window = [(t, e) for t, e in failures[:index + 1]
                          if window_start <= t <= stamp]
                # Evaluate each failure as the end of a rolling window.
                if len(window) >= FAILED_LOGIN_THRESHOLD:
                    window_ids = sorted(e["id"] for _, e in window)
                    rule_key = f"BRUTE_FORCE:{ip}:{window_ids[-1]}"
                    evidence = (
                        f"{len(window)} failed login events from {ip} within "
                        f"{FAILED_LOGIN_WINDOW_MINUTES} minutes. Event IDs: "
                        + ", ".join(map(str, window_ids))
                    )
                    created += _create_alert(
                        conn, rule_key, stamp, ip, "HIGH",
                        "Repeated failed logins",
                        f"At least {FAILED_LOGIN_THRESHOLD} failed login attempts "
                        f"were observed from {ip} in a short time window.",
                        evidence
                    )
                    break

        # Rule 2: failed attempt followed by a success from same IP within 5 minutes.
        events_by_ip = {}
        for event in events:
            try:
                stamp = datetime.fromisoformat(event["timestamp"])
            except ValueError:
                continue
            events_by_ip.setdefault(event["source_ip"], []).append((stamp, event))

        for ip, sequence in events_by_ip.items():
            for index, (stamp, event) in enumerate(sequence):
                if event["status"].upper() != "SUCCESS":
                    continue
                prior_failures = [
                    (prior_stamp, prior)
                    for prior_stamp, prior in sequence[:index]
                    if prior["status"].upper() == "FAILED"
                    and timedelta(0) <= stamp - prior_stamp
                    <= timedelta(minutes=SUCCESS_AFTER_FAILURE_WINDOW_MINUTES)
                ]
                if prior_failures:
                    prior_stamp, prior = prior_failures[-1]
                    rule_key = f"FAIL_THEN_SUCCESS:{ip}:{event['id']}"
                    created += _create_alert(
                        conn, rule_key, stamp, ip, "MEDIUM",
                        "Success after failed login",
                        "A successful login followed a failed login from the same IP "
                        "within the configured review window.",
                        f"Failed event ID {prior['id']} at {prior_stamp}; "
                        f"successful event ID {event['id']} at {stamp}."
                    )

        # Rule 3: failed login attempts using privileged account names.
        for event in events:
            if (event["status"].upper() != "FAILED"
                    or event["username"].strip().lower() not in PRIVILEGED_USERS):
                continue
            try:
                stamp = datetime.fromisoformat(event["timestamp"])
            except ValueError:
                continue
            rule_key = f"PRIVILEGED_LOGIN:{event['id']}"
            created += _create_alert(
                conn, rule_key, stamp, event["source_ip"], "MEDIUM",
                "Privileged account login attempt",
                f"Failed login attempt for privileged account "
                f"'{event['username']}'.",
                f"Event ID {event['id']}; details: {event['details']}"
            )

    return created


def _create_alert(conn, rule_key, timestamp, ip, severity,
                  rule_name, description, evidence):
    cursor = conn.execute("""
        INSERT OR IGNORE INTO alerts
        (created_at, source_ip, severity, rule_key, rule_name,
         description, evidence, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'Open')
    """, (
        timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        ip, severity, rule_key, rule_name, description, evidence
    ))
    return max(cursor.rowcount, 0)
