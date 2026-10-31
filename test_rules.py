"""Tests for the four explainable detection rules."""

from datetime import datetime, timedelta

import pandas as pd

from detection.rules import run_rules

ALERT_KEYS = {
    "ip",
    "user",
    "timestamp",
    "severity",
    "reason",
    "source",
    "mitre",
    "count",
    "event_indices",
}


def make_events(rows: list[tuple]) -> pd.DataFrame:
    """Build an events DataFrame from (timestamp, ip, user, event, status, port) rows."""
    frame = pd.DataFrame(
        rows,
        columns=["timestamp", "ip", "user", "event", "status", "port"],
    )
    frame["bytes"] = 100
    frame["label"] = 0
    frame["timestamp"] = pd.to_datetime(frame["timestamp"])
    return frame


def login_rows(ip: str, count: int, start: str, seconds: int, status: str = "fail") -> list[tuple]:
    base = datetime.fromisoformat(start)
    return [
        (
            (base + timedelta(seconds=seconds * index)).strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            "admin",
            "login",
            status,
            443,
        )
        for index in range(count)
    ]


def alerts_for(events: pd.DataFrame, mitre: str) -> list[dict]:
    return [alert for alert in run_rules(events) if alert["mitre"] == mitre]


def test_alert_schema() -> None:
    alerts = alerts_for(make_events(login_rows("10.0.0.9", 5, "2026-03-01 10:00:00", 30)), "T1110")

    assert len(alerts) == 1
    assert ALERT_KEYS <= alerts[0].keys()
    assert alerts[0]["source"] == "Rule"


def test_brute_force_threshold() -> None:
    alerts = alerts_for(make_events(login_rows("10.0.0.9", 5, "2026-03-01 10:00:00", 30)), "T1110")

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["ip"] == "10.0.0.9"
    assert alert["user"] == "admin"
    assert alert["severity"] == "High"
    assert alert["count"] == 5
    assert len(alert["event_indices"]) == 5
    assert "5 failed logins" in alert["reason"]


def test_brute_force_below_threshold() -> None:
    assert alerts_for(make_events(login_rows("10.0.0.9", 4, "2026-03-01 10:00:00", 30)), "T1110") == []


def test_brute_force_outside_window_is_not_combined() -> None:
    events = make_events(login_rows("10.0.0.9", 5, "2026-03-01 10:00:00", 6 * 60))
    assert alerts_for(events, "T1110") == []


def test_brute_force_from_different_ips_is_not_combined() -> None:
    rows = login_rows("10.0.0.9", 4, "2026-03-01 10:00:00", 30)
    rows += login_rows("10.0.0.10", 4, "2026-03-01 10:00:00", 30)
    assert alerts_for(make_events(rows), "T1110") == []


def test_successful_login_after_burst_is_critical() -> None:
    rows = login_rows("10.0.0.9", 5, "2026-03-01 10:00:00", 30)
    rows.append(("2026-03-01 10:03:00", "10.0.0.9", "admin", "login", "success", 443))

    alerts = alerts_for(make_events(rows), "T1110")

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "Critical"
    assert "followed by a successful login" in alerts[0]["reason"]
    assert len(alerts[0]["event_indices"]) == 6


def test_port_scan_threshold() -> None:
    rows = [
        ("2026-03-01 12:00:00", "10.0.0.7", "unknown", "conn", "denied", port)
        for port in range(1, 16)
    ]
    alerts = alerts_for(make_events(rows), "T1046")

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "High"
    assert "15 distinct ports" in alerts[0]["reason"]


def test_port_scan_below_threshold() -> None:
    rows = [
        ("2026-03-01 12:00:00", "10.0.0.7", "unknown", "conn", "denied", port)
        for port in range(1, 15)
    ]
    assert alerts_for(make_events(rows), "T1046") == []


def test_flood_threshold() -> None:
    base = datetime(2026, 3, 1, 10, 0, 0)
    rows = [
        ((base + timedelta(seconds=index)).strftime("%Y-%m-%d %H:%M:%S"), "10.0.0.6", "u", "web", "ok", 80)
        for index in range(60)
    ]
    alerts = alerts_for(make_events(rows), "T1498")

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "High"
    assert "60 requests" in alerts[0]["reason"]


def test_flood_below_threshold() -> None:
    base = datetime(2026, 3, 1, 10, 0, 0)
    rows = [
        ((base + timedelta(seconds=index)).strftime("%Y-%m-%d %H:%M:%S"), "10.0.0.6", "u", "web", "ok", 80)
        for index in range(59)
    ]
    assert alerts_for(make_events(rows), "T1498") == []


def test_off_hours_successful_login() -> None:
    rows = [("2026-03-01 02:15:00", "10.0.0.5", "backup", "login", "success", 443)]
    alerts = alerts_for(make_events(rows), "T1078")

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "Medium"
    assert alerts[0]["user"] == "backup"


def test_off_hours_ignores_business_hours_and_failures() -> None:
    rows = [
        ("2026-03-01 22:00:00", "10.0.0.5", "ali", "login", "success", 443),
        ("2026-03-01 05:00:00", "10.0.0.5", "ali", "login", "success", 443),
        ("2026-03-01 02:00:00", "10.0.0.5", "ali", "login", "fail", 443),
    ]
    assert alerts_for(make_events(rows), "T1078") == []
