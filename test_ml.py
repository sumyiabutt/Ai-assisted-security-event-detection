"""Tests for per-IP feature extraction and Isolation Forest detection."""

from datetime import datetime, timedelta

import pandas as pd

from detection.ml_model import build_features, detect_anomalies

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
    frame = pd.DataFrame(
        rows,
        columns=["timestamp", "ip", "user", "event", "status", "port"],
    )
    frame["bytes"] = 100
    frame["label"] = 0
    frame["timestamp"] = pd.to_datetime(frame["timestamp"])
    return frame


def test_build_features_per_ip() -> None:
    events = make_events(
        [
            ("2026-03-01 10:00:00", "10.0.0.1", "a", "login", "fail", 443),
            ("2026-03-01 10:00:30", "10.0.0.1", "a", "login", "fail", 443),
            ("2026-03-01 10:01:00", "10.0.0.1", "a", "web", "ok", 80),
            ("2026-03-01 10:01:10", "10.0.0.1", "a", "web", "ok", 443),
            ("2026-03-01 01:00:00", "10.0.0.2", "b", "login", "success", 443),
        ]
    )
    features = build_features(events)

    assert set(features.index) == {"10.0.0.1", "10.0.0.2"}
    assert features.loc["10.0.0.1", "total_events"] == 4
    assert features.loc["10.0.0.1", "failed_logins"] == 2
    assert features.loc["10.0.0.1", "distinct_ports"] == 2
    assert features.loc["10.0.0.1", "peak_requests_per_minute"] == 2
    assert features.loc["10.0.0.1", "off_hours_logins"] == 0
    assert features.loc["10.0.0.2", "off_hours_logins"] == 1


def _normal_rows() -> list[tuple]:
    rows: list[tuple] = []
    for offset in range(12):
        ip = f"192.168.0.{offset + 1}"
        for event_index in range(6):
            timestamp = datetime(2026, 3, 1, 9, 0) + timedelta(minutes=event_index * 7)
            rows.append(
                (
                    timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    ip,
                    "user",
                    "login" if event_index == 0 else "web",
                    "success" if event_index == 0 else "ok",
                    443 if event_index == 0 else 80,
                )
            )
    return rows


def _attack_rows() -> list[tuple]:
    rows: list[tuple] = []
    base = datetime(2026, 3, 2, 10, 0)
    for index in range(20):
        rows.append(
            (
                (base + timedelta(seconds=10 * index)).strftime("%Y-%m-%d %H:%M:%S"),
                "203.0.113.45",
                "admin",
                "login",
                "fail",
                443,
            )
        )
    for port in range(1, 21):
        rows.append(("2026-03-02 11:00:00", "203.0.113.45", "unknown", "conn", "denied", port))
    rows.append(("2026-03-03 02:00:00", "203.0.113.45", "admin", "login", "success", 443))
    return rows


def test_isolation_forest_flags_extreme_ip() -> None:
    events = make_events(_normal_rows() + _attack_rows())
    alerts = detect_anomalies(events)
    flagged_ips = {alert["ip"] for alert in alerts}

    assert "203.0.113.45" in flagged_ips

    attack_alert = next(alert for alert in alerts if alert["ip"] == "203.0.113.45")
    assert ALERT_KEYS <= attack_alert.keys()
    assert attack_alert["source"] == "ML"
    assert attack_alert["mitre"] is None
    assert attack_alert["severity"] in {"Low", "Medium", "High", "Critical"}
    assert attack_alert["count"] == 41
    assert len(attack_alert["event_indices"]) == 41
    assert isinstance(attack_alert["anomaly_score"], float)
    assert attack_alert["reason"].startswith("Unusually")
    assert any(
        phrase in attack_alert["reason"]
        for phrase in ("event volume", "failed logins", "distinct ports", "off-hours")
    )


def test_detection_is_deterministic() -> None:
    events = make_events(_normal_rows() + _attack_rows())
    first = detect_anomalies(events)
    second = detect_anomalies(events)

    assert [(alert["ip"], alert["anomaly_score"]) for alert in first] == [
        (alert["ip"], alert["anomaly_score"]) for alert in second
    ]


def test_too_few_ips_returns_no_alerts() -> None:
    events = make_events(_normal_rows()[:18])  # 3 IPs only
    assert build_features(events).shape[0] == 3
    assert detect_anomalies(events) == []


def test_empty_events_return_no_alerts() -> None:
    events = make_events([])
    features = build_features(events)

    assert features.empty
    assert detect_anomalies(events) == []
