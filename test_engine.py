"""Tests for merging rule and ML detections and flagging events."""

from datetime import datetime, timedelta

import pandas as pd

from detection.engine import run_engine
from detection.rules import SEVERITY_ORDER

COLUMNS = ["timestamp", "ip", "user", "event", "status", "port", "bytes", "label"]


def make_events(rows: list[tuple]) -> pd.DataFrame:
    frame = pd.DataFrame(
        rows,
        columns=["timestamp", "ip", "user", "event", "status", "port"],
    )
    frame["bytes"] = 100
    frame["label"] = 0
    frame["timestamp"] = pd.to_datetime(frame["timestamp"])
    return frame


def build_scenario() -> tuple[pd.DataFrame, list[int], list[int]]:
    """Return events, brute-force indices and port-scan indices."""
    rows: list[tuple] = []
    base = datetime(2026, 3, 2, 10, 0, 0)

    for index in range(5):
        rows.append(
            (
                (base + timedelta(seconds=30 * index)).strftime("%Y-%m-%d %H:%M:%S"),
                "10.0.0.9",
                "admin",
                "login",
                "fail",
                443,
            )
        )
    rows.append(("2026-03-02 10:03:00", "10.0.0.9", "admin", "login", "success", 443))
    brute_indices = list(range(len(rows)))

    scan_start = len(rows)
    for port in range(1, 16):
        rows.append(("2026-03-02 12:00:00", "10.0.0.7", "unknown", "conn", "denied", port))
    scan_indices = list(range(scan_start, len(rows)))

    for host in range(10, 16):
        for event_index in range(5):
            timestamp = base + timedelta(minutes=event_index * 7)
            rows.append(
                (
                    timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    f"10.0.0.{host}",
                    "user",
                    "login" if event_index == 0 else "web",
                    "success" if event_index == 0 else "ok",
                    443 if event_index == 0 else 80,
                )
            )

    return make_events(rows), brute_indices, scan_indices


def test_engine_merges_alerts_and_flags_events() -> None:
    events, brute_indices, scan_indices = build_scenario()
    result = run_engine(events)

    alerts = result["alerts"]
    summary = result["summary"]
    flagged = result["events"]

    assert len(flagged) == len(events)
    assert {"rule_flag", "ml_flag", "suspicious", "alert_source"} <= set(flagged.columns)

    assert summary["total_alerts"] == len(alerts)
    assert summary["total_alerts"] == summary["rule_alerts"] + summary["ml_alerts"]
    assert summary["rule_alerts"] >= 2
    assert summary["ml_alerts"] >= 1
    assert summary["suspicious_events"] == int(flagged["suspicious"].sum())
    assert sum(summary["severity_counts"].values()) == summary["total_alerts"]

    assert {alert["source"] for alert in alerts} <= {"Rule", "ML"}
    assert flagged.loc[brute_indices, "suspicious"].all()
    assert flagged.loc[scan_indices, "suspicious"].all()
    assert flagged.loc[brute_indices, "rule_flag"].all()
    assert set(flagged["alert_source"].unique()) <= {"Rule", "ML", "Rule+ML", ""}


def test_alerts_are_sorted_by_severity() -> None:
    events, _, _ = build_scenario()
    alerts = run_engine(events)["alerts"]

    scores = [SEVERITY_ORDER[alert["severity"]] for alert in alerts]
    assert scores == sorted(scores, reverse=True)


def test_empty_events_produce_empty_result() -> None:
    empty = pd.DataFrame(columns=COLUMNS)
    empty["timestamp"] = pd.to_datetime(empty["timestamp"])

    result = run_engine(empty)

    assert result["alerts"] == []
    assert len(result["events"]) == 0
    assert result["summary"] == {
        "total_events": 0,
        "suspicious_events": 0,
        "total_alerts": 0,
        "rule_alerts": 0,
        "ml_alerts": 0,
        "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
    }
