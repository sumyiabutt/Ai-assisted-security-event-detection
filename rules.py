"""Explainable, rule-based detection over validated security events.

Every function returns a list of alert dictionaries with a common schema:

    ip, user, timestamp, severity, reason, source, mitre, count, event_indices

``event_indices`` are the positional DataFrame indices of the events that
caused (or belong to) the alert. They let the engine mark suspicious events
and let the evaluator score row-level detection.
"""

from __future__ import annotations

from typing import TypedDict

import pandas as pd

SEVERITY_ORDER: dict[str, int] = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 10
PORT_SCAN_THRESHOLD = 15
FLOOD_THRESHOLD = 60
OFF_HOURS_START = 23  # 23:00
OFF_HOURS_END = 5  # 05:00 (exclusive)


class Alert(TypedDict):
    """Common alert schema shared by rule and ML detections."""

    ip: str
    user: str
    timestamp: pd.Timestamp
    severity: str
    reason: str
    source: str
    mitre: str | None
    count: int
    event_indices: list[int]


def _alert(
    *,
    ip: str,
    user: str,
    timestamp: pd.Timestamp,
    severity: str,
    reason: str,
    mitre: str,
    event_indices: list[int],
) -> Alert:
    return {
        "ip": ip,
        "user": user,
        "timestamp": timestamp,
        "severity": severity,
        "reason": reason,
        "source": "Rule",
        "mitre": mitre,
        "count": len(event_indices),
        "event_indices": event_indices,
    }


def detect_brute_force(
    events: pd.DataFrame,
    threshold: int = BRUTE_FORCE_THRESHOLD,
    window_minutes: int = BRUTE_FORCE_WINDOW_MINUTES,
) -> list[Alert]:
    """Flag ``threshold`` failed logins from one IP inside one time window.

    The rule walks each source IP's failed attempts in time order. When a
    burst is found the scan continues after the burst so the same group is not
    reported twice. A successful login shortly after the burst raises the
    severity to Critical (the attempt may have worked).
    """
    failed = events[(events["event"] == "login") & (events["status"] == "fail")]
    alerts: list[Alert] = []
    window = pd.Timedelta(minutes=window_minutes)

    for ip, group in failed.groupby("ip"):
        attempts = group.sort_values("timestamp")
        times = attempts["timestamp"].tolist()
        indices = attempts.index.tolist()
        start = 0

        while start < len(times):
            end = start
            while end + 1 < len(times) and times[end + 1] - times[start] <= window:
                end += 1

            count = end - start + 1
            if count >= threshold:
                burst_start, burst_end = times[start], times[end]
                burst_indices = indices[start:end + 1]

                followups = events[
                    (events["ip"] == ip)
                    & (events["event"] == "login")
                    & (events["status"] == "success")
                    & (events["timestamp"] >= burst_start)
                    & (events["timestamp"] <= burst_end + window)
                ]

                targets = attempts.iloc[start:end + 1]["user"]
                primary_target = targets.mode().iloc[0] if not targets.empty else "unknown"

                reason = (
                    f"{count} failed logins from {ip} within {window_minutes} minutes"
                )
                if not followups.empty:
                    reason += " followed by a successful login"
                    severity = "Critical"
                else:
                    severity = "High"

                alert_indices = burst_indices + followups.index.tolist()
                alerts.append(
                    _alert(
                        ip=str(ip),
                        user=str(primary_target),
                        timestamp=burst_start,
                        severity=severity,
                        reason=reason,
                        mitre="T1110",
                        event_indices=alert_indices,
                    )
                )
                start = end + 1
            else:
                start += 1

    return alerts


def detect_port_scan(events: pd.DataFrame, threshold: int = PORT_SCAN_THRESHOLD) -> list[Alert]:
    """Flag an IP that contacts ``threshold`` or more distinct ports."""
    connections = events[events["event"] == "conn"]
    alerts: list[Alert] = []

    for ip, group in connections.groupby("ip"):
        distinct_ports = int(group["port"].nunique())
        if distinct_ports < threshold:
            continue

        alerts.append(
            _alert(
                ip=str(ip),
                user="multiple",
                timestamp=group["timestamp"].min(),
                severity="High",
                reason=f"{distinct_ports} distinct ports contacted by {ip} (possible port scan)",
                mitre="T1046",
                event_indices=group.index.tolist(),
            )
        )

    return alerts


def detect_flood(events: pd.DataFrame, threshold: int = FLOOD_THRESHOLD) -> list[Alert]:
    """Flag ``threshold`` or more requests from one IP inside a single minute."""
    alerts: list[Alert] = []

    for ip, group in events.groupby("ip"):
        buckets = group.groupby(group["timestamp"].dt.floor("min"))
        for minute, bucket in buckets:
            if len(bucket) < threshold:
                continue

            alerts.append(
                _alert(
                    ip=str(ip),
                    user="multiple",
                    timestamp=minute,
                    severity="High",
                    reason=f"{len(bucket)} requests from {ip} within one minute",
                    mitre="T1498",
                    event_indices=bucket.index.tolist(),
                )
            )

    return alerts


def detect_off_hours_logins(events: pd.DataFrame) -> list[Alert]:
    """Flag successful logins between 23:00 and 05:00."""
    logins = events[(events["event"] == "login") & (events["status"] == "success")]
    if logins.empty:
        return []

    hours = logins["timestamp"].dt.hour
    off_hours = logins[(hours >= OFF_HOURS_START) | (hours < OFF_HOURS_END)]

    alerts: list[Alert] = []
    for index, row in off_hours.iterrows():
        alerts.append(
            _alert(
                ip=str(row["ip"]),
                user=str(row["user"]),
                timestamp=row["timestamp"],
                severity="Medium",
                reason=(
                    f"Successful login for '{row['user']}' at "
                    f"{row['timestamp'].strftime('%H:%M')} outside business hours "
                    f"({OFF_HOURS_START:02d}:00-{OFF_HOURS_END:02d}:00)"
                ),
                mitre="T1078",
                event_indices=[int(index)],
            )
        )

    return alerts


def run_rules(events: pd.DataFrame) -> list[Alert]:
    """Run every rule and return the combined alert list."""
    if events.empty:
        return []
    return [
        *detect_brute_force(events),
        *detect_port_scan(events),
        *detect_flood(events),
        *detect_off_hours_logins(events),
    ]
