"""Combine rule-based and ML detections into one result set."""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

from detection.ml_model import DEFAULT_CONTAMINATION, detect_anomalies
from detection.rules import SEVERITY_ORDER, Alert, run_rules


def _sort_key(alert: Alert) -> tuple[int, pd.Timestamp, str]:
    """Sort by severity (most severe first), then by time, then by IP."""
    return (
        -SEVERITY_ORDER.get(alert["severity"], 0),
        alert["timestamp"],
        alert["ip"],
    )


def run_engine(
    events: pd.DataFrame,
    contamination: float = DEFAULT_CONTAMINATION,
) -> dict[str, Any]:
    """Run rules and ML, merge the alerts and flag suspicious events.

    Returns a dict with:
        alerts  - merged alerts, most severe first
        events  - a copy of the input with rule_flag, ml_flag, suspicious and
                  alert_source columns
        summary - counts used by the dashboard and reports
    """
    rule_alerts = run_rules(events)
    ml_alerts = detect_anomalies(events, contamination=contamination)
    alerts = sorted([*rule_alerts, *ml_alerts], key=_sort_key)

    rule_mask = pd.Series(False, index=events.index)
    for alert in rule_alerts:
        indices = [index for index in alert["event_indices"] if index in events.index]
        if indices:
            rule_mask.loc[indices] = True

    flagged_ips = [alert["ip"] for alert in ml_alerts]
    ml_mask = events["ip"].isin(flagged_ips) if flagged_ips else pd.Series(False, index=events.index)

    flagged = events.copy()
    flagged["rule_flag"] = rule_mask
    flagged["ml_flag"] = ml_mask
    flagged["suspicious"] = rule_mask | ml_mask
    flagged["alert_source"] = np.select(
        [rule_mask & ml_mask, rule_mask, ml_mask],
        ["Rule+ML", "Rule", "ML"],
        default="",
    )

    severity_counts = {
        severity: sum(1 for alert in alerts if alert["severity"] == severity)
        for severity in ("Critical", "High", "Medium", "Low")
    }

    summary = {
        "total_events": int(len(events)),
        "suspicious_events": int(flagged["suspicious"].sum()),
        "total_alerts": len(alerts),
        "rule_alerts": len(rule_alerts),
        "ml_alerts": len(ml_alerts),
        "severity_counts": severity_counts,
    }

    return {"alerts": alerts, "events": flagged, "summary": summary}
