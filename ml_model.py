"""Unsupervised anomaly detection with Isolation Forest.

The model works per source IP, not per event. Five behavioural features are
computed for every IP and the Isolation Forest learns which addresses look
different from the rest of the batch. Because the model is unsupervised, the
severity is relative to the current file: it ranks each flagged IP against its
peers instead of claiming an absolute probability of compromise.
"""

from __future__ import annotations

import pandas as pd
from sklearn.ensemble import IsolationForest

try:  # package import (app, tests, ``python -m detection.evaluate``)
    from detection.rules import Alert
except ImportError:  # pragma: no cover - direct script fallback
    from rules import Alert

FEATURE_COLUMNS: list[str] = [
    "total_events",
    "failed_logins",
    "distinct_ports",
    "peak_requests_per_minute",
    "off_hours_logins",
]

FEATURE_LABELS: dict[str, str] = {
    "total_events": "event volume",
    "failed_logins": "failed logins",
    "distinct_ports": "distinct ports contacted",
    "peak_requests_per_minute": "peak request rate",
    "off_hours_logins": "off-hours successful logins",
}

UNITS: dict[str, str] = {"peak_requests_per_minute": "/min"}

DEFAULT_CONTAMINATION = 0.2
RANDOM_STATE = 42
MIN_IPS_FOR_MODEL = 5


def build_features(events: pd.DataFrame) -> pd.DataFrame:
    """Compute one feature row per source IP, indexed by IP address."""
    rows: list[dict[str, object]] = []

    if not events.empty:
        for ip, group in events.groupby("ip"):
            minutes = group["timestamp"].dt.floor("min")
            peak_per_minute = int(minutes.value_counts().max())

            is_login = group["event"] == "login"
            hour = group["timestamp"].dt.hour
            off_hours = (hour >= 23) | (hour < 5)

            rows.append(
                {
                    "ip": ip,
                    "total_events": int(len(group)),
                    "failed_logins": int((is_login & (group["status"] == "fail")).sum()),
                    "distinct_ports": int(group["port"].nunique()),
                    "peak_requests_per_minute": peak_per_minute,
                    "off_hours_logins": int(
                        (is_login & (group["status"] == "success") & off_hours).sum()
                    ),
                }
            )

    frame = pd.DataFrame(rows, columns=["ip", *FEATURE_COLUMNS])
    return frame.set_index("ip") if not frame.empty else pd.DataFrame(columns=FEATURE_COLUMNS)


def _severity_from_score(score: float) -> str:
    """Map a 0-100 relative anomaly score to a severity label."""
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 55:
        return "Medium"
    return "Low"


def _explain(features: pd.DataFrame, ip: str) -> str:
    """Name the feature that makes ``ip`` stand out the most (z-score).

    Features that are above the peer average are preferred because unusually
    low activity is rarely by itself a security signal. When every feature is
    below average the largest deviation is still reported.
    """
    row = features.loc[ip]
    z_scores: dict[str, float] = {}

    for column in FEATURE_COLUMNS:
        mean = float(features[column].mean())
        std = float(features[column].std(ddof=0))
        value = float(row[column])

        if std == 0:
            # All peers share this value. Scale the difference by the peer
            # average so the most abnormal feature is still chosen first.
            if value == mean:
                z_scores[column] = 0.0
            else:
                z_scores[column] = 10.0 * (value - mean) / max(abs(mean), 1.0)
        else:
            z_scores[column] = (value - mean) / std

    positive = {column: z for column, z in z_scores.items() if z > 0.5}
    if positive:
        best_feature = max(positive, key=positive.get)
    elif any(abs(z) > 0 for z in z_scores.values()):
        best_feature = max(z_scores, key=lambda column: abs(z_scores[column]))
    else:
        return f"The combination of features for {ip} is unusual compared with other IPs"

    value = int(row[best_feature])
    median = float(features[best_feature].median())
    unit = UNITS.get(best_feature, "")
    median_text = int(median) if median.is_integer() else round(median, 1)
    comparison = f"{value}{unit} vs median {median_text}{unit} across {len(features)} IPs"

    if value > median:
        return f"Unusually high {FEATURE_LABELS[best_feature]}: {comparison}"

    return (
        f"Atypical profile: {FEATURE_LABELS[best_feature]} is lower than peers "
        f"({comparison}); no high-risk feature stands out"
    )


def detect_anomalies(
    events: pd.DataFrame,
    contamination: float = DEFAULT_CONTAMINATION,
    random_state: int = RANDOM_STATE,
) -> list[Alert]:
    """Fit an Isolation Forest on per-IP features and alert on anomalous IPs.

    Returns an empty list when there are too few distinct IPs for the model to
    compare against.
    """
    features = build_features(events)
    if len(features) < MIN_IPS_FOR_MODEL:
        return []

    model = IsolationForest(
        n_estimators=200,
        contamination=min(max(contamination, 0.01), 0.5),
        random_state=random_state,
    )
    model.fit(features[FEATURE_COLUMNS])

    predictions = model.predict(features[FEATURE_COLUMNS])
    # score_samples returns higher values for normal points; negate so that a
    # larger number means "more anomalous".
    raw_scores = pd.Series(
        -model.score_samples(features[FEATURE_COLUMNS]),
        index=features.index,
    )

    span = float(raw_scores.max() - raw_scores.min())
    if span > 0:
        relative_scores = (raw_scores - raw_scores.min()) / span * 100.0
    else:
        relative_scores = pd.Series(0.0, index=features.index)

    alerts: list[Alert] = []
    for ip in features.index[predictions == -1]:
        group = events[events["ip"] == ip]
        score = float(raw_scores.loc[ip])
        relative = float(relative_scores.loc[ip])

        alerts.append(
            {
                "ip": str(ip),
                "user": "multiple",
                "timestamp": group["timestamp"].min(),
                "severity": _severity_from_score(relative),
                "reason": _explain(features, ip),
                "source": "ML",
                "mitre": None,
                "count": int(len(group)),
                "event_indices": group.index.tolist(),
                "anomaly_score": round(score, 4),
                "relative_score": round(relative, 1),
            }
        )

    return alerts
