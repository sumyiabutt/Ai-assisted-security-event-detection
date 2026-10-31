"""Score rule-based, ML-based and combined detection against ground truth.

An event counts as detected when it is covered by at least one alert:

* a rule alert covers the exact events that formed the pattern;
* an ML alert covers every event from the anomalous source IP.

Run from the ``cyberfox`` directory:

    python -m detection.evaluate
    python -m detection.evaluate --input data/sample_logs.csv --contamination 0.2
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

try:  # works both as ``python -m detection.evaluate`` and as a script
    from .ml_model import DEFAULT_CONTAMINATION, detect_anomalies
    from .parser import ParseError, ParseResult, parse_logs
    from .rules import Alert, run_rules
except ImportError:  # pragma: no cover - script fallback
    from ml_model import DEFAULT_CONTAMINATION, detect_anomalies
    from parser import ParseError, ParseResult, parse_logs
    from rules import Alert, run_rules

DEFAULT_INPUT = Path(__file__).resolve().parent.parent / "data" / "sample_logs.csv"


def prediction_mask(events: pd.DataFrame, alerts: list[Alert]) -> pd.Series:
    """Return a boolean Series marking every event covered by the alerts."""
    mask = pd.Series(False, index=events.index)
    for alert in alerts:
        if alert["source"] == "ML":
            mask |= events["ip"].eq(alert["ip"])
        else:
            indices = [index for index in alert["event_indices"] if index in events.index]
            if indices:
                mask.loc[indices] = True
    return mask


def compute_metrics(truth: pd.Series, predicted: pd.Series) -> dict[str, float]:
    """Compute TP/FP/FN and precision, recall and F1 for boolean Series."""
    true_positive = int((truth & predicted).sum())
    false_positive = int((~truth & predicted).sum())
    false_negative = int((truth & ~predicted).sum())

    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    return {
        "TP": true_positive,
        "FP": false_positive,
        "FN": false_negative,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def _print_row(name: str, metrics: dict[str, float]) -> None:
    print(
        f"{name:<9}"
        f"{metrics['TP']:>6}"
        f"{metrics['FP']:>6}"
        f"{metrics['FN']:>6}"
        f"{metrics['precision']:>11.3f}"
        f"{metrics['recall']:>8.3f}"
        f"{metrics['f1']:>7.3f}"
    )


def evaluate(result: ParseResult, contamination: float) -> None:
    """Print precision, recall and F1 for rules, ML and the combined system."""
    events = result.valid
    if events.empty:
        print("No valid events to evaluate.")
        return
    if "label" not in events.columns:
        print("No 'label' column found; ground-truth evaluation is not possible.")
        return

    truth = events["label"].astype(bool)
    rule_alerts = run_rules(events)
    ml_alerts = detect_anomalies(events, contamination=contamination)
    combined_alerts = [*rule_alerts, *ml_alerts]

    rule_mask = prediction_mask(events, rule_alerts)
    ml_mask = prediction_mask(events, ml_alerts)
    combined_mask = prediction_mask(events, combined_alerts)

    print("CyberFox - detection evaluation")
    print(f"Events: {len(events)} | malicious: {int(truth.sum())} | benign: {int((~truth).sum())}")
    print(
        f"Alerts: rules={len(rule_alerts)}, ml={len(ml_alerts)}, "
        f"combined={len(combined_alerts)}"
    )
    print("An event is detected if any alert covers it (ML covers all events from an IP).")
    print()
    print(f"{'Approach':<9}{'TP':>6}{'FP':>6}{'FN':>6}{'Precision':>11}{'Recall':>8}{'F1':>7}")
    print("-" * 53)
    _print_row("Rules", compute_metrics(truth, rule_mask))
    _print_row("ML", compute_metrics(truth, ml_mask))
    _print_row("Combined", compute_metrics(truth, combined_mask))


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate CyberFox detections against labels.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT, help="CSV log file")
    parser.add_argument(
        "--contamination",
        type=float,
        default=DEFAULT_CONTAMINATION,
        help="Isolation Forest contamination (0-0.5)",
    )
    args = parser.parse_args()

    try:
        result = parse_logs(args.input)
    except ParseError as exc:
        print(f"ERROR: {exc}")
        return 1

    print(f"Input: {args.input}")
    print(
        f"Parsed {result.stats['total_rows']} rows: "
        f"{result.stats['valid_rows']} valid, {result.stats['invalid_rows']} invalid"
    )
    print()
    evaluate(result, args.contamination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
