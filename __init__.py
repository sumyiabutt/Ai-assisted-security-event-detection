"""CyberFox detection package: parsing, rules, anomaly detection and evaluation."""

from detection.engine import run_engine
from detection.ml_model import build_features, detect_anomalies
from detection.parser import ParseError, ParseResult, parse_logs
from detection.rules import run_rules

__all__ = [
    "ParseError",
    "ParseResult",
    "build_features",
    "detect_anomalies",
    "parse_logs",
    "run_engine",
    "run_rules",
]
