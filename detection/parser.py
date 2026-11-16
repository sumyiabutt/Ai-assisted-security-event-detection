"""Load, validate and summarise CSV security-event logs.

The parser is the only module that looks at untrusted input. It never raises
for a single bad row: invalid rows are collected with a line number and a
human-readable reason so the rest of the pipeline can keep working.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import ipaddress

import pandas as pd

REQUIRED_COLUMNS: tuple[str, ...] = (
    "timestamp",
    "ip",
    "user",
    "event",
    "status",
    "port",
    "bytes",
)
OPTIONAL_COLUMNS: tuple[str, ...] = ("label",)

VALID_EVENTS: frozenset[str] = frozenset({"login", "web", "conn"})
VALID_STATUSES: frozenset[str] = frozenset({"success", "fail", "ok", "denied"})

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

VALID_COLUMNS = ["line_number", *REQUIRED_COLUMNS, "label"]
INVALID_COLUMNS = ["line_number", "reason", *REQUIRED_COLUMNS, "label"]


class ParseError(ValueError):
    """Raised when the file as a whole cannot be analysed."""


@dataclass
class ParseResult:
    """Valid rows, rejected rows and summary statistics for one CSV file."""

    valid: pd.DataFrame
    invalid: pd.DataFrame
    stats: dict[str, Any]


def _cell(row: pd.Series, column: str) -> str:
    """Return a stripped cell value ('' for missing or NaN values)."""
    if column not in row.index:
        return ""
    value = row[column]
    if pd.isna(value):
        return ""
    return str(value).strip()


def load_csv(path: str | Path) -> pd.DataFrame:
    """Read a CSV file as raw strings and check that required columns exist."""
    path = Path(path)
    if not path.exists():
        raise ParseError(f"File not found: {path}")

    try:
        raw = pd.read_csv(
            path,
            dtype=str,
            keep_default_na=False,
            skip_blank_lines=False,
        )
    except pd.errors.EmptyDataError as exc:
        raise ParseError("The CSV file is empty (no header row found).") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise ParseError(f"Could not read {path}: {exc}") from exc

    raw.columns = [str(column).strip().lower() for column in raw.columns]
    missing = [column for column in REQUIRED_COLUMNS if column not in raw.columns]
    if missing:
        raise ParseError("Missing required column(s): " + ", ".join(missing))
    return raw


def _clean_row(values: dict[str, str]) -> tuple[dict[str, Any] | None, list[str]]:
    """Validate one raw row and return a typed record or a list of problems."""
    problems: list[str] = []

    timestamp: pd.Timestamp | None = None
    if not values["timestamp"]:
        problems.append("missing timestamp")
    else:
        parsed = pd.to_datetime(values["timestamp"], format=TIMESTAMP_FORMAT, errors="coerce")
        if pd.isna(parsed):
            problems.append(
                f"invalid timestamp '{values['timestamp']}' (expected YYYY-MM-DD HH:MM:SS)"
            )
        else:
            timestamp = parsed

    ip: str | None = None
    if not values["ip"]:
        problems.append("missing ip")
    else:
        try:
            ip = str(ipaddress.ip_address(values["ip"]))
        except ValueError:
            problems.append(f"invalid IP address '{values['ip']}'")

    user = values["user"]
    if not user:
        problems.append("missing user")

    event = values["event"].lower()
    if not event:
        problems.append("missing event")
    elif event not in VALID_EVENTS:
        problems.append(f"invalid event '{values['event']}' (expected login, web or conn)")

    status = values["status"].lower()
    if not status:
        problems.append("missing status")
    elif status not in VALID_STATUSES:
        problems.append(
            f"invalid status '{values['status']}' (expected success, fail, ok or denied)"
        )

    port: int | None = None
    if not values["port"]:
        problems.append("missing port")
    else:
        try:
            port = int(values["port"])
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            problems.append(f"invalid port '{values['port']}' (expected 1-65535)")

    size: int | None = None
    if not values["bytes"]:
        problems.append("missing bytes")
    else:
        try:
            size = int(values["bytes"])
            if size < 0:
                raise ValueError
        except ValueError:
            problems.append(f"invalid bytes '{values['bytes']}' (expected a non-negative integer)")

    if problems:
        return None, problems

    # Any label other than "1" is treated as benign. The label is ground truth
    # only; detection never reads it.
    label = 1 if values.get("label", "") == "1" else 0

    return (
        {
            "timestamp": timestamp,
            "ip": ip,
            "user": user,
            "event": event,
            "status": status,
            "port": port,
            "bytes": size,
            "label": label,
        },
        [],
    )


def _build_stats(valid: pd.DataFrame, total_rows: int, invalid_rows: int) -> dict[str, Any]:
    """Compute the summary statistics reported by the dashboard."""
    login_events = int((valid["event"] == "login").sum())
    failed_logins = int(((valid["event"] == "login") & (valid["status"] == "fail")).sum())

    time_start = None
    time_end = None
    if not valid.empty:
        time_start = valid["timestamp"].min().strftime(TIMESTAMP_FORMAT)
        time_end = valid["timestamp"].max().strftime(TIMESTAMP_FORMAT)

    return {
        "total_rows": total_rows,
        "valid_rows": int(len(valid)),
        "invalid_rows": invalid_rows,
        "unique_ips": int(valid["ip"].nunique()),
        "unique_users": int(valid["user"].nunique()),
        "time_start": time_start,
        "time_end": time_end,
        "login_events": login_events,
        "failed_logins": failed_logins,
        # Share of login events that failed. Other event types are excluded.
        "failure_rate": (failed_logins / login_events) if login_events else 0.0,
    }


def parse_logs(path: str | Path) -> ParseResult:
    """Parse a log file and return valid rows, invalid rows and statistics.

    Line numbers are 1-based and include the header, so the first data row is
    line 2. Blank lines are ignored.
    """
    raw = load_csv(path)

    records: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    total_rows = 0

    for position, row in raw.iterrows():
        values = {column: _cell(row, column) for column in (*REQUIRED_COLUMNS, "label")}
        if not any(values.values()):
            continue  # blank line

        total_rows += 1
        line_number = int(position) + 2  # header is line 1

        record, problems = _clean_row(values)
        if problems:
            rejected.append(
                {
                    "line_number": line_number,
                    "reason": "; ".join(problems),
                    **{column: values[column] for column in (*REQUIRED_COLUMNS, "label")},
                }
            )
        else:
            record["line_number"] = line_number
            records.append(record)

    valid = pd.DataFrame(records, columns=VALID_COLUMNS).reset_index(drop=True)
    valid["timestamp"] = pd.to_datetime(valid["timestamp"], format=TIMESTAMP_FORMAT)
    for column in ("line_number", "port", "bytes", "label"):
        valid[column] = valid[column].astype("int64")

    invalid = pd.DataFrame(rejected, columns=INVALID_COLUMNS)

    stats = _build_stats(valid, total_rows=total_rows, invalid_rows=len(invalid))
    return ParseResult(valid=valid, invalid=invalid, stats=stats)
