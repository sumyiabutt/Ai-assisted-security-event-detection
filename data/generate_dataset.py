"""Generate the seeded synthetic dataset used by CyberFox.

The data is entirely fictional. Internal addresses are RFC 1918 addresses,
external addresses come from the documentation ranges (RFC 5737), and the
usernames are invented. Every row carries a ``label`` column:

    1 = the row belongs to an injected attack scenario
    0 = benign background traffic

The generator is seeded, so the same command always produces the same file.
Synthetic data is used only to exercise the detection pipeline; it does not
demonstrate real-world detection performance.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
import random

import pandas as pd

SEED = 42
TOTAL_ROWS = 2000
START = datetime(2026, 3, 1, 0, 0, 0)
DAYS = 3

COLUMNS = ["timestamp", "ip", "user", "event", "status", "port", "bytes", "label"]

# 24 internal client addresses. Keeping the port sets small means benign hosts
# never look like port scanners.
INTERNAL_IPS = [f"192.168.1.{last_octet}" for last_octet in range(10, 34)]
USERS = [
    "ali",
    "sara",
    "ahmed",
    "fatima",
    "bilal",
    "hina",
    "usman",
    "zara",
    "kamran",
    "maira",
    "hamza",
    "ayesha",
]
SERVICE_PORTS = [22, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080]

# Normal activity happens between 07:00 and 22:59; peaks mirror a workday.
BUSINESS_HOURS = list(range(7, 23))
HOUR_WEIGHTS = [2, 3, 5, 7, 6, 4, 3, 5, 7, 7, 5, 4, 3, 2, 1, 1]

OUTPUT_PATH = Path(__file__).resolve().parent / "sample_logs.csv"


def _row(
    timestamp: datetime,
    ip: str,
    user: str,
    event: str,
    status: str,
    port: int,
    size: int,
    label: int,
) -> dict[str, object]:
    """Build one dataset record with the exact CSV column names."""
    return {
        "timestamp": timestamp,
        "ip": ip,
        "user": user,
        "event": event,
        "status": status,
        "port": port,
        "bytes": size,
        "label": label,
    }


def _business_timestamp(rng: random.Random) -> datetime:
    """Return a random timestamp inside business hours on one of the 3 days."""
    day = rng.randrange(DAYS)
    hour = rng.choices(BUSINESS_HOURS, weights=HOUR_WEIGHTS, k=1)[0]
    return START + timedelta(
        days=day,
        hours=hour,
        minutes=rng.randrange(60),
        seconds=rng.randrange(60),
    )


def _normal_rows(rng: random.Random, count: int) -> list[dict[str, object]]:
    """Generate benign login, web and connection traffic."""
    ports_by_ip = {ip: rng.sample(SERVICE_PORTS, k=3) for ip in INTERNAL_IPS}
    failed_login_times: dict[str, list[datetime]] = defaultdict(list)
    rows: list[dict[str, object]] = []

    while len(rows) < count:
        ip = rng.choice(INTERNAL_IPS)
        user = rng.choice(USERS)
        timestamp = _business_timestamp(rng)
        event = rng.choices(["login", "web", "conn"], weights=[35, 40, 25], k=1)[0]

        if event == "login":
            status = "fail" if rng.random() < 0.04 else "success"
            # A benign user occasionally mistypes a password, but never fast
            # enough to look like a brute-force burst.
            if status == "fail" and any(
                abs((timestamp - previous).total_seconds()) < 20 * 60
                for previous in failed_login_times[ip]
            ):
                status = "success"
            if status == "fail":
                failed_login_times[ip].append(timestamp)
            port, size = 443, rng.randint(150, 900)
        elif event == "web":
            status = "denied" if rng.random() < 0.03 else "ok"
            port = rng.choice([80, 443])
            size = rng.randint(300, 8000)
        else:
            status = "denied" if rng.random() < 0.08 else "ok"
            port = rng.choice(ports_by_ip[ip])
            size = rng.randint(40, 400)

        rows.append(_row(timestamp, ip, user, event, status, port, size, 0))

    return rows


def _brute_force_with_success() -> list[dict[str, object]]:
    """Eight failed logins in under 3 minutes followed by a success."""
    ip = "203.0.113.45"
    start = datetime(2026, 3, 2, 10, 10, 0)
    rows = [
        _row(start + timedelta(seconds=25 * index), ip, "admin", "login", "fail", 443, 180, 1)
        for index in range(8)
    ]
    rows.append(_row(start + timedelta(minutes=3, seconds=20), ip, "admin", "login", "success", 443, 640, 1))
    return rows


def _brute_force_burst() -> list[dict[str, object]]:
    """Six failed logins against several accounts inside 3 minutes."""
    ip = "198.51.100.23"
    start = datetime(2026, 3, 2, 14, 0, 0)
    targets = ["guest", "root", "admin", "test", "oracle", "admin"]
    return [
        _row(start + timedelta(seconds=30 * index), ip, targets[index], "login", "fail", 443, 150, 1)
        for index in range(len(targets))
    ]


def _port_scan() -> list[dict[str, object]]:
    """Twenty-five distinct destination ports contacted in 75 seconds."""
    ip = "203.0.113.77"
    start = datetime(2026, 3, 2, 12, 0, 0)
    ports = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        135,
        139,
        143,
        443,
        445,
        993,
        995,
        1433,
        1521,
        2049,
        3306,
        3389,
        5432,
        5900,
        6379,
        8080,
        8443,
        9200,
    ]
    return [
        _row(start + timedelta(seconds=3 * index), ip, "unknown", "conn", "denied", port, 40, 1)
        for index, port in enumerate(ports)
    ]


def _request_flood() -> list[dict[str, object]]:
    """Seventy-five web requests inside a single minute."""
    ip = "198.51.100.99"
    start = datetime(2026, 3, 3, 20, 30, 0)
    return [
        _row(start + timedelta(seconds=round(0.7 * index, 3)), ip, "unknown", "web", "ok", 80, 120, 1)
        for index in range(75)
    ]


def _off_hours_logins() -> list[dict[str, object]]:
    """Two successful logins in the middle of the night."""
    ip = "203.0.113.150"
    return [
        _row(datetime(2026, 3, 3, 2, 15, 0), ip, "backup", "login", "success", 443, 420, 1),
        _row(datetime(2026, 3, 3, 3, 40, 0), ip, "admin", "login", "success", 443, 380, 1),
    ]


def build_dataset(seed: int = SEED, total_rows: int = TOTAL_ROWS) -> pd.DataFrame:
    """Create the complete labelled dataset as a DataFrame."""
    rng = random.Random(seed)
    attack_rows = [
        *_brute_force_with_success(),
        *_brute_force_burst(),
        *_port_scan(),
        *_request_flood(),
        *_off_hours_logins(),
    ]
    normal_rows = _normal_rows(rng, total_rows - len(attack_rows))

    dataset = pd.DataFrame(normal_rows + attack_rows, columns=COLUMNS)
    dataset["timestamp"] = pd.to_datetime(dataset["timestamp"])
    return dataset.sort_values(
        ["timestamp", "ip", "event"], kind="stable"
    ).reset_index(drop=True)


def main() -> None:
    """Write the dataset to data/sample_logs.csv and print a short summary."""
    dataset = build_dataset()
    dataset.to_csv(OUTPUT_PATH, index=False, date_format="%Y-%m-%d %H:%M:%S")

    attack_rows = int(dataset["label"].sum())
    print(f"Synthetic dataset written to: {OUTPUT_PATH}")
    print(f"Rows: {len(dataset)} | benign: {len(dataset) - attack_rows} | attack: {attack_rows}")
    print("Injected scenarios:")
    print("  - brute force with a follow-up success (203.0.113.45)")
    print("  - brute-force burst, no success (198.51.100.23)")
    print("  - port scan, 25 ports (203.0.113.77)")
    print("  - request flood, 75 requests/minute (198.51.100.99)")
    print("  - off-hours successful logins (203.0.113.150)")


if __name__ == "__main__":
    main()
