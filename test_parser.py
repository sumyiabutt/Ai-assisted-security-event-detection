"""Tests for CSV loading, row validation and parsing statistics."""

from pathlib import Path

import pytest

from detection.parser import ParseError, parse_logs

HEADER = "timestamp,ip,user,event,status,port,bytes,label\n"
VALID_ROW = "2026-03-01 09:00:00,192.168.1.10,ali,login,success,443,500,0\n"


def write_csv(tmp_path: Path, body: str, name: str = "logs.csv") -> Path:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")
    return path


def test_missing_file_raises_parse_error(tmp_path: Path) -> None:
    with pytest.raises(ParseError, match="File not found"):
        parse_logs(tmp_path / "missing.csv")


def test_empty_file_raises_parse_error(tmp_path: Path) -> None:
    path = write_csv(tmp_path, "")
    with pytest.raises(ParseError, match="empty"):
        parse_logs(path)


def test_missing_required_column_is_reported(tmp_path: Path) -> None:
    path = write_csv(tmp_path, "timestamp,ip\n2026-03-01 09:00:00,192.168.1.10\n")
    with pytest.raises(ParseError, match="user"):
        parse_logs(path)


def test_valid_rows_and_statistics(tmp_path: Path) -> None:
    body = HEADER + (
        VALID_ROW
        + "2026-03-01 09:05:00,192.168.1.10,ali,login,fail,443,400,0\n"
        + "2026-03-01 10:00:00,192.168.1.11,sara,web,ok,80,1200,0\n"
    )
    result = parse_logs(write_csv(tmp_path, body))

    assert len(result.valid) == 3
    assert result.invalid.empty
    assert result.valid["line_number"].tolist() == [2, 3, 4]

    stats = result.stats
    assert stats["total_rows"] == 3
    assert stats["valid_rows"] == 3
    assert stats["invalid_rows"] == 0
    assert stats["unique_ips"] == 2
    assert stats["unique_users"] == 2
    assert stats["time_start"] == "2026-03-01 09:00:00"
    assert stats["time_end"] == "2026-03-01 10:00:00"
    assert stats["login_events"] == 2
    assert stats["failed_logins"] == 1
    assert stats["failure_rate"] == pytest.approx(0.5)


def test_invalid_rows_are_reported_with_line_numbers(tmp_path: Path) -> None:
    body = HEADER + (
        "not-a-time,192.168.1.10,ali,login,fail,443,100,0\n"          # line 2
        "2026-03-01 09:00:00,999.1.2.3,ali,login,fail,443,100,0\n"    # line 3
        "2026-03-01 09:00:00,192.168.1.10,ali,login,fail,70000,100,0\n"  # line 4
        "2026-03-01 09:00:00,192.168.1.10,,login,fail,443,100,0\n"    # line 5
        "2026-03-01 09:00:00,192.168.1.10,ali,login,pending,443,100,0\n"  # line 6
        "2026-03-01 09:00:00,192.168.1.10,ali,dns,ok,443,100,0\n"     # line 7
        "2026-03-01 09:00:00,192.168.1.11,sara,login,success,443,100,0\n"  # line 8
    )
    result = parse_logs(write_csv(tmp_path, body))

    assert len(result.valid) == 1
    assert len(result.invalid) == 6
    assert result.invalid["line_number"].tolist() == [2, 3, 4, 5, 6, 7]
    assert result.stats["total_rows"] == 7
    assert result.stats["valid_rows"] == 1
    assert result.stats["invalid_rows"] == 6

    reasons = result.invalid["reason"].tolist()
    assert "invalid timestamp" in reasons[0]
    assert "invalid IP address" in reasons[1]
    assert "invalid port" in reasons[2]
    assert "missing user" in reasons[3]
    assert "invalid status" in reasons[4]
    assert "invalid event" in reasons[5]


def test_blank_lines_are_ignored(tmp_path: Path) -> None:
    body = HEADER + "\n" + VALID_ROW
    result = parse_logs(write_csv(tmp_path, body))

    assert len(result.valid) == 1
    assert result.invalid.empty
    assert result.stats["total_rows"] == 1
    assert result.valid["line_number"].tolist() == [3]


def test_header_only_file_is_valid(tmp_path: Path) -> None:
    result = parse_logs(write_csv(tmp_path, HEADER))

    assert result.valid.empty
    assert result.invalid.empty
    assert result.stats["total_rows"] == 0
    assert result.stats["failure_rate"] == 0.0


def test_label_column_is_optional(tmp_path: Path) -> None:
    body = "timestamp,ip,user,event,status,port,bytes\n" + (
        "2026-03-01 09:00:00,192.168.1.10,ali,login,success,443,500\n"
    )
    result = parse_logs(write_csv(tmp_path, body))

    assert len(result.valid) == 1
    assert int(result.valid.loc[0, "label"]) == 0


def test_ipv6_and_lower_case_values_are_normalised(tmp_path: Path) -> None:
    body = HEADER + (
        "2026-03-01 09:00:00,2001:db8::1,ali,LOGIN,FAIL,443,500,1\n"
    )
    result = parse_logs(write_csv(tmp_path, body))

    row = result.valid.iloc[0]
    assert row["ip"] == "2001:db8::1"
    assert row["event"] == "login"
    assert row["status"] == "fail"
    assert int(row["label"]) == 1
