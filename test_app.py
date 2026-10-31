"""Route tests for the CyberFox web app using the Flask test client."""

from __future__ import annotations

import io
import re
import sqlite3
from pathlib import Path

import pytest

from app import create_app

TOKEN_RE = re.compile(r'name="token" value="([^"]+)"')

CSV_HEADER = "timestamp,ip,user,event,status,port,bytes\n"
UPLOAD_CSV = CSV_HEADER + (
    "2026-03-01 10:00:00,10.0.0.5,alice,login,fail,22,120\n"
    "2026-03-01 10:01:00,10.0.0.5,alice,login,fail,22,120\n"
    "2026-03-01 10:02:00,10.0.0.6,bob,login,fail,22,120\n"
    "2026-03-01 10:03:00,10.0.0.7,carol,web,ok,80,900\n"
    "2026-03-01 10:04:00,10.0.0.8,dave,conn,ok,443,500\n"
    "2026-03-01 10:05:00,10.0.0.9,erin,web,ok,80,700\n"
    "2026-03-01 10:06:00,not-an-ip,frank,login,success,22,120\n"
)


@pytest.fixture()
def app(tmp_path: Path):
    application = create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-key",
            "DATABASE": str(tmp_path / "test.db"),
            "UPLOAD_DIR": str(tmp_path / "uploads"),
            "SAMPLE_PATH": str(
                Path(__file__).resolve().parents[1] / "data" / "sample_logs.csv"
            ),
            "SAMPLE_ON_STARTUP": True,
        }
    )
    yield application


@pytest.fixture()
def client(app):
    return app.test_client()


def run_count(app) -> int:
    with sqlite3.connect(app.config["DATABASE"]) as connection:
        return connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0]


def upload(client, filename: str = "events.csv", content: str = UPLOAD_CSV):
    return client.post(
        "/analyze/preview",
        data={"logfile": (io.BytesIO(content.encode("utf-8")), filename)},
        content_type="multipart/form-data",
    )


def test_root_redirects_to_dashboard(client):
    response = client.get("/")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/dashboard")


def test_dashboard_loads_with_sample(client):
    response = client.get("/dashboard")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Detection dashboard" in body
    assert "Total log records" in body
    assert "Security alerts" in body
    assert "2,000" in body
    assert "sample_logs.csv" in body


def test_alerts_page_lists_engine_alerts(client):
    response = client.get("/alerts")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Security alerts" in body
    assert "203.0.113.45" in body
    assert "T1110" in body
    assert "12 shown of 12 total" in body


def test_alerts_severity_filter(client):
    response = client.get("/alerts?severity=Critical")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert body.count("pill sev-critical") == 4
    assert "pill sev-high" not in body


def test_alerts_source_filter(client):
    response = client.get("/alerts?source=ML")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert body.count("pill sev-") == 6
    assert "Unusually" in body
    assert "T1110" not in body  # rule-only technique absent from ML results


def test_alerts_search_filter(client):
    response = client.get("/alerts?q=203.0.113.45")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "203.0.113.45" in body
    assert "198.51.100.99" not in body
    assert "198.51.100.23" not in body


def test_alerts_search_with_no_results(client):
    response = client.get("/alerts?q=no-such-value")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "No alerts match these filters." in body


def test_analyze_page_offers_upload_and_sample(client):
    response = client.get("/analyze")
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Upload a CSV file" in body
    assert "Load sample dataset" in body
    assert '/sample.csv' in body


def test_sample_preview_shows_statistics(client):
    response = client.post("/analyze/preview", data={"sample": "1"})
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Validation summary" in body
    assert "first 8 valid rows" in body
    assert "Every row passed validation." in body
    assert TOKEN_RE.search(body)


def test_upload_preview_lists_invalid_rows(client):
    response = upload(client)
    body = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "events.csv" in body
    assert "invalid IP address" in body
    assert ">8<" in body  # the bad row sits on CSV line 8


def test_upload_rejects_non_csv(client):
    response = upload(client, filename="events.txt")
    follow = client.get("/analyze")

    assert response.status_code == 302
    assert "Only .csv files are supported." in follow.get_data(as_text=True)


def test_unknown_token_is_rejected(app, client):
    before = run_count(app)
    response = client.post("/analyze/run", data={"token": "no-such-file.csv"})
    follow = client.get("/analyze")

    assert response.status_code == 302
    assert "could not be found" in follow.get_data(as_text=True)
    assert run_count(app) == before


def test_path_traversal_token_is_rejected(app, client):
    before = run_count(app)
    response = client.post("/analyze/run", data={"token": "../../app.py"})
    follow = client.get("/analyze")

    assert response.status_code == 302
    assert "upload reference is not valid" in follow.get_data(as_text=True)
    assert run_count(app) == before


def test_sample_run_stores_analysis_and_redirects(app, client):
    before = run_count(app)
    preview = client.post("/analyze/preview", data={"sample": "1"})
    token = TOKEN_RE.search(preview.get_data(as_text=True)).group(1)

    response = client.post("/analyze/run", data={"token": token})
    assert response.status_code == 302

    result = client.get(response.headers["Location"])
    body = result.get_data(as_text=True)
    assert result.status_code == 200
    assert "Analysis complete" in body
    assert "Open dashboard" in body
    assert "View alerts" in body
    assert run_count(app) == before + 1


def test_uploaded_file_is_removed_after_analysis(app, client):
    preview = upload(client)
    token = TOKEN_RE.search(preview.get_data(as_text=True)).group(1)
    stored = Path(app.config["UPLOAD_DIR"]) / token
    assert stored.exists()

    client.post("/analyze/run", data={"token": token})
    assert not stored.exists()


def test_sample_download(client):
    response = client.get("/sample.csv")

    assert response.status_code == 200
    assert response.headers["Content-Type"].startswith("text/csv")
    assert "attachment" in response.headers["Content-Disposition"]
    assert response.data.startswith(b"timestamp,ip,user,event,status,port,bytes")


def test_unknown_run_returns_404(client):
    response = client.get("/analyze?run_id=9999")
    assert response.status_code == 404
    assert "does not exist" in response.get_data(as_text=True)
