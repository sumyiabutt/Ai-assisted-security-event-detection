"""CyberFox web application.

Dashboard, alerts and CSV analysis pages on top of the rule + ML detection
engine. Every run, event, alert and rejected row is stored in SQLite, and the
bundled sample dataset is analysed automatically when the database is empty.
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import (
    Blueprint,
    Flask,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from detection.engine import run_engine
from detection.parser import ParseError, ParseResult, parse_logs

BASE_DIR = Path(__file__).resolve().parent
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"
SAMPLE_TOKEN = "sample"
SAMPLE_FILENAME = "sample_logs.csv"
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}$")
SEVERITIES = ("Critical", "High", "Medium", "Low")
SOURCES = ("Rule", "ML")
SEVERITY_RANK_SQL = (
    "CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 "
    "WHEN 'Medium' THEN 2 ELSE 3 END"
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    created_at TEXT NOT NULL,
    is_sample INTEGER NOT NULL DEFAULT 0,
    total_rows INTEGER NOT NULL,
    valid_rows INTEGER NOT NULL,
    invalid_rows INTEGER NOT NULL,
    unique_ips INTEGER NOT NULL,
    unique_users INTEGER NOT NULL,
    time_start TEXT,
    time_end TEXT,
    failure_rate REAL NOT NULL,
    login_events INTEGER NOT NULL,
    failed_logins INTEGER NOT NULL,
    total_alerts INTEGER NOT NULL,
    rule_alerts INTEGER NOT NULL,
    ml_alerts INTEGER NOT NULL,
    critical_count INTEGER NOT NULL,
    high_count INTEGER NOT NULL,
    medium_count INTEGER NOT NULL,
    low_count INTEGER NOT NULL,
    suspicious_events INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    line_number INTEGER NOT NULL,
    timestamp TEXT NOT NULL,
    hour INTEGER NOT NULL,
    ip TEXT NOT NULL,
    user TEXT NOT NULL,
    event TEXT NOT NULL,
    status TEXT NOT NULL,
    port INTEGER NOT NULL,
    bytes INTEGER NOT NULL,
    label INTEGER NOT NULL DEFAULT 0,
    rule_flag INTEGER NOT NULL DEFAULT 0,
    ml_flag INTEGER NOT NULL DEFAULT 0,
    suspicious INTEGER NOT NULL DEFAULT 0,
    alert_source TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    user TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    reason TEXT NOT NULL,
    source TEXT NOT NULL,
    mitre TEXT,
    anomaly_score REAL,
    event_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS invalid_rows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    line_number INTEGER NOT NULL,
    reason TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id);
CREATE INDEX IF NOT EXISTS idx_alerts_run ON alerts(run_id);
CREATE INDEX IF NOT EXISTS idx_invalid_run ON invalid_rows(run_id);
"""

web = Blueprint("web", __name__)


# --------------------------------------------------------------------------- #
# Database helpers
# --------------------------------------------------------------------------- #


def get_db() -> sqlite3.Connection:
    """Return the request-scoped SQLite connection."""
    if "db" not in g:
        connection = sqlite3.connect(current_app.config["DATABASE"])
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.db = connection
    return g.db


def close_db(_exception: BaseException | None = None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db() -> None:
    """Create the tables and indexes if they do not exist yet."""
    connection = sqlite3.connect(current_app.config["DATABASE"])
    try:
        connection.executescript(SCHEMA)
        connection.commit()
    finally:
        connection.close()


def _format_timestamp(value: Any) -> str:
    """Format a pandas Timestamp (or anything with strftime) for SQLite."""
    if hasattr(value, "strftime"):
        return value.strftime(TIMESTAMP_FORMAT)
    return str(value)


def store_run(
    filename: str,
    result: ParseResult,
    engine_result: dict[str, Any],
    *,
    is_sample: bool = False,
) -> int:
    """Persist a completed analysis and return the new run id."""
    db = get_db()
    stats = result.stats
    summary = engine_result["summary"]
    counts = summary["severity_counts"]

    cursor = db.execute(
        """
        INSERT INTO runs (
            filename, created_at, is_sample, total_rows, valid_rows,
            invalid_rows, unique_ips, unique_users, time_start, time_end,
            failure_rate, login_events, failed_logins, total_alerts,
            rule_alerts, ml_alerts, critical_count, high_count, medium_count,
            low_count, suspicious_events
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            filename,
            datetime.now().strftime(TIMESTAMP_FORMAT),
            int(is_sample),
            stats["total_rows"],
            stats["valid_rows"],
            stats["invalid_rows"],
            stats["unique_ips"],
            stats["unique_users"],
            stats["time_start"],
            stats["time_end"],
            float(stats["failure_rate"]),
            stats["login_events"],
            stats["failed_logins"],
            summary["total_alerts"],
            summary["rule_alerts"],
            summary["ml_alerts"],
            counts["Critical"],
            counts["High"],
            counts["Medium"],
            counts["Low"],
            summary["suspicious_events"],
        ),
    )
    run_id = int(cursor.lastrowid)

    db.executemany(
        """
        INSERT INTO alerts (
            run_id, ip, user, timestamp, severity, reason, source, mitre,
            anomaly_score, event_count
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                run_id,
                alert["ip"],
                alert["user"],
                _format_timestamp(alert["timestamp"]),
                alert["severity"],
                alert["reason"],
                alert["source"],
                alert["mitre"],
                alert.get("anomaly_score"),
                int(alert.get("count", 0)),
            )
            for alert in engine_result["alerts"]
        ],
    )

    db.executemany(
        "INSERT INTO invalid_rows (run_id, line_number, reason) VALUES (?, ?, ?)",
        [
            (run_id, int(row["line_number"]), str(row["reason"]))
            for _, row in result.invalid.iterrows()
        ],
    )

    events = engine_result["events"]
    db.executemany(
        """
        INSERT INTO events (
            run_id, line_number, timestamp, hour, ip, user, event, status,
            port, bytes, label, rule_flag, ml_flag, suspicious, alert_source
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                run_id,
                int(row.line_number),
                _format_timestamp(row.timestamp),
                int(row.timestamp.hour),
                str(row.ip),
                str(row.user),
                str(row.event),
                str(row.status),
                int(row.port),
                int(row.bytes),
                int(row.label),
                int(row.rule_flag),
                int(row.ml_flag),
                int(row.suspicious),
                str(row.alert_source),
            )
            for row in events.itertuples(index=False)
        ],
    )

    db.commit()
    return run_id


def analyze_file(filename: str, path: Path, *, is_sample: bool = False) -> int:
    """Parse a CSV, run detection and store the result.

    Raises ParseError when the file cannot be analysed at all.
    """
    result = parse_logs(path)
    if result.valid.empty:
        raise ParseError("The file contains no valid events to analyse.")
    engine_result = run_engine(result.valid)
    return store_run(filename, result, engine_result, is_sample=is_sample)


def _ensure_sample_loaded(app: Flask) -> None:
    """Analyse the bundled sample once so the dashboard is never empty."""
    with app.app_context():
        db = get_db()
        existing = db.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
        if existing:
            return
        sample_path = Path(app.config["SAMPLE_PATH"])
        if not sample_path.exists():
            return
        analyze_file(
            f"{SAMPLE_FILENAME} (bundled sample)",
            sample_path,
            is_sample=True,
        )


# --------------------------------------------------------------------------- #
# Upload helpers
# --------------------------------------------------------------------------- #


def _upload_directory() -> Path:
    directory = Path(current_app.config["UPLOAD_DIR"]).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _save_upload(upload: Any) -> tuple[str, Path]:
    """Validate, store and return (token, absolute path) for an upload."""
    original = upload.filename or ""
    safe_name = secure_filename(original)
    if not original or not safe_name or not safe_name.lower().endswith(".csv"):
        raise ValueError("Only .csv files are supported.")

    token = f"{uuid.uuid4().hex}__{safe_name}"
    path = _upload_directory() / token
    upload.save(path)
    return token, path


def _resolve_token(token: str) -> tuple[Path, str, bool]:
    """Map a preview token to (path, display name, is_sample)."""
    if not token or not TOKEN_PATTERN.fullmatch(token):
        raise ValueError("The upload reference is not valid.")

    if token == SAMPLE_TOKEN:
        path = Path(current_app.config["SAMPLE_PATH"]).resolve()
        if not path.exists():
            raise ValueError("The bundled sample dataset is missing.")
        return path, SAMPLE_FILENAME, True

    upload_dir = _upload_directory()
    path = (upload_dir / token).resolve()
    if path.parent != upload_dir or path.suffix.lower() != ".csv" or not path.is_file():
        raise ValueError("The uploaded file could not be found.")
    display_name = token.split("__", 1)[1] if "__" in token else token
    return path, display_name, False


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _latest_run(db: sqlite3.Connection) -> sqlite3.Row | None:
    return db.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()


def _get_run(db: sqlite3.Connection, run_id: int) -> sqlite3.Row:
    run = db.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if run is None:
        abort(404)
    return run


# --------------------------------------------------------------------------- #
# Template helpers
# --------------------------------------------------------------------------- #


@web.app_template_filter("sev_class")
def sev_class(severity: str) -> str:
    return f"sev-{str(severity).lower()}"


@web.app_template_filter("num")
def num(value: Any) -> str:
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


@web.app_template_filter("percent")
def percent(value: Any) -> str:
    try:
        return f"{float(value) * 100:.1f}%"
    except (TypeError, ValueError):
        return "0.0%"


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #


@web.get("/")
def index():
    return redirect(url_for("web.dashboard"))


@web.get("/dashboard")
def dashboard():
    db = get_db()
    run = _latest_run(db)

    if run is None:
        return render_template(
            "dashboard.html",
            run=None,
            cards={
                "total_rows": 0,
                "valid_rows": 0,
                "suspicious_events": 0,
                "total_alerts": 0,
            },
            hourly={"labels": [], "events": [], "suspicious": []},
            donut=None,
            sources=[],
            failed_logins=[],
            recent_alerts=[],
            severity_counts={"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
        )

    run_id = int(run["id"])

    hourly_rows = db.execute(
        """
        SELECT hour, COUNT(*) AS total, SUM(suspicious) AS suspicious
        FROM events WHERE run_id = ? GROUP BY hour
        """,
        (run_id,),
    ).fetchall()
    per_hour = {int(row["hour"]): row for row in hourly_rows}
    hourly = {
        "labels": [f"{hour:02d}:00" for hour in range(24)],
        "events": [int(per_hour[hour]["total"]) if hour in per_hour else 0 for hour in range(24)],
        "suspicious": [
            int(per_hour[hour]["suspicious"] or 0) if hour in per_hour else 0
            for hour in range(24)
        ],
    }

    suspicious_events = int(run["suspicious_events"])
    valid_rows = int(run["valid_rows"])
    normal_events = max(valid_rows - suspicious_events, 0)
    share = (suspicious_events / valid_rows * 100) if valid_rows else 0.0
    donut = {
        "normal": normal_events,
        "suspicious": suspicious_events,
        "share": share,
        "style": (
            "conic-gradient(var(--orange) 0 "
            f"{share:.2f}%, #1b2a44 {share:.2f}% 100%)"
        ),
    }

    source_rows = db.execute(
        f"""
        SELECT ip,
               COUNT(*) AS alert_count,
               MIN({SEVERITY_RANK_SQL}) AS rank,
               GROUP_CONCAT(DISTINCT source) AS sources,
               MAX(timestamp) AS last_seen
        FROM alerts
        WHERE run_id = ?
        GROUP BY ip
        ORDER BY rank, alert_count DESC
        LIMIT 8
        """,
        (run_id,),
    ).fetchall()
    severity_by_rank = {0: "Critical", 1: "High", 2: "Medium", 3: "Low"}
    sources = [
        {
            "ip": row["ip"],
            "alert_count": row["alert_count"],
            "severity": severity_by_rank.get(int(row["rank"]), "Low"),
            "sources": row["sources"],
            "last_seen": row["last_seen"],
        }
        for row in source_rows
    ]

    failed_logins = db.execute(
        """
        SELECT timestamp, ip, user, status, alert_source
        FROM events
        WHERE run_id = ? AND event = 'login' AND suspicious = 1
        ORDER BY timestamp DESC
        LIMIT 6
        """,
        (run_id,),
    ).fetchall()

    recent_alerts = db.execute(
        f"""
        SELECT * FROM alerts WHERE run_id = ?
        ORDER BY timestamp DESC, {SEVERITY_RANK_SQL}
        LIMIT 8
        """,
        (run_id,),
    ).fetchall()

    severity_counts = {
        "Critical": int(run["critical_count"]),
        "High": int(run["high_count"]),
        "Medium": int(run["medium_count"]),
        "Low": int(run["low_count"]),
    }

    cards = {
        "total_rows": int(run["total_rows"]),
        "valid_rows": valid_rows,
        "suspicious_events": suspicious_events,
        "total_alerts": int(run["total_alerts"]),
    }

    return render_template(
        "dashboard.html",
        run=run,
        cards=cards,
        hourly=hourly,
        donut=donut,
        sources=sources,
        failed_logins=failed_logins,
        recent_alerts=recent_alerts,
        severity_counts=severity_counts,
    )


@web.get("/alerts")
def alerts():
    db = get_db()
    requested_run = request.args.get("run_id", type=int)
    run = _get_run(db, requested_run) if requested_run else _latest_run(db)

    if run is None:
        return render_template(
            "alerts.html",
            run=None,
            alerts=[],
            total=0,
            filters={"q": "", "severity": "", "source": ""},
        )

    run_id = int(run["id"])
    query_text = request.args.get("q", "").strip()[:120]
    severity = request.args.get("severity", "").strip()
    source = request.args.get("source", "").strip()
    severity = severity if severity in SEVERITIES else ""
    source = source if source in SOURCES else ""

    clauses = ["run_id = ?"]
    params: list[Any] = [run_id]

    if query_text:
        pattern = f"%{_escape_like(query_text)}%"
        clauses.append(
            "(ip LIKE ? ESCAPE '\\' OR user LIKE ? ESCAPE '\\' "
            "OR reason LIKE ? ESCAPE '\\' OR mitre LIKE ? ESCAPE '\\' "
            "OR timestamp LIKE ? ESCAPE '\\')"
        )
        params.extend([pattern] * 5)

    if severity:
        clauses.append("severity = ?")
        params.append(severity)

    if source:
        clauses.append("source = ?")
        params.append(source)

    rows = db.execute(
        f"""
        SELECT * FROM alerts
        WHERE {' AND '.join(clauses)}
        ORDER BY {SEVERITY_RANK_SQL}, timestamp DESC
        LIMIT 500
        """,
        params,
    ).fetchall()

    total = db.execute(
        "SELECT COUNT(*) FROM alerts WHERE run_id = ?", (run_id,)
    ).fetchone()[0]

    return render_template(
        "alerts.html",
        run=run,
        alerts=rows,
        total=int(total),
        filters={"q": query_text, "severity": severity, "source": source},
    )


@web.get("/analyze")
def analyze():
    run_id = request.args.get("run_id", type=int)
    db = get_db()

    if run_id is not None:
        run = _get_run(db, run_id)
        invalid_rows = db.execute(
            "SELECT line_number, reason FROM invalid_rows WHERE run_id = ? "
            "ORDER BY line_number LIMIT 25",
            (run_id,),
        ).fetchall()
        return render_template(
            "analyze.html",
            state="result",
            run=run,
            invalid_rows=invalid_rows,
        )

    return render_template("analyze.html", state="upload", run=None)


@web.post("/analyze/preview")
def analyze_preview():
    wants_sample = request.form.get("sample") == "1"

    try:
        if wants_sample:
            path, display_name, is_sample = _resolve_token(SAMPLE_TOKEN)
            token = SAMPLE_TOKEN
        else:
            upload = request.files.get("logfile")
            if upload is None or not upload.filename:
                raise ValueError("Choose a CSV file first.")
            token, path = _save_upload(upload)
            display_name = token.split("__", 1)[1]
            is_sample = False

        result = parse_logs(path)
    except (ValueError, ParseError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("web.analyze"))

    if result.valid.empty:
        if not is_sample:
            path.unlink(missing_ok=True)
        flash(
            "None of the rows passed validation. Check the required columns and "
            "the timestamp / IP / port formats.",
            "error",
        )
        return redirect(url_for("web.analyze"))

    preview_rows = result.valid.head(8).to_dict("records")
    invalid_preview = result.invalid.head(25)

    return render_template(
        "analyze.html",
        state="preview",
        run=None,
        token=token,
        display_name=display_name,
        is_sample=is_sample,
        stats=result.stats,
        preview_rows=preview_rows,
        invalid_rows=invalid_preview.to_dict("records"),
        invalid_total=int(result.stats["invalid_rows"]),
    )


@web.post("/analyze/run")
def analyze_run():
    token = request.form.get("token", "")

    try:
        path, display_name, is_sample = _resolve_token(token)
        run_id = analyze_file(display_name, path, is_sample=is_sample)
    except (ValueError, ParseError) as exc:
        flash(str(exc), "error")
        return redirect(url_for("web.analyze"))
    finally:
        if token and token != SAMPLE_TOKEN and TOKEN_PATTERN.fullmatch(token):
            upload_dir = _upload_directory()
            candidate = (upload_dir / token).resolve()
            if candidate.parent == upload_dir:
                candidate.unlink(missing_ok=True)

    return redirect(url_for("web.analyze", run_id=run_id))



@web.get("/sample.csv")
def sample_download():
    path = Path(current_app.config["SAMPLE_PATH"]).resolve()
    if not path.exists():
        abort(404)
    return send_file(
        path,
        as_attachment=True,
        download_name=SAMPLE_FILENAME,
        mimetype="text/csv",
    )


# --------------------------------------------------------------------------- #
# Application factory
# --------------------------------------------------------------------------- #


def create_app(test_config: dict[str, Any] | None = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)

    # Serverless hosts such as Vercel only allow writes under /tmp.
    data_dir = Path(tempfile.gettempdir()) if os.environ.get("VERCEL") else BASE_DIR

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "cyberfox-dev-key"),
        DATABASE=str(data_dir / "cyberfox.db"),
        UPLOAD_DIR=str(data_dir / "cyberfox-uploads"),
        SAMPLE_PATH=str(BASE_DIR / "data" / "sample_logs.csv"),
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,
        SAMPLE_ON_STARTUP=True,
    )
    if test_config:
        app.config.update(test_config)

    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    Path(app.config["UPLOAD_DIR"]).mkdir(parents=True, exist_ok=True)

    # A fresh serverless instance starts with an empty /tmp, so ship the sample
    # analysis as a prebuilt database instead of re-running the engine.
    seed_path = BASE_DIR / "data" / "seed_cyberfox.db"
    database_path = Path(app.config["DATABASE"])
    if (
        os.environ.get("VERCEL")
        and not database_path.exists()
        and seed_path.exists()
    ):
        shutil.copyfile(seed_path, database_path)

    app.register_blueprint(web)
    app.teardown_appcontext(close_db)

    @app.errorhandler(RequestEntityTooLarge)
    def handle_too_large(_error: RequestEntityTooLarge):
        flash("That file is larger than the 10 MB upload limit.", "error")
        return render_template("analyze.html", state="upload", run=None), 413

    @app.errorhandler(404)
    def handle_not_found(_error):
        return (
            render_template(
                "error.html",
                code=404,
                message="That page or analysis run does not exist.",
            ),
            404,
        )

    with app.app_context():
        init_db()
        if app.config["SAMPLE_ON_STARTUP"]:
            _ensure_sample_loaded(app)

    return app


# Vercel's Flask preset needs a top-level WSGI callable in this module.
app = create_app()


if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
    )
