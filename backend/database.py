import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from models.alert import Alert


DATABASE_PATH = Path(__file__).resolve().parent / "ai_soc_analyst.db"


@contextmanager
def get_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database():
    with get_connection() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                alert_type TEXT NOT NULL,
                description TEXT NOT NULL,
                severity INTEGER NOT NULL,
                frequency INTEGER NOT NULL,
                asset_criticality INTEGER NOT NULL,
                business_impact INTEGER NOT NULL,
                confidence INTEGER NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                username TEXT,
                asset_id TEXT,
                status TEXT NOT NULL DEFAULT 'NEW',
                source TEXT NOT NULL DEFAULT 'seed',
                run_id TEXT,
                created_at TEXT,
                archived INTEGER NOT NULL DEFAULT 0,
                triage_decision TEXT,
                simulated_evidence_json TEXT NOT NULL DEFAULT '[]',
                threat_classification TEXT,
                threat_score REAL,
                evidence_json TEXT NOT NULL DEFAULT '[]',
                investigation_json TEXT,
                response_plan_json TEXT,
                resolution_action TEXT
            )"""
        )
        existing_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(alerts)").fetchall()
        }
        migrations = {
            "source": "TEXT NOT NULL DEFAULT 'seed'",
            "run_id": "TEXT",
            "created_at": "TEXT",
            "archived": "INTEGER NOT NULL DEFAULT 0",
            "triage_decision": "TEXT",
            "simulated_evidence_json": "TEXT NOT NULL DEFAULT '[]'",
            "threat_classification": "TEXT",
            "threat_score": "REAL",
            "evidence_json": "TEXT NOT NULL DEFAULT '[]'",
            "investigation_json": "TEXT",
            "response_plan_json": "TEXT",
            "resolution_action": "TEXT",
        }
        for column, definition in migrations.items():
            if column not in existing_columns:
                connection.execute(
                    f"ALTER TABLE alerts ADD COLUMN {column} {definition}"
                )
        connection.execute(
            "UPDATE alerts SET created_at = ? WHERE created_at IS NULL",
            (datetime.now(timezone.utc).isoformat(),),
        )


def insert_alert(alert):
    """Persist an alert without replacing its existing status or workflow history."""
    with get_connection() as connection:
        connection.execute(
            """INSERT OR IGNORE INTO alerts (
                id, alert_type, description, severity, frequency,
                asset_criticality, business_impact, confidence,
                source_ip, destination_ip, username, asset_id, status,
                source, run_id, created_at, archived, simulated_evidence_json,
                triage_decision, threat_classification, threat_score, evidence_json,
                investigation_json, response_plan_json, resolution_action
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                alert.id, alert.alert_type, alert.description, alert.severity,
                alert.frequency, alert.asset_criticality, alert.business_impact,
                alert.confidence, alert.source_ip, alert.destination_ip,
                alert.username, alert.asset_id, alert.status, alert.source,
                alert.run_id, alert.created_at or datetime.now(timezone.utc).isoformat(),
                int(alert.archived), _json(alert.simulated_evidence or []),
                alert.triage_decision,
                alert.threat_classification, alert.threat_score,
                _json(alert.evidence or []), _json_or_none(alert.investigation),
                _json_or_none(alert.response_plan), alert.resolution_action,
            ),
        )

def _json(value):
    return json.dumps(value, separators=(",", ":"))


def _json_or_none(value):
    return _json(value) if value is not None else None


def _alert_from_row(row):
    values = dict(row)
    values["archived"] = bool(values["archived"])
    for column, field in (
        ("simulated_evidence_json", "simulated_evidence"),
        ("evidence_json", "evidence"),
        ("investigation_json", "investigation"),
        ("response_plan_json", "response_plan"),
    ):
        raw_value = values.pop(column)
        values[field] = json.loads(raw_value) if raw_value is not None else None
    return Alert(**values)


def get_all_alerts(include_archived=False):
    with get_connection() as connection:
        if include_archived:
            rows = connection.execute(
                "SELECT * FROM alerts ORDER BY created_at, id"
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT * FROM alerts WHERE archived = 0 ORDER BY created_at, id"
            ).fetchall()
    return [_alert_from_row(row) for row in rows]


def get_alert_history(limit=20):
    with get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_alert_from_row(row) for row in rows]


def save_alert_workflow(alert):
    with get_connection() as connection:
        cursor = connection.execute(
            """UPDATE alerts SET
                severity = ?, frequency = ?, asset_criticality = ?,
                business_impact = ?, confidence = ?, status = ?,
                simulated_evidence_json = ?, threat_classification = ?,
                triage_decision = ?,
                threat_score = ?, evidence_json = ?, investigation_json = ?,
                response_plan_json = ?, resolution_action = ?
            WHERE id = ?""",
            (
                alert.severity, alert.frequency, alert.asset_criticality,
                alert.business_impact, alert.confidence, alert.status,
                _json(alert.simulated_evidence or []),
                alert.threat_classification, alert.triage_decision,
                alert.threat_score,
                _json(alert.evidence or []), _json_or_none(alert.investigation),
                _json_or_none(alert.response_plan), alert.resolution_action,
                alert.id,
            ),
        )
        return cursor.rowcount == 1


def archive_simulation_run(run_id):
    with get_connection() as connection:
        connection.execute(
            "UPDATE alerts SET archived = 1 WHERE source = 'simulation' AND run_id = ?",
            (run_id,),
        )


def archive_all_simulation_alerts():
    with get_connection() as connection:
        connection.execute(
            "UPDATE alerts SET archived = 1 WHERE source = 'simulation' AND archived = 0"
        )


def archive_simulation_alert(alert_id):
    with get_connection() as connection:
        connection.execute(
            "UPDATE alerts SET archived = 1 WHERE id = ? AND source = 'simulation'",
            (alert_id,),
        )


def update_alert_status(alert_id, status):
    with get_connection() as connection:
        cursor = connection.execute(
            "UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id)
        )
        return cursor.rowcount == 1


def reset_alert_statuses():
    with get_connection() as connection:
        connection.execute(
            """UPDATE alerts SET status = 'NEW',
                threat_classification = NULL, threat_score = NULL,
                triage_decision = NULL,
                evidence_json = '[]', investigation_json = NULL,
                response_plan_json = NULL, resolution_action = NULL
            WHERE source = 'seed' AND archived = 0"""
        )
