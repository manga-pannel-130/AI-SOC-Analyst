import sqlite3
from pathlib import Path


DATABASE_PATH = (
    Path(__file__).resolve().parent
    / "ai_soc_analyst.db"
)


def get_connection():

    connection = sqlite3.connect(
        DATABASE_PATH
    )

    connection.row_factory = (
        sqlite3.Row
    )

    return connection


def initialize_database():

    connection = get_connection()

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
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
            status TEXT DEFAULT 'NEW'
        )
        """
    )

    connection.commit()
    connection.close()


def insert_alert(alert):

    connection = get_connection()

    connection.execute(
        """
        INSERT OR REPLACE INTO alerts (
            id,
            alert_type,
            description,
            severity,
            frequency,
            asset_criticality,
            business_impact,
            confidence,
            source_ip,
            destination_ip,
            username,
            asset_id,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            alert.id,
            alert.alert_type,
            alert.description,
            alert.severity,
            alert.frequency,
            alert.asset_criticality,
            alert.business_impact,
            alert.confidence,
            alert.source_ip,
            alert.destination_ip,
            alert.username,
            alert.asset_id,
            alert.status
        )
    )

    connection.commit()
    connection.close()


def update_alert_status(
    alert_id,
    status
):

    connection = get_connection()

    connection.execute(
        """
        UPDATE alerts
        SET status = ?
        WHERE id = ?
        """,
        (
            status,
            alert_id
        )
    )

    connection.commit()
    connection.close()