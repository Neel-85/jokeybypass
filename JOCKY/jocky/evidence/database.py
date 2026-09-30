import sqlite3
from pathlib import Path


def initialize_database(db_path: Path) -> None:
    """Create the JOCKY evidence database."""
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                collected_at TEXT NOT NULL
            )
            """
        )

        connection.commit()


def add_evidence(
    db_path: Path,
    evidence_type: str,
    file_path: str,
    sha256: str,
    collected_at: str,
) -> None:
    """Add an evidence record to the database."""

    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO evidence (
                evidence_type,
                file_path,
                sha256,
                collected_at
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                evidence_type,
                file_path,
                sha256,
                collected_at,
            ),
        )

        connection.commit()
        
def get_evidence(db_path: Path) -> list[tuple]:
    """Return all evidence records."""
    with sqlite3.connect(db_path) as connection:
        cursor = connection.execute(
            """
            SELECT
                id,
                evidence_type,
                file_path,
                sha256,
                collected_at
            FROM evidence
            ORDER BY id
            """
        )

        return cursor.fetchall()