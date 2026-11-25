from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from core.config import SCHEMA_FILE
from core.time_utils import from_storage, to_storage


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def initialise(self) -> None:
        with self.connection() as connection:
            connection.executescript(SCHEMA_FILE.read_text(encoding="utf-8"))
            self._normalise_timestamp_columns(connection)

    @staticmethod
    def _normalise_timestamp_columns(connection: sqlite3.Connection) -> None:
        columns = {
            "security_events": ("event_timestamp", "ingestion_timestamp"),
            "ingestion_batches": ("created_at",),
            "detection_rules": ("updated_at",),
            "security_alerts": ("alert_timestamp", "created_at", "superseded_at"),
            "investigation_notes": ("created_at",),
            "status_history": ("changed_at",),
            "incidents": ("created_at", "updated_at", "resolved_at"),
            "vulnerabilities": ("created_at", "updated_at"),
            "remediation_actions": ("created_at", "updated_at"),
            "audit_log": ("created_at",),
            "application_settings": ("updated_at",),
        }
        for table, timestamp_columns in columns.items():
            rows = connection.execute(f"SELECT rowid, * FROM {table}").fetchall()
            for row in rows:
                for column in timestamp_columns:
                    stored = row[column]
                    if stored is None:
                        continue
                    normalised = to_storage(from_storage(stored))
                    if normalised != stored:
                        connection.execute(
                            f"UPDATE {table} SET {column} = ? WHERE rowid = ?",
                            (normalised, row["rowid"]),
                        )

    def fetch_all(self, query: str, parameters: Sequence[object] = ()) -> list[sqlite3.Row]:
        with self.connection() as connection:
            return list(connection.execute(query, parameters).fetchall())

    def fetch_one(self, query: str, parameters: Sequence[object] = ()) -> sqlite3.Row | None:
        with self.connection() as connection:
            return connection.execute(query, parameters).fetchone()

    def execute(self, query: str, parameters: Sequence[object] = ()) -> int:
        with self.connection() as connection:
            return connection.execute(query, parameters).lastrowid

    def execute_many(self, query: str, rows: Iterable[Sequence[object]]) -> None:
        with self.connection() as connection:
            connection.executemany(query, rows)
