from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable

import yaml

from core.config import ALERT_STATUSES, RULES_DIR, SEVERITIES
from core.database import Database
from core.models import RuleDefinition, SecurityEvent
from core.time_utils import to_storage, utc_now


EVENT_COLUMNS = """
    event_id, event_timestamp, event_source, hostname, source_ip, destination_ip,
    username, event_category, event_action, authentication_result, raw_message,
    ingestion_timestamp, simulated
"""


class EventRepository:
    def __init__(self, database: Database):
        self.database = database

    def add_many(self, events: Iterable[SecurityEvent]) -> tuple[int, int]:
        accepted = 0
        duplicates = 0
        statement = f"INSERT OR IGNORE INTO security_events ({EVENT_COLUMNS}) VALUES ({','.join('?' for _ in range(13))})"
        with self.database.connection() as connection:
            for event in events:
                cursor = connection.execute(statement, event.storage_values())
                if cursor.rowcount == 1:
                    accepted += 1
                else:
                    duplicates += 1
        return accepted, duplicates

    def all(self) -> list[SecurityEvent]:
        rows = self.database.fetch_all(f"SELECT {EVENT_COLUMNS} FROM security_events")
        return sorted(
            (SecurityEvent.from_row(row) for row in rows), key=lambda event: (event.timestamp, event.event_id)
        )

    def get(self, event_id: str) -> SecurityEvent | None:
        row = self.database.fetch_one(
            f"SELECT {EVENT_COLUMNS} FROM security_events WHERE event_id = ?", (event_id,)
        )
        return SecurityEvent.from_row(row) if row else None

    def search(
        self,
        source_ip: str | None = None,
        username: str | None = None,
        category: str | None = None,
        text: str | None = None,
        limit: int = 5000,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[object] = []
        for column, value in (("source_ip", source_ip), ("username", username), ("event_category", category)):
            if value:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        if text:
            clauses.append("LOWER(raw_message) LIKE ?")
            parameters.append(f"%{text.lower()}%")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(max(1, min(limit, 10_000)))
        rows = self.database.fetch_all(
            f"SELECT {EVENT_COLUMNS} FROM security_events {where} ORDER BY event_timestamp DESC LIMIT ?",
            parameters,
        )
        return [dict(row) for row in rows]

    def count(self) -> int:
        return self.database.fetch_one("SELECT COUNT(*) AS count FROM security_events")["count"]


class RuleRepository:
    def __init__(self, database: Database, rules_directory: Path = RULES_DIR):
        self.database = database
        self.rules_directory = rules_directory

    def sync_defaults(self) -> None:
        now = to_storage(utc_now())
        with self.database.connection() as connection:
            for path in sorted(self.rules_directory.glob("*.yaml")):
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                connection.execute(
                    """
                    INSERT OR IGNORE INTO detection_rules (
                        rule_id, name, description, severity, enabled, config_json,
                        documentation, recommended_actions_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        data["rule_id"], data["name"], data["description"], data["severity"],
                        int(data.get("enabled", True)), json.dumps(data.get("config", {}), sort_keys=True),
                        data["documentation"], json.dumps(data.get("recommended_actions", [])), now,
                    ),
                )

    def _to_rule(self, row: sqlite3.Row) -> RuleDefinition:
        return RuleDefinition(
            rule_id=row["rule_id"], name=row["name"], description=row["description"],
            severity=row["severity"], enabled=bool(row["enabled"]),
            config=json.loads(row["config_json"]), documentation=row["documentation"],
            recommended_actions=tuple(json.loads(row["recommended_actions_json"])),
        )

    def list(self) -> list[RuleDefinition]:
        return [self._to_rule(row) for row in self.database.fetch_all("SELECT * FROM detection_rules ORDER BY rule_id")]

    def get(self, rule_id: str) -> RuleDefinition:
        row = self.database.fetch_one("SELECT * FROM detection_rules WHERE rule_id = ?", (rule_id,))
        if not row:
            raise ValueError("Unknown detection rule")
        return self._to_rule(row)

    def update(self, rule_id: str, enabled: bool, config: dict[str, Any]) -> None:
        self.get(rule_id)
        self.database.execute(
            "UPDATE detection_rules SET enabled = ?, config_json = ?, updated_at = ? WHERE rule_id = ?",
            (int(enabled), json.dumps(config, sort_keys=True), to_storage(utc_now()), rule_id),
        )


class AlertRepository:
    def __init__(self, database: Database):
        self.database = database

    def list(
        self,
        severity: str | None = None,
        rule_id: str | None = None,
        status: str | None = None,
        source_ip: str | None = None,
        username: str | None = None,
        active_only: bool = True,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        parameters: list[object] = []
        if active_only:
            clauses.append("a.active = 1")
        for column, value in (
            ("a.severity", severity), ("a.rule_id", rule_id), ("a.status", status),
            ("a.source_ip", source_ip),
        ):
            if value:
                clauses.append(f"{column} = ?")
                parameters.append(value)
        if username:
            clauses.append("""(
                a.username = ? OR EXISTS (
                    SELECT 1 FROM alert_events ae JOIN security_events e ON e.event_id = ae.event_id
                    WHERE ae.alert_id = a.alert_id AND e.username = ?
                )
            )""")
            parameters.extend((username, username))
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self.database.fetch_all(
            f"""
            SELECT a.*, GROUP_CONCAT(ia.incident_id) AS incident_ids
            FROM security_alerts a
            LEFT JOIN incident_alerts ia ON ia.alert_id = a.alert_id
            {where}
            GROUP BY a.alert_id
            ORDER BY a.alert_timestamp DESC, a.alert_id
            """,
            parameters,
        )
        return [dict(row) for row in rows]

    def get(self, alert_id: str) -> dict[str, Any]:
        row = self.database.fetch_one(
            """
            SELECT a.*, GROUP_CONCAT(ia.incident_id) AS incident_ids
            FROM security_alerts a
            LEFT JOIN incident_alerts ia ON ia.alert_id = a.alert_id
            WHERE a.alert_id = ? GROUP BY a.alert_id
            """, (alert_id,),
        )
        if not row:
            raise ValueError("Alert not found")
        return dict(row)

    def related(self, alert_id: str, limit: int = 6) -> list[dict[str, Any]]:
        selected = self.get(alert_id)
        parameters: list[object] = [alert_id]
        conditions = []
        for field in ("source_ip", "username", "hostname"):
            if selected[field]:
                conditions.append(f"a.{field} = ?")
                parameters.append(selected[field])
        if not conditions:
            return []
        parameters.extend((selected["rule_id"], selected["alert_timestamp"], max(1, min(limit, 15))))
        clauses = " OR ".join(conditions)
        rows = self.database.fetch_all(
            f"""
            SELECT a.*, GROUP_CONCAT(ia.incident_id) AS incident_ids
            FROM security_alerts a
            LEFT JOIN incident_alerts ia ON ia.alert_id = a.alert_id
            WHERE a.active = 1 AND a.alert_id <> ? AND ({clauses})
            GROUP BY a.alert_id
            ORDER BY (a.rule_id = ?) DESC, ABS(julianday(a.alert_timestamp) - julianday(?)), a.alert_id
            LIMIT ?
            """,
            parameters,
        )
        return [dict(row) for row in rows]

    def for_events(self, event_ids: set[str]) -> list[dict[str, Any]]:
        if not event_ids:
            return []
        placeholders = ",".join("?" for _ in event_ids)
        rows = self.database.fetch_all(
            f"""
            SELECT DISTINCT a.alert_id FROM security_alerts a
            JOIN alert_events ae ON ae.alert_id = a.alert_id
            WHERE a.active = 1 AND ae.event_id IN ({placeholders})
            ORDER BY a.alert_timestamp, a.alert_id
            """, sorted(event_ids),
        )
        return [self.get(row["alert_id"]) for row in rows]

    def evidence(self, alert_id: str) -> list[SecurityEvent]:
        rows = self.database.fetch_all(
            """
            SELECT e.* FROM alert_events ae
            JOIN security_events e ON e.event_id = ae.event_id
            WHERE ae.alert_id = ? ORDER BY e.event_timestamp, e.event_id
            """,
            (alert_id,),
        )
        return [SecurityEvent.from_row(row) for row in rows]

    def update_status(self, alert_id: str, status: str, note: str = "") -> None:
        if status not in ALERT_STATUSES:
            raise ValueError("Invalid alert status")
        with self.database.connection() as connection:
            row = connection.execute("SELECT status FROM security_alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            if not row:
                raise ValueError("Alert not found")
            if row["status"] == status:
                return
            now = to_storage(utc_now())
            connection.execute("UPDATE security_alerts SET status = ? WHERE alert_id = ?", (status, alert_id))
            connection.execute(
                "INSERT INTO status_history (entity_type, entity_id, previous_status, new_status, changed_at, note) VALUES ('alert', ?, ?, ?, ?, ?)",
                (alert_id, row["status"], status, now, note.strip()),
            )
            connection.execute(
                "INSERT INTO audit_log (action, entity_type, entity_id, details, created_at) VALUES ('status_changed', 'alert', ?, ?, ?)",
                (alert_id, f"{row['status']} -> {status}", now),
            )

    def add_note(self, alert_id: str, category: str, note: str, author: str = "Analyst") -> int:
        if not note.strip():
            raise ValueError("A note cannot be empty")
        if len(note) > 20_000 or len(category) > 100 or len(author) > 200:
            raise ValueError("Note fields exceed their size limits")
        return self.database.execute(
            "INSERT INTO investigation_notes (alert_id, category, note, author, created_at) VALUES (?, ?, ?, ?, ?)",
            (alert_id, category.strip() or "Observation", note.strip(), author.strip() or "Analyst", to_storage(utc_now())),
        )

    def notes(self, alert_id: str) -> list[dict[str, Any]]:
        return [dict(row) for row in self.database.fetch_all(
            "SELECT * FROM investigation_notes WHERE alert_id = ? ORDER BY created_at, note_id", (alert_id,)
        )]


class SettingsRepository:
    def __init__(self, database: Database):
        self.database = database

    def get(self, key: str, default: str = "") -> str:
        row = self.database.fetch_one("SELECT value FROM application_settings WHERE key = ?", (key,))
        return row["value"] if row else default

    def set(self, key: str, value: str) -> None:
        self.database.execute(
            """
            INSERT INTO application_settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, value, to_storage(utc_now())),
        )


def validate_severity(value: str) -> str:
    if value not in SEVERITIES:
        raise ValueError("Invalid severity")
    return value
