from __future__ import annotations

import json
import uuid
from typing import Any

from core.config import INCIDENT_STATUSES, SEVERITIES
from core.database import Database
from core.time_utils import from_storage, to_storage, utc_now


class IncidentManager:
    def __init__(self, database: Database):
        self.database = database

    def create(
        self,
        title: str,
        description: str,
        severity: str,
        alert_ids: list[str],
        recommended_actions: str = "",
    ) -> str:
        title = title.strip()
        description = description.strip()
        if not title or len(title) > 300:
            raise ValueError("Incident title is required and must not exceed 300 characters")
        if not description or len(description) > 20_000:
            raise ValueError("Incident description is required and must not exceed 20,000 characters")
        if severity not in SEVERITIES:
            raise ValueError("Invalid incident severity")
        unique_alerts = list(dict.fromkeys(alert_ids))
        if not unique_alerts:
            raise ValueError("Select at least one alert for the incident")
        placeholders = ",".join("?" for _ in unique_alerts)
        alerts = self.database.fetch_all(
            f"SELECT * FROM security_alerts WHERE alert_id IN ({placeholders})", unique_alerts
        )
        if len(alerts) != len(unique_alerts):
            raise ValueError("One or more selected alerts do not exist")
        incident_id = f"INC-{utc_now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
        evidence_entities = self.database.fetch_all(
            f"""
            SELECT DISTINCT e.username, e.hostname, e.source_ip
            FROM alert_events ae JOIN security_events e ON e.event_id = ae.event_id
            WHERE ae.alert_id IN ({placeholders})
            """,
            unique_alerts,
        )
        users = sorted({value for alert in alerts for value in (alert["username"],) if value} | {row["username"] for row in evidence_entities if row["username"]})
        hosts = sorted({value for alert in alerts for value in (alert["hostname"],) if value} | {row["hostname"] for row in evidence_entities if row["hostname"]})
        source_ips = sorted({value for alert in alerts for value in (alert["source_ip"],) if value} | {row["source_ip"] for row in evidence_entities if row["source_ip"]})
        now = to_storage(utc_now())
        with self.database.connection() as connection:
            connection.execute(
                """
                INSERT INTO incidents (
                    incident_id, title, description, severity, status, created_at, updated_at,
                    affected_users_json, affected_hosts_json, source_ips_json, recommended_actions
                ) VALUES (?, ?, ?, ?, 'Open', ?, ?, ?, ?, ?, ?)
                """,
                (incident_id, title, description, severity, now, now, json.dumps(users),
                 json.dumps(hosts), json.dumps(source_ips), recommended_actions.strip()),
            )
            connection.executemany(
                "INSERT INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)",
                [(incident_id, alert_id) for alert_id in unique_alerts],
            )
            connection.execute(
                "INSERT INTO status_history (entity_type, entity_id, previous_status, new_status, changed_at, note) VALUES ('incident', ?, NULL, 'Open', ?, 'Incident created')",
                (incident_id, now),
            )
        return incident_id

    def list(self) -> list[dict[str, Any]]:
        rows = self.database.fetch_all(
            """
            SELECT i.*, COUNT(ia.alert_id) AS alert_count
            FROM incidents i LEFT JOIN incident_alerts ia ON ia.incident_id = i.incident_id
            GROUP BY i.incident_id ORDER BY i.updated_at DESC, i.incident_id
            """
        )
        return [dict(row) for row in rows]

    def get(self, incident_id: str) -> dict[str, Any]:
        row = self.database.fetch_one("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
        if not row:
            raise ValueError("Incident not found")
        incident = dict(row)
        incident["alerts"] = [dict(alert) for alert in self.database.fetch_all(
            """
            SELECT a.alert_id, a.rule_id, a.detection_name, a.severity, a.alert_timestamp, a.status
            FROM incident_alerts ia JOIN security_alerts a ON a.alert_id = ia.alert_id
            WHERE ia.incident_id = ? ORDER BY a.alert_timestamp, a.alert_id
            """, (incident_id,)
        )]
        return incident

    def update_status(self, incident_id: str, status: str, resolution_summary: str = "", note: str = "") -> None:
        if status not in INCIDENT_STATUSES:
            raise ValueError("Invalid incident status")
        with self.database.connection() as connection:
            row = connection.execute("SELECT status, resolution_summary, resolved_at FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            if not row:
                raise ValueError("Incident not found")
            summary = resolution_summary.strip()
            reopening = row["status"] in {"Resolved", "Closed"} and status not in {"Resolved", "Closed"}
            if not summary and not reopening:
                summary = row["resolution_summary"]
            if status in {"Resolved", "Closed"} and not summary:
                raise ValueError("A resolution summary is required before resolving or closing an incident")
            now = to_storage(utc_now())
            resolved_at = (row["resolved_at"] or now) if status in {"Resolved", "Closed"} else None
            connection.execute(
                "UPDATE incidents SET status = ?, updated_at = ?, resolved_at = ?, resolution_summary = ? WHERE incident_id = ?",
                (status, now, resolved_at, summary, incident_id),
            )
            if row["status"] != status:
                connection.execute(
                    "INSERT INTO status_history (entity_type, entity_id, previous_status, new_status, changed_at, note) VALUES ('incident', ?, ?, ?, ?, ?)",
                    (incident_id, row["status"], status, now, note.strip()),
                )

    def add_note(self, incident_id: str, category: str, note: str, author: str = "Analyst") -> int:
        if not note.strip():
            raise ValueError("A note cannot be empty")
        if len(note) > 20_000 or len(category) > 100 or len(author) > 200:
            raise ValueError("Note fields exceed their size limits")
        self.get(incident_id)
        with self.database.connection() as connection:
            cursor = connection.execute(
                "INSERT INTO investigation_notes (incident_id, category, note, author, created_at) VALUES (?, ?, ?, ?, ?)",
                (incident_id, category.strip() or "Observation", note.strip(), author.strip() or "Analyst", to_storage(utc_now())),
            )
            connection.execute("UPDATE incidents SET updated_at = ? WHERE incident_id = ?", (to_storage(utc_now()), incident_id))
            return cursor.lastrowid

    def update_note(self, incident_id: str, note_id: int, category: str, note: str, author: str) -> None:
        if not note.strip():
            raise ValueError("A note cannot be empty")
        if len(note) > 20_000 or len(category) > 100 or len(author) > 200:
            raise ValueError("Note fields exceed their size limits")
        self.get(incident_id)
        now = to_storage(utc_now())
        with self.database.connection() as connection:
            cursor = connection.execute(
                "UPDATE investigation_notes SET category = ?, note = ?, author = ? WHERE note_id = ? AND incident_id = ?",
                (category.strip() or "Observation", note.strip(), author.strip() or "Analyst", note_id, incident_id),
            )
            if cursor.rowcount != 1:
                raise ValueError("Investigation note not found for this incident")
            connection.execute("UPDATE incidents SET updated_at = ? WHERE incident_id = ?", (now, incident_id))
            connection.execute(
                "INSERT INTO audit_log (action, entity_type, entity_id, details, created_at) VALUES ('investigation_note_edited', 'investigation_note', ?, ?, ?)",
                (str(note_id), "Investigation note edited by an authorised local analyst", now),
            )

    def notes(self, incident_id: str) -> list[dict[str, Any]]:
        self.get(incident_id)
        return [dict(row) for row in self.database.fetch_all(
            """
            SELECT n.*, (
                SELECT MAX(a.created_at) FROM audit_log a
                WHERE a.action = 'investigation_note_edited' AND a.entity_type = 'investigation_note'
                    AND a.entity_id = CAST(n.note_id AS TEXT)
            ) AS last_edited_at
            FROM investigation_notes n WHERE n.incident_id = ? ORDER BY n.created_at, n.note_id
            """, (incident_id,)
        )]

    def update_resolution_summary(self, incident_id: str, summary: str) -> None:
        incident = self.get(incident_id)
        self.update_status(incident_id, incident["status"], summary)

    def suggestions(self, alert_id: str, window_seconds: int = 3600) -> list[dict[str, Any]]:
        selected = self.database.fetch_one("SELECT * FROM security_alerts WHERE alert_id = ?", (alert_id,))
        if not selected:
            raise ValueError("Alert not found")
        candidates = self.database.fetch_all(
            "SELECT * FROM security_alerts WHERE active = 1 AND alert_id <> ? ORDER BY alert_timestamp", (alert_id,)
        )
        selected_time = from_storage(selected["alert_timestamp"])
        matches = []
        for candidate in candidates:
            shared = []
            for field in ("source_ip", "username", "hostname"):
                if selected[field] and selected[field] == candidate[field]:
                    shared.append(field)
            distance = abs((from_storage(candidate["alert_timestamp"]) - selected_time).total_seconds())
            if len(shared) >= 2 and distance <= window_seconds:
                matches.append({
                    "alert_id": candidate["alert_id"], "detection_name": candidate["detection_name"],
                    "shared_fields": shared, "distance_seconds": distance,
                    "explanation": f"Shared {', '.join(shared)} and alerts are {int(distance)} seconds apart. Review explicitly before grouping.",
                })
        return matches
