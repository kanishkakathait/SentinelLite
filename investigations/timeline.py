from __future__ import annotations

from typing import Any

from core.database import Database


def incident_timeline(database: Database, incident_id: str) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    alerts = database.fetch_all(
        """
        SELECT DISTINCT a.* FROM security_alerts a
        JOIN incident_alerts ia ON ia.alert_id = a.alert_id WHERE ia.incident_id = ?
        """, (incident_id,)
    )
    for alert in alerts:
        entries.extend([
            {"timestamp": alert["alert_timestamp"], "type": "Detection trigger", "title": alert["detection_name"], "detail": alert["explanation"], "reference": alert["alert_id"], "marker": "detection", "entity_type": "alert"},
            {"timestamp": alert["created_at"], "type": "Alert creation", "title": alert["alert_id"], "detail": f"Alert status: {alert['status']}", "reference": alert["alert_id"], "marker": "alert", "entity_type": "alert"},
        ])
    events = database.fetch_all(
        """
        SELECT DISTINCT e.* FROM security_events e
        JOIN alert_events ae ON ae.event_id = e.event_id
        JOIN incident_alerts ia ON ia.alert_id = ae.alert_id
        WHERE ia.incident_id = ? ORDER BY e.event_timestamp, e.event_id
        """, (incident_id,)
    )
    for event in events:
        marker = "success" if event["authentication_result"] == "success" else "failure" if event["authentication_result"] == "failure" else "event"
        title = "Failed authentication" if marker == "failure" else "Successful authentication" if marker == "success" else f"{event['event_category']} / {event['event_action']}"
        entries.append({
            "timestamp": event["event_timestamp"], "type": "Security event",
            "title": title,
            "detail": f"{event['authentication_result'] or 'no result'} | user={event['username'] or 'not supplied'} | source={event['source_ip'] or 'not supplied'} | {event['raw_message']}",
            "reference": event["event_id"], "marker": marker, "entity_type": "security_event",
        })
    history = database.fetch_all("SELECT * FROM status_history WHERE entity_type = 'incident' AND entity_id = ?", (incident_id,))
    for item in history:
        entries.append({
            "timestamp": item["changed_at"], "type": "Analyst status change",
            "title": f"{item['previous_status'] or 'Created'} → {item['new_status']}",
            "detail": item["note"], "reference": str(item["history_id"]), "marker": "analyst", "entity_type": "status_history",
        })
    notes = database.fetch_all(
        """
        SELECT n.*, (
            SELECT MAX(a.created_at) FROM audit_log a
            WHERE a.action = 'investigation_note_edited' AND a.entity_type = 'investigation_note'
                AND a.entity_id = CAST(n.note_id AS TEXT)
        ) AS last_edited_at
        FROM investigation_notes n WHERE n.incident_id = ? ORDER BY n.created_at, n.note_id
        """, (incident_id,)
    )
    for note in notes:
        entries.append({
            "timestamp": note["created_at"], "type": "Analyst note", "title": note["category"],
            "detail": note["note"], "reference": str(note["note_id"]), "marker": "analyst", "entity_type": "investigation_note",
        })
    return sorted(entries, key=lambda entry: (entry["timestamp"], entry["type"], entry["reference"]))
