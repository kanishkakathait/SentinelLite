from __future__ import annotations

from typing import Any

from core.database import Database


def recent_activity(database: Database, limit: int = 24) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 100))
    window = min(limit, 25)
    activities: list[dict[str, Any]] = []
    events = database.fetch_all(
        """
        SELECT event_id, event_timestamp, event_category, event_action, authentication_result,
            source_ip, username, hostname, raw_message, simulated
        FROM security_events ORDER BY event_timestamp DESC, event_id DESC LIMIT ?
        """, (window,),
    )
    for event in events:
        activities.append({
            "timestamp": event["event_timestamp"], "kind": "event",
            "label": "Security event" if not event["authentication_result"] else f"Authentication {event['authentication_result']}",
            "detail": f"{event['event_category']} / {event['event_action']} · {event['username'] or 'No user supplied'} · {event['source_ip'] or 'No source supplied'}",
            "reference": event["event_id"], "target": "event",
            "raw_message": event["raw_message"], "simulated": bool(event["simulated"]),
        })
    alerts = database.fetch_all(
        "SELECT alert_id, rule_id, detection_name, alert_timestamp, severity, status, explanation FROM security_alerts WHERE active = 1 ORDER BY alert_timestamp DESC, alert_id LIMIT ?", (window,),
    )
    for alert in alerts:
        activities.append({
            "timestamp": alert["alert_timestamp"], "kind": "detection", "label": alert["detection_name"],
            "detail": f"{alert['severity'].title()} · {alert['status']} · {alert['rule_id']}",
            "reference": alert["alert_id"], "target": "alert", "raw_message": alert["explanation"], "simulated": False,
        })
    notes = database.fetch_all("SELECT * FROM investigation_notes ORDER BY created_at DESC, note_id DESC LIMIT ?", (window,))
    for note in notes:
        reference = note["incident_id"] or note["alert_id"]
        activities.append({
            "timestamp": note["created_at"], "kind": "analyst", "label": f"Analyst note · {note['category']}",
            "detail": f"{note['author']} · {reference}", "reference": reference,
            "target": "incident" if note["incident_id"] else "alert",
            "raw_message": note["note"], "simulated": False,
        })
    history = database.fetch_all("SELECT * FROM status_history ORDER BY changed_at DESC, history_id DESC LIMIT ?", (window,))
    for item in history:
        target = "incident" if item["entity_type"] == "incident" else "alert" if item["entity_type"] == "alert" else "vulnerability"
        activities.append({
            "timestamp": item["changed_at"], "kind": "analyst", "label": f"{item['entity_type'].title()} status · {item['new_status']}",
            "detail": f"{item['entity_id']} · {item['previous_status'] or 'Initial'} → {item['new_status']}",
            "reference": item["entity_id"], "target": target, "raw_message": item["note"], "simulated": False,
        })
    return sorted(activities, key=lambda item: (item["timestamp"], item["reference"]), reverse=True)[:limit]
