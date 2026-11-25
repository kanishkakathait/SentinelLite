from __future__ import annotations

from datetime import datetime, time, timezone
from typing import Any
from zoneinfo import ZoneInfo

from core.database import Database
from core.time_utils import from_storage, to_storage, utc_now


class DashboardMetrics:
    def __init__(self, database: Database, timezone_name: str):
        self.database = database
        self.zone = ZoneInfo(timezone_name)

    def summary(self) -> dict[str, Any]:
        now = utc_now().astimezone(self.zone)
        start_local = datetime.combine(now.date(), time.min, tzinfo=self.zone)
        start_utc = start_local.astimezone(timezone.utc)
        total = self.database.fetch_one("SELECT COUNT(*) AS count FROM security_events")["count"]
        processed_today = self.database.fetch_one(
            "SELECT COUNT(*) AS count FROM security_events WHERE ingestion_timestamp >= ?", (to_storage(start_utc),)
        )["count"]
        open_alert_count = self.database.fetch_one(
            "SELECT COUNT(*) AS count FROM security_alerts WHERE active = 1 AND status IN ('New', 'Investigating')"
        )["count"]
        priority_alerts = self.database.fetch_one(
            "SELECT COUNT(*) AS count FROM security_alerts WHERE active = 1 AND severity IN ('critical', 'high')"
        )["count"]
        suspicious_ips = self.database.fetch_one(
            "SELECT COUNT(DISTINCT source_ip) AS count FROM security_alerts WHERE active = 1 AND source_ip IS NOT NULL"
        )["count"]
        open_incidents = self.database.fetch_one(
            "SELECT COUNT(*) AS count FROM incidents WHERE status IN ('Open', 'Investigating', 'Contained')"
        )["count"]
        resolved_incidents = self.database.fetch_one(
            "SELECT COUNT(*) AS count FROM incidents WHERE status IN ('Resolved', 'Closed')"
        )["count"]
        resolved = self.database.fetch_all("SELECT created_at, resolved_at FROM incidents WHERE resolved_at IS NOT NULL")
        durations = [(from_storage(row["resolved_at"]) - from_storage(row["created_at"])).total_seconds() / 3600 for row in resolved]
        return {
            "total_events": total, "events_today": processed_today,
            "open_alerts": open_alert_count, "critical_high_alerts": priority_alerts,
            "suspicious_ips": suspicious_ips, "open_incidents": open_incidents,
            "resolved_incidents": resolved_incidents,
            "mean_resolution_hours": sum(durations) / len(durations) if durations else None,
        }

    def events_in_range(self, start: datetime, end: datetime) -> list[dict[str, Any]]:
        return [dict(row) for row in self.database.fetch_all(
            """
            SELECT event_id, event_timestamp, authentication_result, event_category,
                source_ip, username, hostname, simulated
            FROM security_events WHERE event_timestamp >= ? AND event_timestamp < ?
            ORDER BY event_timestamp, event_id
            """, (to_storage(start), to_storage(end)),
        )]

    def alerts_in_range(self, start: datetime, end: datetime) -> list[dict[str, Any]]:
        return [dict(row) for row in self.database.fetch_all(
            """
            SELECT alert_id, alert_timestamp, detection_name, severity, source_ip,
                username, hostname, status FROM security_alerts
            WHERE active = 1 AND alert_timestamp >= ? AND alert_timestamp < ?
            ORDER BY alert_timestamp DESC, alert_id
            """, (to_storage(start), to_storage(end)),
        )]
