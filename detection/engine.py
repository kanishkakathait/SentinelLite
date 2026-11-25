from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import time
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from core.database import Database
from core.models import DetectionResult, SecurityEvent
from core.repositories import AlertRepository, EventRepository, RuleRepository
from core.time_utils import to_storage, utc_now
from detection.scenarios import DETECTORS, is_authentication


@dataclass
class DetectionRun:
    findings: int
    created: int
    refreshed: int
    superseded: int
    active: int


class DetectionEngine:
    def __init__(self, database: Database, timezone: str = "Australia/Melbourne"):
        self.database = database
        self.timezone = timezone
        self.events = EventRepository(database)
        self.rules = RuleRepository(database)
        self.alerts = AlertRepository(database)

    @staticmethod
    def _validate_rule(rule) -> None:
        for key, value in rule.config.items():
            if key in {"failure_threshold", "distinct_account_threshold"}:
                if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 1000:
                    raise ValueError(f"{rule.rule_id}: {key} must be between 1 and 1000")
            if key in {"window_seconds", "session_window_seconds"}:
                if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 604800:
                    raise ValueError(f"{rule.rule_id}: {key} must be between 1 and 604800")
            if key == "minimum_indicators":
                if not isinstance(value, int) or not 2 <= value <= 3:
                    raise ValueError("minimum_indicators must be 2 or 3")
            if key in {"business_start", "business_end"}:
                time.fromisoformat(str(value))
            if key == "timezone":
                try:
                    ZoneInfo(str(value))
                except ZoneInfoNotFoundError as error:
                    raise ValueError(f"{rule.rule_id}: unknown IANA timezone") from error
        if rule.rule_id not in DETECTORS:
            raise ValueError(f"No detector is registered for {rule.rule_id}")

    def detect_events(
        self,
        events: list[SecurityEvent],
        rule_ids: set[str] | None = None,
        include_disabled: bool = False,
    ) -> list[DetectionResult]:
        ordered_events = sorted(events, key=lambda event: (event.timestamp, event.event_id))
        authentication = [event for event in ordered_events if is_authentication(event)]
        findings: list[DetectionResult] = []
        for rule in self.rules.list():
            if rule_ids is not None and rule.rule_id not in rule_ids:
                continue
            if not rule.enabled and not include_disabled:
                continue
            self._validate_rule(rule)
            findings.extend(DETECTORS[rule.rule_id](authentication, rule))
        return sorted(
            findings,
            key=lambda finding: (
                max(event.timestamp for event in finding.evidence), finding.rule.rule_id, finding.deduplication_key
            ),
        )

    def run(self, events: list[SecurityEvent] | None = None) -> DetectionRun:
        events = events if events is not None else self.events.all()
        findings = self.detect_events(events)
        existing_rows = self.database.fetch_all("SELECT alert_id, deduplication_key, created_at FROM security_alerts")
        existing = {row["deduplication_key"]: dict(row) for row in existing_rows}
        created = 0
        refreshed = 0
        now = to_storage(utc_now())
        with self.database.connection() as connection:
            for finding in findings:
                key = finding.deduplication_key
                alert_id = "ALT-" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:24]
                previous = existing.get(key)
                created_at = previous["created_at"] if previous else now
                created += int(previous is None)
                refreshed += int(previous is not None)
                alert_timestamp = max(event.timestamp for event in finding.evidence)
                connection.execute(
                    """
                    INSERT INTO security_alerts (
                        alert_id, deduplication_key, rule_id, detection_name, alert_timestamp,
                        created_at, severity, source_ip, username, hostname, status, explanation,
                        severity_justification, details_json, active, superseded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'New', ?, ?, ?, 1, NULL)
                    ON CONFLICT(deduplication_key) DO UPDATE SET
                        rule_id = excluded.rule_id,
                        detection_name = excluded.detection_name,
                        alert_timestamp = excluded.alert_timestamp,
                        severity = excluded.severity,
                        source_ip = excluded.source_ip,
                        username = excluded.username,
                        hostname = excluded.hostname,
                        explanation = excluded.explanation,
                        severity_justification = excluded.severity_justification,
                        details_json = excluded.details_json,
                        active = 1,
                        superseded_at = NULL
                    """,
                    (
                        alert_id, key, finding.rule.rule_id, finding.rule.name, to_storage(alert_timestamp),
                        created_at, finding.rule.severity, finding.source_ip, finding.username or None,
                        finding.hostname, finding.explanation, finding.severity_justification,
                        json.dumps(finding.details, sort_keys=True),
                    ),
                )
                connection.execute("DELETE FROM alert_events WHERE alert_id = ?", (alert_id,))
                connection.executemany(
                    "INSERT INTO alert_events (alert_id, event_id, evidence_role) VALUES (?, ?, 'supporting')",
                    [(alert_id, event.event_id) for event in finding.evidence],
                )
            current_keys = {finding.deduplication_key for finding in findings}
            stale_ids = [row["alert_id"] for row in existing_rows if row["deduplication_key"] not in current_keys]
            superseded = 0
            if stale_ids:
                placeholders = ",".join("?" for _ in stale_ids)
                cursor = connection.execute(
                    f"UPDATE security_alerts SET active = 0, superseded_at = ? WHERE alert_id IN ({placeholders}) AND active = 1",
                    [now, *stale_ids],
                )
                superseded = cursor.rowcount
        active = self.database.fetch_one("SELECT COUNT(*) AS count FROM security_alerts WHERE active = 1")["count"]
        return DetectionRun(len(findings), created, refreshed, superseded, active)

    def dry_run(self, rule_id: str, events: list[SecurityEvent]) -> list[DetectionResult]:
        return self.detect_events(events, rule_ids={rule_id}, include_disabled=True)
