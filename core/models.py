from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from core.time_utils import from_storage, to_storage


@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    timestamp: datetime
    event_source: str
    hostname: str | None
    source_ip: str | None
    destination_ip: str | None
    username: str | None
    event_category: str
    event_action: str
    authentication_result: str | None
    raw_message: str
    ingestion_timestamp: datetime
    simulated: bool = False

    @classmethod
    def from_row(cls, row: Any) -> SecurityEvent:
        return cls(
            event_id=row["event_id"],
            timestamp=from_storage(row["event_timestamp"]),
            event_source=row["event_source"],
            hostname=row["hostname"],
            source_ip=row["source_ip"],
            destination_ip=row["destination_ip"],
            username=row["username"],
            event_category=row["event_category"],
            event_action=row["event_action"],
            authentication_result=row["authentication_result"],
            raw_message=row["raw_message"],
            ingestion_timestamp=from_storage(row["ingestion_timestamp"]),
            simulated=bool(row["simulated"]),
        )

    def storage_values(self) -> tuple[object, ...]:
        return (
            self.event_id,
            to_storage(self.timestamp),
            self.event_source,
            self.hostname,
            self.source_ip,
            self.destination_ip,
            self.username,
            self.event_category,
            self.event_action,
            self.authentication_result,
            self.raw_message,
            to_storage(self.ingestion_timestamp),
            int(self.simulated),
        )


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    name: str
    description: str
    severity: str
    enabled: bool
    config: dict[str, Any]
    documentation: str
    recommended_actions: tuple[str, ...]


@dataclass
class DetectionResult:
    rule: RuleDefinition
    evidence: list[SecurityEvent]
    explanation: str
    severity_justification: str
    details: dict[str, Any] = field(default_factory=dict)
    source_ip: str | None = None
    username: str | None = None
    hostname: str | None = None
    anchor_event_id: str | None = None

    @property
    def deduplication_key(self) -> str:
        anchor = self.anchor_event_id or self.evidence[0].event_id
        return "|".join(
            (self.rule.rule_id, self.source_ip or "", self.username or "", anchor)
        )


@dataclass(frozen=True)
class IngestionIssue:
    record: int
    message: str


@dataclass
class IngestionResult:
    filename: str
    format: str
    received: int = 0
    accepted: int = 0
    duplicates: int = 0
    rejected: int = 0
    errors: list[IngestionIssue] = field(default_factory=list)
    batch_id: int | None = None

    @property
    def issue_summary(self) -> str:
        return f"{self.accepted} accepted, {self.duplicates} duplicates, {self.rejected} rejected"
