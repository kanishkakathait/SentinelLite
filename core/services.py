from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from core.config import DATABASE_PATH, DEFAULT_TIMEZONE, SAMPLE_EVENTS_FILE, SAMPLE_GROUND_TRUTH_FILE
from core.database import Database
from core.metrics import DashboardMetrics
from core.repositories import AlertRepository, EventRepository, RuleRepository, SettingsRepository
from detection.engine import DetectionEngine
from ingestion.normalisation import normalise_record
from ingestion.service import IngestionService
from investigations.incident_manager import IncidentManager
from investigations.vulnerabilities import VulnerabilityService
from simulation.generate_logs import generate_dataset
from simulation.scenarios import scenario_definitions


class AppServices:
    def __init__(self, database_path: str | Path = DATABASE_PATH, timezone: str | None = None):
        self.database = Database(database_path)
        self.database.initialise()
        self.events = EventRepository(self.database)
        self.rules = RuleRepository(self.database)
        self.rules.sync_defaults()
        self.alerts = AlertRepository(self.database)
        self.settings = SettingsRepository(self.database)
        timezone = timezone or self.settings.get("timezone", DEFAULT_TIMEZONE)
        self.ingestion = IngestionService(self.database, timezone)
        self.detection = DetectionEngine(self.database, timezone)
        self.incidents = IncidentManager(self.database)
        self.vulnerabilities = VulnerabilityService(self.database)
        self.metrics = DashboardMetrics(self.database, timezone)

    def load_demonstration(self) -> dict[str, Any]:
        if not SAMPLE_EVENTS_FILE.exists() or not SAMPLE_GROUND_TRUTH_FILE.exists():
            generate_dataset()
        ingestion = self.ingestion.ingest_bytes(SAMPLE_EVENTS_FILE.name, SAMPLE_EVENTS_FILE.read_bytes(), simulated=True)
        detection = self.detection.run()
        vulnerabilities = self.vulnerabilities.seed_demonstration_records()
        return {"ingestion": ingestion, "detection": detection, "vulnerabilities": vulnerabilities}

    def rule_test_events(self, rule_id: str):
        if not SAMPLE_EVENTS_FILE.exists() or not SAMPLE_GROUND_TRUTH_FILE.exists():
            generate_dataset()
        with SAMPLE_GROUND_TRUTH_FILE.open(encoding="utf-8", newline="") as handle:
            ground_truth = list(csv.DictReader(handle))
        scenario_id = next(
            row["scenario_id"] for definition in scenario_definitions()
            if rule_id in definition.expected_rules
            for row in ground_truth if row["scenario_id"] == definition.scenario_id
        )
        document = json.loads(SAMPLE_EVENTS_FILE.read_text(encoding="utf-8"))
        records = [
            record for record in document["events"]
            if record.get("scenario_id") == scenario_id
        ]
        return [normalise_record(record, "sample", DEFAULT_TIMEZONE, simulated=True) for record in records]

    def ingestion_batches(self, limit: int = 20) -> list[dict[str, Any]]:
        return [dict(row) for row in self.database.fetch_all(
            "SELECT * FROM ingestion_batches ORDER BY created_at DESC, batch_id DESC LIMIT ?", (limit,)
        )]
