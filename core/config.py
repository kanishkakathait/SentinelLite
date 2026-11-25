from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
SAMPLE_DATA_DIR = DATA_DIR / "sample"
GENERATED_DATA_DIR = DATA_DIR / "generated"
RULES_DIR = PROJECT_ROOT / "detection" / "rules"
SCHEMA_FILE = PROJECT_ROOT / "core" / "schema.sql"
DATABASE_PATH = Path(os.environ.get("SENTINELLITE_DB_PATH", DATA_DIR / "sentinellite.db"))
SAMPLE_EVENTS_FILE = SAMPLE_DATA_DIR / "synthetic_events.json"
SAMPLE_GROUND_TRUTH_FILE = SAMPLE_DATA_DIR / "ground_truth.csv"
DEFAULT_TIMEZONE = "Australia/Melbourne"
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_RECORDS = 100_000
MAX_ERROR_SAMPLES = 100
ALLOWED_UPLOAD_SUFFIXES = {".csv", ".json", ".jsonl", ".log", ".txt"}
ALERT_STATUSES = ("New", "Investigating", "Resolved", "False Positive", "Closed")
INCIDENT_STATUSES = ("Open", "Investigating", "Contained", "Resolved", "Closed")
REMEDIATION_STATUSES = ("Open", "In Progress", "Remediated", "Verified")
SEVERITIES = ("critical", "high", "medium", "low", "informational")
