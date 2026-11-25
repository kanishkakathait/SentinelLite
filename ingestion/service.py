from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

from core.config import MAX_ERROR_SAMPLES, MAX_RECORDS, MAX_UPLOAD_BYTES
from core.database import Database
from core.models import IngestionIssue, IngestionResult, SecurityEvent
from core.repositories import EventRepository
from core.time_utils import to_storage, utc_now
from ingestion.csv_parser import iter_csv_records
from ingestion.json_parser import iter_json_records
from ingestion.linux_auth_parser import parse_linux_auth_line
from ingestion.normalisation import normalise_record


class IngestionService:
    def __init__(self, database: Database, default_timezone: str):
        self.database = database
        self.events = EventRepository(database)
        self.default_timezone = default_timezone

    def _records(self, text: str, suffix: str, format_name: str):
        if format_name == "csv":
            yield from iter_csv_records(text)
        elif format_name == "json":
            yield from iter_json_records(text, suffix)
        else:
            for line_number, line in enumerate(text.splitlines(), start=1):
                if line.strip():
                    yield line_number, line.strip()

    def ingest_bytes(
        self,
        filename: str,
        content: bytes,
        default_timezone: str | None = None,
        simulated: bool = False,
        ingestion_timestamp: datetime | None = None,
        reference_year: int | None = None,
        allow_generic_ssh: bool = False,
    ) -> IngestionResult:
        if len(content) > MAX_UPLOAD_BYTES:
            raise ValueError("File exceeds the 10 MiB upload limit")
        suffix = Path(filename).suffix.casefold()
        formats = {".csv": "csv", ".json": "json", ".jsonl": "json", ".log": "linux_auth", ".txt": "linux_auth"}
        if suffix not in formats:
            raise ValueError("Unsupported file type; use CSV, JSON, JSONL, LOG, or TXT")
        format_name = formats[suffix]
        result = IngestionResult(filename=Path(filename).name, format=format_name)
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("Files must contain valid UTF-8 text") from error
        timezone = default_timezone or self.default_timezone
        events: list[SecurityEvent] = []
        seen_in_file: set[str] = set()
        duplicates = 0
        total = 0
        try:
            for record_number, record in self._records(text, suffix, format_name):
                total += 1
                if total > MAX_RECORDS:
                    raise ValueError(f"Input exceeds the {MAX_RECORDS:,} record limit")
                try:
                    if isinstance(record, ValueError):
                        raise record
                    if format_name == "linux_auth":
                        record = parse_linux_auth_line(record, timezone, reference_year=reference_year, allow_generic_ssh=allow_generic_ssh)
                    event = normalise_record(
                        record, format_name, timezone, simulated, ingestion_timestamp=ingestion_timestamp
                    )
                    if event.event_id in seen_in_file:
                        duplicates += 1
                    else:
                        events.append(event)
                        seen_in_file.add(event.event_id)
                except ValueError as error:
                    result.rejected += 1
                    if len(result.errors) < MAX_ERROR_SAMPLES:
                        result.errors.append(IngestionIssue(record_number, str(error)))
        except (ValueError, json.JSONDecodeError, csv.Error) as error:
            if total == 0:
                total = 1
            result.rejected = max(1, result.rejected)
            if len(result.errors) < MAX_ERROR_SAMPLES:
                result.errors.append(IngestionIssue(max(1, total), str(error)))
        result.received = total
        accepted, stored_duplicates = self.events.add_many(events)
        result.accepted = accepted
        result.duplicates = duplicates + stored_duplicates
        batch_id = self.database.execute(
            """
            INSERT INTO ingestion_batches (
                filename, format, received_records, accepted_records, duplicate_records,
                rejected_records, errors_json, simulated, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.filename, result.format, result.received, result.accepted, result.duplicates,
                result.rejected, json.dumps([issue.__dict__ for issue in result.errors]),
                int(simulated), to_storage(utc_now()),
            ),
        )
        result.batch_id = batch_id
        return result
