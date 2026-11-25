from __future__ import annotations

import argparse
import csv
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from core.config import SAMPLE_DATA_DIR
from core.time_utils import to_storage, utc_now
from ingestion.normalisation import normalise_record
from simulation.scenarios import business_and_off_hours, event_record, scenario_definitions


def _canonical_record(raw: dict, end: datetime) -> dict:
    raw_message = raw.get("raw_message") or f"[SIMULATED] {raw.get('scenario_id', 'routine')} authentication on {raw['hostname']}"
    raw["raw_message"] = raw_message
    event = normalise_record(raw, "synthetic_auth", "Australia/Melbourne", ingestion_timestamp=end)
    return {
        "event_id": event.event_id,
        "timestamp": to_storage(event.timestamp),
        "event_source": event.event_source,
        "hostname": event.hostname,
        "source_ip": event.source_ip,
        "destination_ip": event.destination_ip,
        "username": event.username,
        "event_category": event.event_category,
        "event_action": event.event_action,
        "authentication_result": event.authentication_result,
        "raw_message": event.raw_message,
        "simulated": True,
        "scenario_id": raw.get("scenario_id", "normal"),
    }


def _normal_events(end: datetime, seed: int) -> list[dict]:
    start = end - timedelta(hours=24)
    zone = ZoneInfo("Australia/Melbourne")
    candidates = []
    step = (end - start) / 3000
    for index in range(3000):
        candidate = start + index * step
        local = candidate.astimezone(zone)
        if 8 <= local.hour < 18:
            candidates.append(candidate)
    if len(candidates) < 1000:
        raise ValueError("The selected 24-hour range has insufficient business-hours coverage")
    users = ["amy", "ben", "chloe", "daniel", "emma", "finn", "georgia", "harry", "isla", "jack", "kiara", "liam"]
    random.Random(seed).shuffle(users)
    records = []
    for index in range(1000):
        timestamp = candidates[(index * len(candidates)) // 1000]
        result = "failure" if index % 13 == 0 else "success"
        hostname = f"mel-ws-{1 + index % 20:02d}"
        raw = event_record("normal", timestamp, f"198.51.100.{1 + index % 200}", users[index % len(users)], result, hostname)
        raw["raw_message"] = f"[SIMULATED] routine {result} authentication on {hostname}"
        records.append(_canonical_record(raw, end))
    return records


def generate_dataset(output_directory: Path = SAMPLE_DATA_DIR, seed: int = 42, end: datetime | None = None) -> dict[str, int]:
    end = (end or utc_now()).astimezone(timezone.utc).replace(microsecond=0)
    business, off_hours = business_and_off_hours(end)
    normal = _normal_events(end, seed)
    suspicious = []
    ground_truth = []
    definitions = scenario_definitions()
    for definition in definitions:
        raw_records = definition.build(business, off_hours)
        for raw in raw_records:
            raw["raw_message"] = f"[SIMULATED][{definition.scenario_id}] {raw['authentication_result']} authentication on {raw['hostname']}"
            record = _canonical_record(raw, end)
            suspicious.append(record)
            ground_truth.append({
                "event_id": record["event_id"],
                "scenario_id": definition.scenario_id,
                "scenario_label": definition.label,
                "expected_rules": "|".join(definition.expected_rules),
            })
    if len(normal) != 1000 or len(suspicious) != 100:
        raise ValueError(f"Scenario totals must be 1000 normal and 100 suspicious, got {len(normal)} and {len(suspicious)}")
    all_records = sorted(normal + suspicious, key=lambda record: (record["timestamp"], record["event_id"]))
    output_directory.mkdir(parents=True, exist_ok=True)
    (output_directory / "synthetic_events.json").write_text(
        json.dumps({"description": "SIMULATED educational records only", "events": all_records}, indent=2), encoding="utf-8"
    )
    with (output_directory / "ground_truth.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["event_id", "scenario_id", "scenario_label", "expected_rules"])
        writer.writeheader()
        writer.writerows(ground_truth)
    metadata = {
        "simulated": True, "seed": seed, "normal_events": len(normal), "suspicious_events": len(suspicious),
        "total_events": len(all_records), "scenario_count": len(definitions), "generated_through": to_storage(end),
        "evaluation_unit": "scenario_id and rule_id pairs", "reserved_ip_ranges": ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
    }
    (output_directory / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate clearly labelled SentinelLite synthetic security data")
    parser.add_argument("--output", type=Path, default=SAMPLE_DATA_DIR)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--end", type=str, help="ISO-8601 dataset end time; defaults to current UTC")
    arguments = parser.parse_args()
    end = datetime.fromisoformat(arguments.end.replace("Z", "+00:00")) if arguments.end else None
    metadata = generate_dataset(arguments.output, arguments.seed, end)
    print(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
