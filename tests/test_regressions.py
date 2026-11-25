from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta

import pytest

from core.services import AppServices
from core.time_utils import from_storage
from detection.engine import DetectionEngine
from reporting.report_generator import render_html, render_markdown


def test_fixed_width_timestamps_preserve_range_boundaries_and_migrate(services, event_factory):
    event = event_factory(timestamp="2026-11-25T10:00:00.500000+11:00")
    services.events.add_many([event])
    stored = services.database.fetch_one("SELECT event_timestamp FROM security_events")["event_timestamp"]
    assert stored == "2026-11-24T23:00:00.500000Z"
    start = from_storage("2026-11-24T23:00:00.000000Z")
    assert len(services.metrics.events_in_range(start, event.timestamp + timedelta(seconds=1))) == 1
    assert services.metrics.events_in_range(start, event.timestamp) == []
    services.database.execute("UPDATE security_events SET event_timestamp = '2026-11-24T23:00:00Z' WHERE event_id = ?", (event.event_id,))
    restarted = AppServices(services.database.path)
    migrated = restarted.database.fetch_one("SELECT event_timestamp FROM security_events")["event_timestamp"]
    assert migrated == "2026-11-24T23:00:00.000000Z"


def test_password_spray_incident_and_filter_retain_all_targeted_users(services, event_factory):
    usernames = [f"target-{index}" for index in range(5)]
    events = [event_factory(f"2026-11-25T10:{index:02d}:00+11:00", username=username) for index, username in enumerate(usernames)]
    services.events.add_many(events)
    services.detection.run()
    alert = next(item for item in services.alerts.list() if item["rule_id"] == "SL-AUTH-005")
    incident_id = services.incidents.create("Account enumeration", "Review all supported evidence", "high", [alert["alert_id"]])
    incident = services.incidents.get(incident_id)
    assert json.loads(incident["affected_users_json"]) == usernames
    filtered = services.alerts.list(username="target-4")
    assert [item["alert_id"] for item in filtered] == [alert["alert_id"]]
    assert "target-0" in render_html(services.database, incident_id)


def test_saved_timezone_is_applied_after_restart(services):
    services.settings.set("timezone", "UTC")
    restarted = AppServices(services.database.path)
    assert restarted.settings.get("timezone") == "UTC"
    assert restarted.ingestion.default_timezone == "UTC"
    assert restarted.metrics.zone.key == "UTC"


def test_invalid_rule_timezone_is_a_validation_error(services):
    rule = services.rules.get("SL-AUTH-003")
    invalid = replace(rule, config={**rule.config, "timezone": "Mars/Unknown"})
    with pytest.raises(ValueError, match="unknown IANA timezone"):
        DetectionEngine._validate_rule(invalid)


def test_malformed_json_records_are_counted_and_do_not_abort_valid_records(services):
    good_one = {"timestamp": "2026-11-25T10:00:00+11:00", "raw_message": "json-one"}
    good_two = {"timestamp": "2026-11-25T10:01:00+11:00", "raw_message": "json-two"}
    result = services.ingestion.ingest_bytes("array.json", json.dumps([good_one, {"timestamp": "bad"}, good_two]).encode())
    assert (result.received, result.accepted, result.rejected) == (3, 2, 1)
    good_three = {"timestamp": "2026-11-25T10:02:00+11:00", "raw_message": "json-three"}
    malformed_lines = '{"timestamp":"bad-json"\nnot-json\n' + json.dumps(good_three)
    lines = services.ingestion.ingest_bytes("records.jsonl", malformed_lines.encode())
    assert (lines.received, lines.accepted, lines.rejected) == (3, 1, 2)


def test_reopening_clears_stale_resolution_summary_and_report_conclusion(services, event_factory):
    events = [event_factory(f"2026-11-25T10:{index:02d}:00+11:00") for index in range(5)]
    services.events.add_many(events)
    services.detection.run()
    alert = services.alerts.list()[0]
    incident_id = services.incidents.create("Reopenable case", "Investigation continues", "medium", [alert["alert_id"]])
    services.incidents.update_status(incident_id, "Resolved", "A historical conclusion no longer applies")
    services.incidents.update_status(incident_id, "Investigating")
    incident = services.incidents.get(incident_id)
    assert incident["resolution_summary"] == "" and incident["resolved_at"] is None
    assert "A historical conclusion" not in render_markdown(services.database, incident_id)
    assert "A historical conclusion" not in render_html(services.database, incident_id)
