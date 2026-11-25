from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from ingestion.normalisation import normalise_record


def csv_bytes(rows):
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["timestamp", "hostname", "source_ip", "username", "event_category", "event_action", "authentication_result", "raw_message"])
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue().encode()


def basic_record(**changes):
    record = {
        "timestamp": "2026-11-25T10:00:00+11:00", "hostname": "host-a",
        "source_ip": "192.0.2.10", "username": "alice", "event_category": "authentication",
        "event_action": "login", "authentication_result": "failure", "raw_message": "raw login event",
    }
    record.update(changes)
    return record


def test_csv_ingestion_normalises_and_reports_malformed_records(services):
    content = csv_bytes([basic_record(), basic_record(timestamp="not-a-time")])
    result = services.ingestion.ingest_bytes("events.csv", content)
    assert (result.received, result.accepted, result.rejected) == (2, 1, 1)
    assert len(result.errors) == 1
    event = services.events.all()[0]
    assert event.timestamp.isoformat() == "2026-11-24T23:00:00+00:00"
    assert event.authentication_result == "failure"


def test_exact_duplicates_are_idempotent_across_reimports(services):
    content = csv_bytes([basic_record()])
    first = services.ingestion.ingest_bytes("events.json", json.dumps(basic_record()).encode())
    second = services.ingestion.ingest_bytes("events.csv", content)
    third = services.ingestion.ingest_bytes("events.csv", content)
    assert first.accepted == 1
    assert second.accepted == 0 and second.duplicates == 1
    assert third.accepted == 0 and third.duplicates == 1
    assert services.events.count() == 1
    assert len(services.ingestion_batches()) == 3


def test_missing_entity_fields_remain_null(services):
    result = services.ingestion.ingest_bytes("event.json", json.dumps(basic_record(source_ip=None, username=None)).encode())
    assert result.accepted == 1
    event = services.events.all()[0]
    assert event.source_ip is None and event.username is None


def test_json_array_single_object_and_json_lines(services):
    records = [basic_record(raw_message="one"), basic_record(raw_message="two")]
    array_result = services.ingestion.ingest_bytes("array.json", json.dumps(records).encode())
    object_result = services.ingestion.ingest_bytes("object.json", json.dumps(basic_record(raw_message="three")).encode())
    lines_result = services.ingestion.ingest_bytes("records.jsonl", b'{"timestamp":"bad"}\n' + json.dumps(basic_record(raw_message="four")).encode())
    assert array_result.accepted == 2
    assert object_result.accepted == 1
    assert lines_result.accepted == 1 and lines_result.rejected == 1
    assert services.events.count() == 4


def test_empty_and_invalid_json_is_handled_without_a_crash(services):
    empty = services.ingestion.ingest_bytes("empty.json", b"")
    invalid = services.ingestion.ingest_bytes("invalid.json", b'{"events": "not-an-array"}')
    ndjson = services.ingestion.ingest_bytes("invalid.jsonl", b"not-json\n")
    assert empty.received == 0 and services.events.count() == 0
    assert invalid.rejected == 1 and ndjson.rejected == 1


def test_invalid_ip_address_is_rejected_without_inventing_an_entity(services):
    result = services.ingestion.ingest_bytes("event.json", json.dumps(basic_record(source_ip="not-an-ip")).encode())
    assert result.accepted == 0 and result.rejected == 1
    assert "Source IP" in result.errors[0].message
    assert services.events.count() == 0


def test_csv_parser_errors_are_reported_without_aborting_the_interface(services):
    content = b"timestamp,raw_message\n2026-11-25T10:00:00+11:00," + b"x" * 131_073
    result = services.ingestion.ingest_bytes("oversized-field.csv", content)
    assert result.accepted == 0 and result.rejected == 1
    assert services.events.count() == 0


def test_unsupported_type_size_and_utf8_limits(services, monkeypatch):
    with pytest.raises(ValueError, match="Unsupported file type"):
        services.ingestion.ingest_bytes("payload.exe", b"binary")
    monkeypatch.setattr("ingestion.service.MAX_UPLOAD_BYTES", 10)
    with pytest.raises(ValueError, match="upload limit"):
        services.ingestion.ingest_bytes("large.json", b"12345678901")
    monkeypatch.setattr("ingestion.service.MAX_UPLOAD_BYTES", 100)
    with pytest.raises(ValueError, match="UTF-8"):
        services.ingestion.ingest_bytes("invalid.json", b"\xff\xfe")


def test_linux_ssh_auth_log_supports_iso_and_traditional_timestamps(services):
    iso = "2026-11-25T10:01:02+11:00 host sshd[22]: Failed password for invalid user admin from 203.0.113.7 port 2022 ssh2"
    traditional = "Nov 25 10:02:03 host sshd[23]: Accepted publickey for alice from 203.0.113.8 port 2023 ssh2"
    result = services.ingestion.ingest_bytes("auth.log", f"{iso}\n{traditional}\nnot-an-ssh-event\n".encode())
    assert result.accepted == 2 and result.rejected == 1
    assert {event.authentication_result for event in services.events.all()} == {"success", "failure"}
    expected_year = datetime.now(ZoneInfo("Australia/Melbourne")).year
    traditional_event = next(event for event in services.events.all() if event.authentication_result == "success")
    assert traditional_event.timestamp.year == expected_year


def test_untrusted_log_content_is_stored_as_text_not_executed(services):
    payload = "<script>alert('xss')</script>; $(touch /tmp/should-not-exist)"
    result = services.ingestion.ingest_bytes("safe.json", json.dumps(basic_record(raw_message=payload)).encode())
    assert result.accepted == 1
    assert services.events.all()[0].raw_message == payload


def test_naive_timestamp_requires_configured_timezone():
    event = normalise_record(basic_record(timestamp="2026-01-15T09:00:00"), "test", "Australia/Melbourne")
    assert event.timestamp.isoformat() == "2026-01-14T22:00:00+00:00"
    with pytest.raises(ValueError, match="Malformed"):
        normalise_record(basic_record(timestamp="2026-99-99T00:00:00Z"), "test", "UTC")
