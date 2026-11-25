from __future__ import annotations

import io

import pytest
from streamlit.testing.v1 import AppTest
from pathlib import Path

from core.services import AppServices
from ingestion.linux_auth_parser import parse_linux_auth_line
from ingestion.normalisation import normalise_record
from ingestion.public_datasets import download_bytes, load_loghub_events, public_dataset_manifest
from reporting.public_evaluation import evaluate_public_bytes

APP = Path(__file__).resolve().parent.parent / "app.py"


def test_generic_public_sshd_message_gets_explicit_reference_timestamp():
    raw = "Dec 10 07:07:45 LabSZ sshd[24206]: Invalid user webmaster from 173.234.31.186"
    record = parse_linux_auth_line(raw, "UTC", reference_year=2015, allow_generic_ssh=True)
    event = normalise_record(record, "public_fixture", "UTC")
    assert record["username"] is None and record["source_ip"] is None
    assert record["event_category"] == "system"
    assert record["authentication_result"] is None
    assert event.timestamp.isoformat() == "2015-12-10T07:07:45+00:00"
    assert event.source_ip is None and event.username is None and event.simulated is False
    assert event.raw_message == raw
    with pytest.raises(ValueError, match="Unsupported sshd"):
        parse_linux_auth_line(raw, "UTC", allow_generic_ssh=False)


def test_download_size_limit_and_checksum_validation(services, monkeypatch):
    monkeypatch.setattr("ingestion.public_datasets.urlopen", lambda request, timeout: io.BytesIO(b"12345"))
    with pytest.raises(ValueError, match="exceeded"):
        download_bytes("https://localhost.invalid/test", maximum_bytes=4)
    manifest = public_dataset_manifest()
    manifest["downloaded_sha256"] = "not-the-source-hash"
    before = services.events.count()
    with pytest.raises(ValueError, match="checksum"):
        evaluate_public_bytes(services, manifest, b"original content")
    assert services.events.count() == before


def test_public_dataset_complete_import_and_original_records(services):
    manifest, content = load_loghub_events()
    result = evaluate_public_bytes(services, manifest, content)
    assert result.raw_record_lines == 2000
    assert result.ingestion.accepted == 2000
    assert result.ingestion.duplicates == 0
    assert result.ingestion.rejected == 0
    assert result.authentication_event_count == 519
    assert len(result.normalised_event_ids) == 2000
    assert len(result.linked_alerts) == 222
    expected_rules = [
        ("SL-AUTH-003", "Authentication outside expected hours", 110),
        ("SL-AUTH-001", "Repeated failed authentication from one source", 77),
        ("SL-AUTH-004", "Privileged account authentication review", 18),
        ("SL-AUTH-005", "Multiple distinct accounts from one source", 17),
    ]
    assert result.rules == expected_rules
    assert not any(alert["rule_id"] == "SL-AUTH-002" for alert in result.linked_alerts)
    assert services.database.fetch_one("SELECT SUM(simulated) AS count FROM security_events")["count"] in (0, None)
    report = result.report_markdown()
    assert "Loghub: A Large Collection" in report
    assert "ISSRE" in report
    assert "Precision, recall, and false-positive rates are not calculated" in report
    assert "Year 2015 and UTC are explicit normalisation conventions" in report
    stored_source_messages = {event.raw_message.strip() for event in services.events.all()}
    assert stored_source_messages == {line.strip() for line in content.decode("utf-8").splitlines()}
    assert manifest["raw_records_modified"] is False


def test_public_import_replay_is_duplicate_safe_and_restart_persistent(services):
    manifest, content = load_loghub_events()
    first = evaluate_public_bytes(services, manifest, content)
    first_ids = {item["alert_id"] for item in first.linked_alerts}
    second = evaluate_public_bytes(services, manifest, content)
    assert second.ingestion.accepted == 0
    assert second.ingestion.duplicates == 2000
    assert second.ingestion.rejected == 0
    assert services.events.count() == 2000
    assert len(second.linked_alerts) == len(first.linked_alerts)
    assert second.detection.created == 0
    restarted = AppServices(services.database.path)
    assert restarted.events.count() == 2000
    assert first_ids == {item["alert_id"] for item in restarted.alerts.list()}


def test_public_dataset_button_runs_actual_import(tmp_path, monkeypatch):
    db_path = tmp_path / "public-import-ui.db"
    monkeypatch.setenv("SENTINELLITE_DB_PATH", str(db_path))
    app = AppTest.from_file(str(APP), default_timeout=90)
    app.run()
    app.session_state["navigation"] = "Security Events"
    app.run()
    assert not app.exception
    app.button(key="load_public_evaluation").click().run()
    assert not app.exception
    services = AppServices(db_path)
    assert services.events.count() == 2000
    assert len(services.alerts.list()) == 222
    assert services.database.fetch_one("SELECT SUM(simulated) AS count FROM security_events")["count"] in (0, None)
