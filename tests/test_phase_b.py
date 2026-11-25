from __future__ import annotations

import pytest

from core.activity import recent_activity
from investigations.timeline import incident_timeline
from reporting.report_generator import incident_report_data, render_html, render_markdown


def incident_fixture(services, event_factory):
    events = [event_factory(f"2026-11-25T10:{index:02d}:00+11:00") for index in range(5)]
    events.append(event_factory("2026-11-25T10:05:00+11:00", result="success"))
    services.events.add_many(events)
    services.detection.run()
    alert_ids = [item["alert_id"] for item in services.alerts.list()]
    incident_id = services.incidents.create("Visual timeline investigation", "Investigate failed and successful authentication records", "high", alert_ids)
    return incident_id


def test_visual_timeline_preserves_exact_order_markers_and_references(services, event_factory):
    incident_id = incident_fixture(services, event_factory)
    services.incidents.add_note(incident_id, "Supporting evidence", "Analyst observation before visual timeline review")
    entries = incident_timeline(services.database, incident_id)
    assert [entry["timestamp"] for entry in entries] == sorted(entry["timestamp"] for entry in entries)
    assert {entry["marker"] for entry in entries}.issuperset({"failure", "success", "detection", "alert", "analyst"})
    assert all(entry["reference"] for entry in entries)
    security_events = [entry for entry in entries if entry["entity_type"] == "security_event"]
    assert len(security_events) == 6
    assert security_events[0]["title"] == "Failed authentication"
    assert security_events[-1]["title"] == "Successful authentication"
    assert all(services.events.get(entry["reference"]) is not None for entry in security_events)


def test_note_edits_preserve_creation_timestamp_and_are_audited(services, event_factory):
    incident_id = incident_fixture(services, event_factory)
    note_id = services.incidents.add_note(incident_id, "Initial observations", "Original observation", "First Analyst")
    created = services.incidents.notes(incident_id)[0]["created_at"]
    services.incidents.update_note(incident_id, note_id, "Supporting evidence", "Edited factual summary", "Second Analyst")
    notes = services.incidents.notes(incident_id)
    assert len(notes) == 1
    assert notes[0]["note"] == "Edited factual summary"
    assert notes[0]["category"] == "Supporting evidence"
    assert notes[0]["author"] == "Second Analyst"
    assert notes[0]["created_at"] == created
    assert notes[0]["last_edited_at"]
    audit = services.database.fetch_one("SELECT * FROM audit_log WHERE action = 'investigation_note_edited' AND entity_id = ?", (str(note_id),))
    assert audit["entity_type"] == "investigation_note"
    with pytest.raises(ValueError, match="not found"):
        services.incidents.update_note(incident_id, 999_999, "Recommended response", "Invalid note reference", "Analyst")


def test_incident_status_workflow_and_timeline_note_metadata(services, event_factory):
    incident_id = incident_fixture(services, event_factory)
    for status in ("Investigating", "Contained"):
        services.incidents.update_status(incident_id, status)
    assert services.incidents.get(incident_id)["status"] == "Contained"
    services.incidents.update_status(incident_id, "Resolved", "Evidence validated; no production impact from this synthetic record")
    services.incidents.update_status(incident_id, "Investigating")
    assert services.incidents.get(incident_id)["resolution_summary"] == ""
    with pytest.raises(ValueError, match="Invalid incident status"):
        services.incidents.update_status(incident_id, "Compromised")
    entries = recent_activity(services.database, 50)
    assert any(item["target"] == "incident" for item in entries)


def test_nine_part_reports_share_real_data_and_escape_untrusted_text(services, event_factory):
    incident_id = incident_fixture(services, event_factory)
    services.incidents.add_note(incident_id, "Supporting evidence", "<script>alert('unsafe')</script>\n![pixel](https://example.invalid/x.png) | table")
    services.incidents.update_status(incident_id, "Resolved", "Synthetic review complete with explicit residual uncertainty")
    data = incident_report_data(services.database, incident_id)
    assert sum(len(events) for events in data["evidence_by_alert"].values()) == 11
    assert len(data["timeline"]) > 6
    markdown = render_markdown(services.database, incident_id, data)
    html = render_html(services.database, incident_id, data)
    for number in range(1, 10):
        assert f"## {number}." in markdown
        assert f"<h2>{number}." in html
    assert "SECURITY OPERATIONS" in html
    assert "Public/manual only" in markdown
    assert "<script>" not in markdown and "<script>" not in html
    assert "![pixel]" not in markdown
    assert "&lt;script&gt;" in markdown and "&lt;script&gt;" in html
    assert "table" in markdown
