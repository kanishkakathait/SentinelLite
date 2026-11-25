from __future__ import annotations

import csv
import io
from datetime import date

import pytest

from core.services import AppServices
from investigations.risk import calculate_priority
from reporting.report_generator import render_html, render_markdown


def create_alert(services, factory):
    events = [factory(f"2026-11-25T10:{index:02d}:00+11:00") for index in range(5)]
    services.events.add_many(events)
    services.detection.run()
    return services.alerts.list()[0]


def test_alert_incident_notes_and_persistence(services, event_factory, tmp_path):
    alert = create_alert(services, event_factory)
    services.alerts.update_status(alert["alert_id"], "Investigating", "Reviewing")
    services.alerts.add_note(alert["alert_id"], "Possible explanations", "Could be stale browser credentials")
    incident_id = services.incidents.create("Authentication review", "Investigate the recorded repeated failures.", "medium", [alert["alert_id"]])
    services.incidents.update_status(incident_id, "Investigating")
    services.incidents.add_note(incident_id, "Final conclusion", "Synthetic validation only")
    services.incidents.update_status(incident_id, "Resolved", "Reviewed local synthetic records")
    reopened = AppServices(services.database.path)
    incident = reopened.incidents.get(incident_id)
    assert incident["status"] == "Resolved"
    assert reopened.alerts.get(alert["alert_id"])["status"] == "Investigating"
    assert len(reopened.incidents.notes(incident_id)) == 1
    assert len(reopened.alerts.notes(alert["alert_id"])) == 1
    assert reopened.metrics.summary()["resolved_incidents"] == 1


def test_incident_validation_and_explicit_correlation(services, event_factory):
    alert = create_alert(services, event_factory)
    with pytest.raises(ValueError, match="at least one alert"):
        services.incidents.create("Title", "Description", "medium", [])
    incident_id = services.incidents.create("Title", "Description", "medium", [alert["alert_id"]])
    with pytest.raises(ValueError, match="resolution summary"):
        services.incidents.update_status(incident_id, "Resolved")
    second = event_factory("2026-11-25T10:05:00+11:00", result="success")
    services.events.add_many([second])
    services.detection.run()
    suggestions = services.incidents.suggestions(alert["alert_id"])
    assert any(item["alert_id"] != alert["alert_id"] for item in suggestions)
    assert all(len(item["shared_fields"]) >= 2 for item in suggestions)


def test_resolution_timestamp_does_not_move_on_summary_edit(services, event_factory):
    alert = create_alert(services, event_factory)
    incident_id = services.incidents.create("Title", "Description", "medium", [alert["alert_id"]])
    services.incidents.update_status(incident_id, "Resolved", "Validated")
    original = services.incidents.get(incident_id)["resolved_at"]
    services.incidents.update_resolution_summary(incident_id, "Validated and clarified")
    assert services.incidents.get(incident_id)["resolved_at"] == original


def test_reports_use_records_and_escape_untrusted_content(services, event_factory):
    alert = create_alert(services, event_factory)
    incident_id = services.incidents.create("<script>title</script>", "Investigation of stored synthetic events", "medium", [alert["alert_id"]])
    payload = "<script>alert('unsafe')</script>\n![remote](https://example.invalid/track.png) | pipe"
    services.incidents.add_note(incident_id, "False-positive considerations", payload)
    services.incidents.update_status(incident_id, "Resolved", f"Reviewed. {payload}")
    markdown = render_markdown(services.database, incident_id)
    html = render_html(services.database, incident_id)
    assert all(f"## {number}." in markdown for number in range(1, 10))
    assert incident_id.replace("-", "\\-") in markdown
    assert alert["alert_id"].replace("-", "\\-") in markdown
    assert "<script>" not in markdown and "<script>" not in html
    assert "&lt;script&gt;" in markdown and "&lt;script&gt;" in html
    assert "![remote]" not in markdown and "!\\[remote\\]" in markdown
    assert "\\| pipe" in markdown
    assert "no automatic containment" in html.lower() or "no automatic containment" in markdown.lower()


def test_risk_score_is_transparent_and_distinct_from_cvss(services):
    critical = calculate_priority("critical", 5, "Internet-facing", "Confirmed")
    low = calculate_priority("informational", 1, "Isolated", "Reported")
    assert critical == {"score": 100, "level": "P1", "components": {"severity": 40, "asset_criticality": 30, "exposure": 20, "evidence": 10}}
    assert low["score"] == 13 and low["level"] == "P4"
    vulnerability_id = services.vulnerabilities.create({
        "title": "Example", "description": "Manual record", "affected_asset": "test-asset",
        "severity": "high", "discovery_date": "2026-11-25", "asset_criticality": 3,
        "exposure": "Internal", "evidence": "Observed", "cvss_score": 6.5,
        "remediation_recommendation": "Patch during change window", "remediation_owner": "Owner",
    })
    record = services.vulnerabilities.get(vulnerability_id)
    assert record["cvss_score"] == 6.5 and record["priority_score"] == 64
    assert record["priority_level"] == "P2"


def test_vulnerability_updates_import_and_demo_labels(services):
    identifier = services.vulnerabilities.create({
        "vulnerability_id": "TEST-VULN-001", "title": "Test vulnerability", "description": "Record only",
        "affected_asset": "test-asset", "severity": "low", "discovery_date": date.today().isoformat(),
        "asset_criticality": 2, "exposure": "Internal", "evidence": "Observed",
        "remediation_recommendation": "Correct configuration", "remediation_owner": "Owner",
        "due_date": "2020-01-01",
    })
    assert services.vulnerabilities.metrics()["overdue"] == 1
    services.vulnerabilities.update(identifier, "Verified", "Owner", "2026-12-01", "Evidence supplied", date.today().isoformat())
    assert services.vulnerabilities.get(identifier)["verification_date"] == date.today().isoformat()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["vulnerability_id", "title", "description", "affected_asset", "severity", "discovery_date", "asset_criticality", "exposure", "evidence", "remediation_recommendation", "remediation_owner"])
    writer.writeheader()
    writer.writerow({"vulnerability_id": f" {identifier} ", "title": "Duplicate", "description": "Duplicate", "affected_asset": "asset", "severity": "low", "discovery_date": "2026-11-25", "asset_criticality": 2, "exposure": "Internal", "evidence": "Observed", "remediation_recommendation": "Fix", "remediation_owner": "Owner"})
    result = services.vulnerabilities.import_csv(output.getvalue().encode())
    assert result["duplicates"] == 1 and result["created"] == 0
    assert services.vulnerabilities.seed_demonstration_records() == 5
    assert services.vulnerabilities.seed_demonstration_records() == 0
    assert all(item["title"].startswith("[DEMO]") for item in services.vulnerabilities.list() if item["vulnerability_id"].startswith("DEMO-"))
