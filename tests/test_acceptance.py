from __future__ import annotations

from core.config import SAMPLE_GROUND_TRUTH_FILE, SAMPLE_EVENTS_FILE
from core.services import AppServices
from detection.evaluation import evaluate_detections, load_ground_truth
from reporting.report_generator import render_html, render_markdown


def test_complete_generate_ingest_detect_investigate_export_restart_acceptance(tmp_path):
    database = tmp_path / "acceptance.db"
    services = AppServices(database)
    outcome = services.load_demonstration()
    assert SAMPLE_EVENTS_FILE.exists()
    assert outcome["ingestion"].accepted == 1100
    assert services.events.count() == 1100
    assert outcome["detection"].active > 0
    evaluation = evaluate_detections(services.database, load_ground_truth(SAMPLE_GROUND_TRUTH_FILE))
    assert (evaluation.true_positives, evaluation.false_positives, evaluation.false_negatives) == (18, 0, 0)
    alert = next(item for item in services.alerts.list() if item["rule_id"] == "SL-AUTH-002")
    services.alerts.update_status(alert["alert_id"], "Investigating")
    services.alerts.add_note(alert["alert_id"], "Supporting evidence", "Reviewed the full six-event sequence")
    assert services.alerts.evidence(alert["alert_id"])
    incident_id = services.incidents.create(
        "Suspicious successful authentication", "Validate the selected event sequence and legitimate alternatives.",
        "high", [alert["alert_id"]], "Confirm activity with the account owner before response.",
    )
    services.incidents.update_status(incident_id, "Investigating")
    services.incidents.add_note(incident_id, "Risk assessment", "Suspicious sequence; impact and likelihood remain unverified")
    services.incidents.update_status(incident_id, "Resolved", "Synthetic scenario validated with no real-world impact")
    markdown = render_markdown(services.database, incident_id)
    html = render_html(services.database, incident_id)
    assert incident_id.replace("-", "\\-") in markdown and incident_id in html
    assert all(f"## {number}." in markdown for number in range(1, 10))
    assert outcome["vulnerabilities"] == 5
    restarted = AppServices(database)
    assert restarted.events.count() == 1100
    assert restarted.incidents.get(incident_id)["status"] == "Resolved"
    assert restarted.alerts.get(alert["alert_id"])["status"] == "Investigating"
    assert restarted.incidents.notes(incident_id)[0]["category"] == "Risk assessment"
    assert restarted.metrics.summary()["total_events"] == 1100
    assert restarted.metrics.summary()["resolved_incidents"] == 1
    assert len(restarted.vulnerabilities.list()) == 5
    reimported = restarted.load_demonstration()
    assert reimported["ingestion"].accepted == 0
    assert reimported["ingestion"].duplicates == 1100
    assert restarted.events.count() == 1100
