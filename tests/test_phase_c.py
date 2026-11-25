from __future__ import annotations

from datetime import datetime, timezone

import pytest
from streamlit.testing.v1 import AppTest
from pathlib import Path

from core.services import AppServices
from simulation.lab import SimulationLab

FIXED_TIME = datetime(2026, 11, 25, 3, 0, 0, tzinfo=timezone.utc)
APP = Path(__file__).resolve().parent.parent / "app.py"


@pytest.mark.parametrize(
    ("scenario", "expected_alerts"),
    [
        ("brute_force", 1), ("password_spraying", 2), ("suspicious_success", 2),
        ("privileged_activity", 1), ("off_hours_authentication", 1), ("correlated_authentication", 5),
    ],
)
def test_all_six_simulations_execute_real_detection_and_scoped_evaluation(services, scenario, expected_alerts):
    lab = SimulationLab(services)
    result = lab.run(scenario, end=FIXED_TIME)
    assert result.ingestion.accepted == len(result.events)
    assert len(result.alerts) == expected_alerts
    assert len(result.evaluation.true_positive_pairs) == len(result.scenario.expected_rules)
    assert result.evaluation.false_positives == 0
    assert result.evaluation.false_negatives == 0
    assert result.evaluation.recall == 1.0
    assert {event.event_id for event in result.events}
    assert services.database.fetch_one("SELECT COUNT(*) AS count FROM security_events WHERE simulated = 1")["count"] == len(result.events)
    for alert in result.alerts:
        assert {event.event_id for event in services.alerts.evidence(alert["alert_id"])} <= result.event_ids
        assert alert["explanation"]
        assert alert["severity_justification"]


def test_simulation_replay_is_idempotent_and_preserves_restart_state(services):
    lab = SimulationLab(services)
    first = lab.run("suspicious_success", end=FIXED_TIME)
    first_ids = {alert["alert_id"] for alert in lab._alerts_for(first.event_ids)}
    alert_id = next(iter(first_ids))
    services.alerts.update_status(alert_id, "Investigating")
    services.alerts.add_note(alert_id, "Supporting evidence", "Lab evidence reviewed")
    incident_id = services.incidents.create("Lab replay investigation", "Persistent scenario record", "high", [alert_id])
    services.incidents.update_status(incident_id, "Investigating")
    second = lab.run("suspicious_success", end=FIXED_TIME)
    assert second.ingestion.accepted == 0
    assert second.ingestion.duplicates == len(first.events)
    assert second.detection.created == 0
    assert services.events.count() == len(first.events)
    restarted = AppServices(services.database.path)
    assert restarted.alerts.get(alert_id)["status"] == "Investigating"
    assert restarted.incidents.get(incident_id)["status"] == "Investigating"
    assert restarted.alerts.notes(alert_id)[0]["note"] == "Lab evidence reviewed"
    third = SimulationLab(restarted).run("suspicious_success", end=FIXED_TIME)
    assert third.ingestion.duplicates == len(first.events)
    assert restarted.events.count() == len(first.events)


def test_disabled_rule_does_not_force_a_demonstration_alert(services):
    rule = services.rules.get("SL-AUTH-001")
    services.rules.update(rule.rule_id, False, rule.config)
    result = SimulationLab(services).run("brute_force", end=FIXED_TIME)
    assert result.alerts == []
    assert result.evaluation.false_negatives == 1
    assert result.evaluation.recall == 0


def test_lab_preserves_unrelated_incident_and_excludes_it_from_scoring(services, event_factory):
    previous_events = [event_factory(f"2026-11-25T10:{index:02d}:00+11:00", source_ip="192.0.2.202", username="different-user") for index in range(5)]
    services.events.add_many(previous_events)
    services.detection.run()
    original = services.alerts.list()[0]
    services.incidents.create("Separate investigation", "Unrelated alert group", "medium", [original["alert_id"]])
    original_active_ids = {item["alert_id"] for item in services.alerts.list()}
    result = SimulationLab(services).run("password_spraying", end=FIXED_TIME)
    assert original_active_ids <= {item["alert_id"] for item in services.alerts.list()}
    assert original["alert_id"] not in {alert["alert_id"] for alert in result.alerts}
    assert result.evaluation.false_positives == 0
    with pytest.raises(ValueError, match="Unsupported"):
        SimulationLab(services).run("invented-attack")


def test_simulation_route_and_button_execute_and_persist(tmp_path, monkeypatch):
    path = tmp_path / "simulation-ui.db"
    monkeypatch.setenv("SENTINELLITE_DB_PATH", str(path))
    application = AppTest.from_file(str(APP), default_timeout=90)
    application.run()
    application.session_state["navigation"] = "Security Simulation Lab"
    application.run()
    assert not application.exception
    application.button(key="lab_run_action").click().run()
    assert not application.exception
    services = AppServices(path)
    assert services.events.count() == 8
    assert len(services.alerts.list()) == 1
