from __future__ import annotations

from dataclasses import replace

from detection.engine import DetectionEngine


def burst(factory, count=5, username="alice", result="failure", minute=0, hour=10, **changes):
    return [factory(f"2026-11-25T{hour:02d}:{minute + index:02d}:00+11:00", username=username, result=result, **changes) for index in range(count)]


def test_brute_force_threshold_and_out_of_order_events(services, event_factory):
    below = services.detection.detect_events(burst(event_factory, count=4))
    assert below == []
    events = list(reversed(burst(event_factory, count=5)))
    findings = services.detection.detect_events(events)
    assert len(findings) == 1
    assert findings[0].rule.rule_id == "SL-AUTH-001"
    assert findings[0].details["attempt_count"] == 5
    assert findings[0].details["targeted_accounts"] == ["alice"]


def test_success_after_failures_is_suspicious_not_compromise_conclusion(services, event_factory):
    events = burst(event_factory, count=5) + burst(event_factory, count=1, result="success", minute=5)
    findings = services.detection.detect_events(events)
    assert [finding.rule.rule_id for finding in findings] == ["SL-AUTH-001", "SL-AUTH-002"]
    success = findings[1]
    assert "requires validation" in success.explanation
    assert "does not establish account compromise" in success.severity_justification


def test_multiple_accounts_is_distinct_from_single_account_repetition(services, event_factory):
    events = [event_factory(f"2026-11-25T10:{index:02d}:00+11:00", username=f"user-{index}") for index in range(5)]
    findings = services.detection.detect_events(events)
    assert [finding.rule.rule_id for finding in findings] == ["SL-AUTH-005"]
    assert findings[0].details["distinct_account_count"] == 5


def test_privileged_activity_is_informational_not_assumed_malicious(services, event_factory):
    event = event_factory(username="root", result="success")
    findings = services.detection.detect_events([event])
    assert [finding.rule.rule_id for finding in findings] == ["SL-AUTH-004"]
    assert findings[0].rule.severity == "informational"
    assert "not classified as malicious" in findings[0].explanation


def test_off_hours_uses_melbourne_timezone(services, event_factory):
    event = event_factory(timestamp="2026-11-25T02:00:00+11:00", result="success")
    findings = services.detection.detect_events([event])
    assert [finding.rule.rule_id for finding in findings] == ["SL-AUTH-003"]
    assert "contextual" in findings[0].explanation


def test_correlation_requires_repeated_failures_and_an_additional_indicator(services, event_factory):
    events = burst(event_factory, count=5, username="admin", hour=2) + [event_factory("2026-11-25T02:05:00+11:00", username="admin", result="success")]
    findings = services.detection.detect_events(events)
    assert {finding.rule.rule_id for finding in findings} == {"SL-AUTH-001", "SL-AUTH-002", "SL-AUTH-003", "SL-AUTH-004", "SL-AUTH-006"}
    correlated = next(finding for finding in findings if finding.rule.rule_id == "SL-AUTH-006")
    assert len(correlated.details["indicators"]) == 3


def test_missing_source_ip_does_not_invent_correlations(services, event_factory):
    events = burst(event_factory, count=5, source_ip=None)
    assert services.detection.detect_events(events) == []


def test_recurring_non_overlapping_episodes_and_alert_deduplication(services, event_factory):
    events = burst(event_factory, count=10)
    services.events.add_many(events)
    first = services.detection.run()
    active = services.alerts.list()
    second = services.detection.run()
    assert first.created == 2 and len(active) == 2
    assert second.created == 0 and second.refreshed == 2 and second.active == 2
    assert len({alert["alert_id"] for alert in active}) == 2
    services.detection.run()
    assert len(services.alerts.list()) == 2


def test_late_events_supersede_current_episode_without_deleting_history(services, event_factory):
    events = burst(event_factory, count=5)
    services.events.add_many(events)
    services.detection.run()
    original = services.alerts.list()[0]
    services.alerts.update_status(original["alert_id"], "Investigating")
    services.alerts.add_note(original["alert_id"], "Supporting evidence", "Keep this analyst record")
    late = event_factory("2026-11-25T09:59:00+11:00")
    services.events.add_many([late])
    services.detection.run()
    current = services.alerts.list()
    history = services.alerts.list(active_only=False)
    assert len(current) == 1 and len(history) == 2
    assert history[-1]["alert_id"] == original["alert_id"] or history[0]["alert_id"] == original["alert_id"]
    old = services.alerts.get(original["alert_id"])
    assert old["active"] == 0 and old["status"] == "Investigating"
    assert services.alerts.notes(original["alert_id"])[0]["note"] == "Keep this analyst record"


def test_rule_disablement_persists_and_supersedes_previous_findings(services, event_factory):
    services.events.add_many(burst(event_factory, count=5))
    services.detection.run()
    rule = services.rules.get("SL-AUTH-001")
    services.rules.update(rule.rule_id, False, rule.config)
    services.detection.run()
    assert services.alerts.list() == []
    assert len(services.alerts.list(active_only=False)) == 1
    services.rules.update(rule.rule_id, True, rule.config)
    services.detection.run()
    assert len(services.alerts.list()) == 1


def test_window_boundary_and_invalid_rule_configuration(services, event_factory):
    events = [
        event_factory("2026-11-25T10:00:00+11:00"),
        event_factory("2026-11-25T10:01:00+11:00"),
        event_factory("2026-11-25T10:02:00+11:00"),
        event_factory("2026-11-25T10:03:00+11:00"),
        event_factory("2026-11-25T10:05:00+11:00"),
    ]
    assert any(finding.rule.rule_id == "SL-AUTH-001" for finding in services.detection.detect_events(events))
    rule = services.rules.get("SL-AUTH-001")
    try:
        DetectionEngine._validate_rule(replace(rule, config={"failure_threshold": 0, "window_seconds": 300}))
        assert False, "Invalid threshold should fail validation"
    except ValueError as error:
        assert "threshold" in str(error)
