from __future__ import annotations

from pathlib import Path

import pytest

from core.activity import recent_activity
from core.view_models import paginate, sort_alerts


def sample_alerts():
    return [
        {"alert_id": "ALT-low", "severity": "low", "alert_timestamp": "2026-11-24T00:00:00.000000Z"},
        {"alert_id": "ALT-critical", "severity": "critical", "alert_timestamp": "2026-11-23T00:00:00.000000Z"},
        {"alert_id": "ALT-high", "severity": "high", "alert_timestamp": "2026-11-25T00:00:00.000000Z"},
    ]


def test_alert_sort_is_severity_aware_and_retains_timestamp_ties():
    records = sample_alerts()
    assert sort_alerts(records, "Newest first")[0]["alert_id"] == "ALT-high"
    assert sort_alerts(records, "Severity, newest first")[-1]["alert_id"] == "ALT-low"
    assert sort_alerts(records, "Lowest severity first")[0]["alert_id"] == "ALT-low"
    assert sort_alerts(records, "Oldest first")[0]["alert_id"] == "ALT-critical"
    with pytest.raises(ValueError, match="Unsupported"):
        sort_alerts(records, "invented order")


def test_pagination_clamps_ranges_and_rejects_invalid_sizes():
    items = list(range(10))
    assert paginate(items, 1, 4) == ([0, 1, 2, 3], 1, 3)
    assert paginate(items, 3, 4) == ([8, 9], 3, 3)
    assert paginate(items, 99, 4) == ([8, 9], 3, 3)
    assert paginate([], 5, 10) == ([], 1, 1)
    with pytest.raises(ValueError, match="positive"):
        paginate(items, 1, 0)


def test_activity_feed_reads_event_alert_and_analyst_records(services, event_factory):
    events = [event_factory(f"2026-11-25T10:{index:02d}:00+11:00") for index in range(5)]
    services.events.add_many(events)
    services.detection.run()
    alert = services.alerts.list()[0]
    services.alerts.update_status(alert["alert_id"], "Investigating", "Review in progress")
    services.incidents.create("Activity case", "Check a real alert", "medium", [alert["alert_id"]])
    activities = recent_activity(services.database, limit=20)
    assert activities
    assert any(item["target"] == "alert" and item["kind"] == "analyst" for item in activities)
    assert any(item["target"] == "incident" for item in activities)
    assert any(item["kind"] == "event" for item in activities)
    assert len(activities) <= 20
    numeric_order = sorted((item["timestamp"], item["reference"]) for item in activities)
    assert [(item["timestamp"], item["reference"]) for item in sorted(reversed(activities), key=lambda item: (item["timestamp"], item["reference"]))] == numeric_order


def test_related_alerts_are_only_scoped_leads(services, event_factory):
    events = [event_factory(f"2026-11-25T10:{index:02d}:00+11:00") for index in range(5)]
    events.append(event_factory("2026-11-25T10:05:00+11:00", result="success"))
    services.events.add_many(events)
    services.detection.run()
    alert = next(item for item in services.alerts.list() if item["rule_id"] == "SL-AUTH-001")
    related = services.alerts.related(alert["alert_id"])
    assert any(item["rule_id"] == "SL-AUTH-002" for item in related)
    untreated = services.alerts.related(alert["alert_id"], limit=1)
    assert len(untreated) <= 1


def test_reduced_motion_and_premium_navigation_markers_exist():
    css = (Path(__file__).resolve().parent.parent / "assets" / "style.css").read_text()
    assert "@media (prefers-reduced-motion: reduce)" in css
    assert "animation: none !important" in css
    assert "transition: none !important" in css
    branding = (Path(__file__).resolve().parent.parent / "assets" / "brand.svg").read_text()
    assert "SentinelLite shield" in branding
