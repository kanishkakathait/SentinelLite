from __future__ import annotations

import csv
import io

import pytest

from detection.evaluation import evaluate_detections, load_ground_truth


def ground_truth_for(events, expected_rules="SL-AUTH-001"):
    rows = []
    for event in events:
        rows.append({"event_id": event.event_id, "scenario_id": "scenario-test", "scenario_label": "Test burst", "expected_rules": expected_rules})
    return {row["event_id"]: {"scenario_id": row["scenario_id"], "scenario_label": row["scenario_label"], "expected_rules": (expected_rules,) if expected_rules else ()} for row in rows}


def test_scenario_rule_precision_recall_and_duplicate_matches(services, event_factory):
    events = [event_factory(f"2026-11-25T10:{index:02d}:00+11:00") for index in range(10)]
    services.events.add_many(events)
    services.detection.run()
    result = evaluate_detections(services.database, ground_truth_for(events))
    assert result.true_positives == 1
    assert result.false_positives == 0 and result.false_negatives == 0
    assert result.precision == 1 and result.recall == 1
    assert result.duplicate_matches == 1


def test_unexpected_and_missing_matches_are_explicit(services, event_factory):
    events = [event_factory(f"2026-11-25T10:{index:02d}:00+11:00") for index in range(5)]
    services.events.add_many(events)
    services.detection.run()
    false_positive = evaluate_detections(services.database, ground_truth_for(events, expected_rules=""))
    assert false_positive.false_positives == 1 and false_positive.precision == 0
    expected = ground_truth_for(events, expected_rules="SL-AUTH-002")
    false_negative = evaluate_detections(services.database, expected)
    assert false_negative.false_positives == 1 and false_negative.false_negatives == 1


def test_ground_truth_csv_validation():
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["event_id", "scenario_id", "scenario_label", "expected_rules"])
    writer.writeheader()
    writer.writerow({"event_id": "one", "scenario_id": "scenario", "scenario_label": "Example", "expected_rules": "SL-AUTH-001|SL-AUTH-002"})
    truth = load_ground_truth(output.getvalue())
    assert truth["one"]["expected_rules"] == ("SL-AUTH-001", "SL-AUTH-002")
    with pytest.raises(ValueError, match="requires"):
        load_ground_truth("event_id\none\n")
