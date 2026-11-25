from __future__ import annotations

import csv
import io
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from core.database import Database


@dataclass
class EvaluationResult:
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    duplicate_matches: int
    true_positive_pairs: list[dict[str, str]] = field(default_factory=list)
    false_positive_pairs: list[dict[str, str]] = field(default_factory=list)
    false_negative_pairs: list[dict[str, str]] = field(default_factory=list)


def load_ground_truth(content: str | Path) -> dict[str, dict[str, object]]:
    if isinstance(content, Path):
        text = content.read_text(encoding="utf-8")
    else:
        text = content
    reader = csv.DictReader(io.StringIO(text))
    required = {"event_id", "scenario_id", "scenario_label", "expected_rules"}
    if not reader.fieldnames or not required.issubset(reader.fieldnames):
        raise ValueError("Ground truth requires event_id, scenario_id, scenario_label, and expected_rules columns")
    events: dict[str, dict[str, object]] = {}
    for row in reader:
        event_id = (row["event_id"] or "").strip()
        scenario_id = (row["scenario_id"] or "").strip()
        if not event_id or not scenario_id:
            raise ValueError("Ground-truth event and scenario IDs cannot be empty")
        events[event_id] = {
            "scenario_id": scenario_id,
            "scenario_label": (row["scenario_label"] or scenario_id).strip(),
            "expected_rules": tuple(rule.strip() for rule in (row["expected_rules"] or "").split("|") if rule.strip()),
        }
    return events


def evaluate_detections(database: Database, ground_truth: dict[str, dict[str, object]], scope_alert_ids: set[str] | None = None) -> EvaluationResult:
    expected: dict[tuple[str, str], str] = {}
    for item in ground_truth.values():
        for rule_id in item["expected_rules"]:
            expected[(item["scenario_id"], rule_id)] = str(item["scenario_label"])
    scope_sql = ""
    scope_parameters: list[object] = []
    if scope_alert_ids is not None:
        if scope_alert_ids:
            placeholders = ",".join("?" for _ in scope_alert_ids)
            scope_sql = f" AND a.alert_id IN ({placeholders})"
            scope_parameters = sorted(scope_alert_ids)
        else:
            scope_sql = " AND 1 = 0"
    alerts = database.fetch_all(
        f"""
        SELECT a.alert_id, a.rule_id, ae.event_id
        FROM security_alerts a
        LEFT JOIN alert_events ae ON ae.alert_id = a.alert_id
        WHERE a.active = 1 {scope_sql}
        ORDER BY a.alert_id, ae.event_id
        """,
        scope_parameters,
    )
    evidence_by_alert: dict[str, list[str]] = defaultdict(list)
    rule_by_alert: dict[str, str] = {}
    for row in alerts:
        rule_by_alert[row["alert_id"]] = row["rule_id"]
        if row["event_id"]:
            evidence_by_alert[row["alert_id"]].append(row["event_id"])
    pair_alert_counts: Counter[tuple[str, str]] = Counter()
    pair_labels: dict[tuple[str, str], str] = {}
    unlabelled_false_positives = []
    for alert_id, rule_id in rule_by_alert.items():
        scenarios = {
            (ground_truth[event_id]["scenario_id"], ground_truth[event_id]["scenario_label"])
            for event_id in evidence_by_alert.get(alert_id, []) if event_id in ground_truth
        }
        if not scenarios:
            unlabelled_false_positives.append({
                "scenario_id": "unlabelled", "scenario_label": "Alert without planted-scenario evidence",
                "rule_id": rule_id, "alert_id": alert_id,
            })
        for scenario_id, label in scenarios:
            pair = (scenario_id, rule_id)
            pair_alert_counts[pair] += 1
            pair_labels[pair] = str(label)
    predicted = set(pair_alert_counts)
    expected_keys = set(expected)
    true_pairs = sorted(predicted & expected_keys)
    false_pairs = sorted(predicted - expected_keys)
    missed_pairs = sorted(expected_keys - predicted)
    false_positives = len(false_pairs) + len(unlabelled_false_positives)
    true_positives = len(true_pairs)
    false_negatives = len(missed_pairs)
    precision = true_positives / (true_positives + false_positives) if true_positives + false_positives else 0.0
    recall = true_positives / (true_positives + false_negatives) if true_positives + false_negatives else 0.0
    def row(pair: tuple[str, str]) -> dict[str, str]:
        return {
            "scenario_id": pair[0], "scenario_label": pair_labels.get(pair, expected.get(pair, pair[0])),
            "rule_id": pair[1], "alert_id": "",
        }
    return EvaluationResult(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=precision,
        recall=recall,
        duplicate_matches=sum(max(0, count - 1) for count in pair_alert_counts.values() if count > 1),
        true_positive_pairs=[row(pair) for pair in true_pairs],
        false_positive_pairs=[row(pair) for pair in false_pairs] + unlabelled_false_positives,
        false_negative_pairs=[row(pair) for pair in missed_pairs],
    )
