from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from core.models import SecurityEvent
from core.time_utils import to_storage, utc_now
from detection.evaluation import EvaluationResult, evaluate_detections, load_ground_truth
from ingestion.normalisation import normalise_record
from simulation.scenarios import business_and_off_hours, scenario_definitions


@dataclass(frozen=True)
class LabScenario:
    key: str
    label: str
    pattern: str
    suspicious_reason: str
    investigation: str
    alternate_explanations: str
    base_scenario_id: str
    expected_rules: tuple[str, ...]


@dataclass
class LabRunResult:
    scenario: LabScenario
    events: list[SecurityEvent]
    ingestion: Any
    detection: Any
    alerts: list[dict[str, Any]]
    evaluation: EvaluationResult
    ran_at: str

    @property
    def event_ids(self) -> set[str]:
        return {event.event_id for event in self.events}


_SCENARIO_TEXT = {
    "brute_force": ("Brute-Force Login Attempts", "Repeated password guesses against one account from one source.", "Many failures against the same account/source can indicate guessing, scripted access attempts, or a credential problem.", "Inspect the failure timeline, lockout policy, unknown source, and whether any subsequent login or account activity is authorised.", "User error, stale saved credentials, a misconfigured password manager, or authorised load/security testing.", "scenario-001"),
    "password_spraying": ("Password Spraying", "Authentication failures against multiple distinct accounts from one source.", "Such behaviour can be spray-like enumeration. It differs from repeatedly attacking one account, but gateways and approved tests can create similar records.", "Compare the accounts, source ownership, testing records, and whether targets share a legitimate access pathway.", "Shared egress addresses, authorisation testing, service discovery, or account migration.", "scenario-003"),
    "suspicious_success": ("Suspicious Successful Login", "A success follows repeated failures for the same account and source.", "Password guessing might eventually succeed, but this sequence alone does not prove account takeover.", "Confirm the success with the user and inspect timestamp, source, session origin, and activity after login.", "A legitimate user remembering their password after typing errors or an assisted account recovery.", "scenario-002"),
    "privileged_activity": ("Privileged Account Activity", "Authentication involving a configured privileged account.", "Privileged accounts require accountability, but administration is normal and should not automatically be called an attack.", "Check for an approved change, service window, operator identity, and subsequent privileged activity.", "Routine administration, a maintenance window, or authorised incident handling.", "scenario-004"),
    "off_hours_authentication": ("Authentication Outside Expected Hours", "Authentication outside configured business hours.", "Unusual timing can add useful evidence, but shift work or maintenance may make it normal.", "Check user shifts, scheduled work, source timestamps, timezone settings, and legitimate after-hours changes.", "Shift work, travel, scheduled jobs, maintenance, or an incorrect timezone configuration.", "scenario-005"),
    "correlated_authentication": ("Correlated Suspicious Authentication Activity", "Repeated failures, a success, privileged context, and unusual timing appear in one evidence chain.", "Several contextual signals can increase investigation priority without proving compromise or attribution.", "Validate each indicator independently, contact authorised owners, inspect the source/user relationship, and review subsequent actions.", "Urgent after-hours administration following a forgotten password or an approved recovery session.", "scenario-006"),
}

BASE_SCENARIOS = {definition.scenario_id: definition for definition in scenario_definitions()}
LAB_SCENARIOS = {
    key: LabScenario(
        key=key, label=values[0], pattern=values[1], suspicious_reason=values[2],
        investigation=values[3], alternate_explanations=values[4], base_scenario_id=values[5],
        expected_rules=BASE_SCENARIOS[values[5]].expected_rules,
    )
    for key, values in _SCENARIO_TEXT.items()
}


class SimulationLab:
    def __init__(self, services):
        self.services = services

    def scenarios(self) -> list[LabScenario]:
        return list(LAB_SCENARIOS.values())

    def scenario(self, key: str) -> LabScenario:
        if key not in LAB_SCENARIOS:
            raise ValueError("Unsupported simulation scenario")
        return LAB_SCENARIOS[key]

    def run(self, key: str, end: datetime | None = None) -> LabRunResult:
        scenario = self.scenario(key)
        run_time = (end or utc_now()).astimezone(timezone.utc).replace(microsecond=0)
        business, off_hours = business_and_off_hours(run_time)
        records = []
        for raw in BASE_SCENARIOS[scenario.base_scenario_id].build(business, off_hours):
            record = dict(raw)
            record["scenario_id"] = f"lab-{scenario.key}"
            record["simulated"] = True
            record["event_source"] = "synthetic_lab"
            record["raw_message"] = f"[SIMULATED][SIMULATION LAB: {scenario.label}] {raw['authentication_result']} authentication for {raw['username']} from {raw['source_ip']} on {raw['hostname']}"
            records.append(record)
        if not records:
            raise ValueError("Scenario contains no events")
        expected = [normalise_record(record, "simulation_lab", self.services.ingestion.default_timezone, simulated=True) for record in records]
        payload = json.dumps({"description": "SIMULATED Security Simulation Lab records", "scenario": scenario.key, "events": records}, ensure_ascii=False).encode("utf-8")
        ingestion = self.services.ingestion.ingest_bytes(
            f"simulation-lab-{scenario.key}.json", payload, simulated=True, ingestion_timestamp=run_time,
        )
        detection = self.services.detection.run()
        ids = {event.event_id for event in expected}
        alerts = self._alerts_for(ids)
        evaluation = self._evaluate(scenario, ids)
        return LabRunResult(scenario, expected, ingestion, detection, alerts, evaluation, to_storage(run_time))

    def _alerts_for(self, event_ids: set[str]) -> list[dict[str, Any]]:
        return self.services.alerts.for_events(event_ids)

    def _evaluate(self, scenario: LabScenario, event_ids: set[str]) -> EvaluationResult:
        output = io.StringIO()
        fields = ["event_id", "scenario_id", "scenario_label", "expected_rules"]
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        for event_id in sorted(event_ids):
            writer.writerow({
                "event_id": event_id, "scenario_id": f"lab-{scenario.key}",
                "scenario_label": scenario.label, "expected_rules": "|".join(scenario.expected_rules),
            })
        return evaluate_detections(
            self.services.database, load_ground_truth(output.getvalue()), scope_alert_ids={alert["alert_id"] for alert in self._alerts_for(event_ids)},
        )
