from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable
from zoneinfo import ZoneInfo


@dataclass(frozen=True)
class ScenarioDefinition:
    scenario_id: str
    label: str
    expected_rules: tuple[str, ...]
    build: Callable[[datetime, datetime], list[dict[str, str]]]


def event_record(scenario_id: str, timestamp: datetime, source_ip: str, username: str, result: str, host: str = "mel-apps-01") -> dict[str, str]:
    return {
        "timestamp": timestamp.isoformat(),
        "event_source": "synthetic_auth",
        "hostname": host,
        "source_ip": source_ip,
        "destination_ip": "192.0.2.20",
        "username": username,
        "event_category": "authentication",
        "event_action": "login",
        "authentication_result": result,
        "simulated": True,
        "scenario_id": scenario_id,
    }


def sequence(scenario_id: str, start: datetime, source_ip: str, users: list[str], results: list[str], host: str = "mel-apps-01") -> list[dict[str, str]]:
    return [
        event_record(scenario_id, start + timedelta(minutes=index), source_ip, users[min(index, len(users) - 1)], results[index], host)
        for index in range(len(results))
    ]


def brute_force(scenario_id: str, ip: str, user: str) -> Callable[[datetime, datetime], list[dict[str, str]]]:
    return lambda business, _: sequence(scenario_id, business, ip, [user], ["failure"] * 8)


def password_spray(scenario_id: str, ip: str, prefix: str) -> Callable[[datetime, datetime], list[dict[str, str]]]:
    users = [f"{prefix}-{index}" for index in range(1, 13)]
    return lambda business, _: sequence(scenario_id, business, ip, users, ["failure"] * len(users))


def successful_after_failures(business: datetime, _: datetime) -> list[dict[str, str]]:
    return sequence("scenario-002", business + timedelta(minutes=15), "203.0.113.20", ["bob"], ["failure"] * 5 + ["success"], "mel-vpn-01")


def privileged_activity(business: datetime, _: datetime) -> list[dict[str, str]]:
    start = business + timedelta(minutes=45)
    return sequence("scenario-004", start, "203.0.113.40", ["root"], ["success", "success"], "mel-admin-01")


def unusual_hours(_: datetime, off_hours: datetime) -> list[dict[str, str]]:
    return sequence("scenario-005", off_hours, "203.0.113.50", ["charlie"], ["success"] * 4, "mel-vpn-01")


def correlated_activity(_: datetime, off_hours: datetime) -> list[dict[str, str]]:
    return sequence("scenario-006", off_hours + timedelta(minutes=15), "203.0.113.60", ["admin"], ["failure"] * 5 + ["success"], "mel-admin-01")


def recurring_attack(business: datetime, _: datetime) -> list[dict[str, str]]:
    first = sequence("scenario-007", business + timedelta(minutes=60), "203.0.113.70", ["eve"], ["failure"] * 5)
    second = sequence("scenario-007", business + timedelta(minutes=90), "203.0.113.70", ["eve"], ["failure"] * 5)
    return first + second


def scenario_definitions() -> list[ScenarioDefinition]:
    return [
        ScenarioDefinition("scenario-001", "Brute-force authentication attempts", ("SL-AUTH-001",), brute_force("scenario-001", "203.0.113.10", "alice")),
        ScenarioDefinition("scenario-002", "Successful authentication after repeated failures", ("SL-AUTH-001", "SL-AUTH-002"), successful_after_failures),
        ScenarioDefinition("scenario-003", "Password-spraying-like account enumeration", ("SL-AUTH-005",), password_spray("scenario-003", "203.0.113.30", "spray-a")),
        ScenarioDefinition("scenario-004", "Privileged account monitoring", ("SL-AUTH-004",), privileged_activity),
        ScenarioDefinition("scenario-005", "Unusual authentication timing", ("SL-AUTH-003",), unusual_hours),
        ScenarioDefinition("scenario-006", "Correlated privileged off-hours authentication", ("SL-AUTH-001", "SL-AUTH-002", "SL-AUTH-003", "SL-AUTH-004", "SL-AUTH-006"), correlated_activity),
        ScenarioDefinition("scenario-007", "Two recurring brute-force episodes", ("SL-AUTH-001",), recurring_attack),
        ScenarioDefinition("scenario-008", "Second brute-force campaign", ("SL-AUTH-001",), brute_force("scenario-008", "203.0.113.80", "frank")),
        ScenarioDefinition("scenario-009", "Third brute-force campaign", ("SL-AUTH-001",), brute_force("scenario-009", "203.0.113.90", "grace")),
        ScenarioDefinition("scenario-010", "Fourth brute-force campaign", ("SL-AUTH-001",), brute_force("scenario-010", "203.0.113.100", "heidi")),
        ScenarioDefinition("scenario-011", "Second password-spraying-like campaign", ("SL-AUTH-005",), password_spray("scenario-011", "203.0.113.110", "spray-b")),
        ScenarioDefinition("scenario-012", "Fifth brute-force campaign", ("SL-AUTH-001",), brute_force("scenario-012", "203.0.113.120", "ivan")),
        ScenarioDefinition("scenario-013", "Sixth brute-force campaign", ("SL-AUTH-001",), brute_force("scenario-013", "203.0.113.130", "judy")),
    ]


def business_and_off_hours(end: datetime) -> tuple[datetime, datetime]:
    zone = ZoneInfo("Australia/Melbourne")
    local_end = end.astimezone(zone)
    business = local_end.replace(hour=10, minute=0, second=0, microsecond=0)
    off_hours = local_end.replace(hour=2, minute=0, second=0, microsecond=0)
    if business.astimezone(timezone.utc) > end:
        business -= timedelta(days=1)
    if off_hours.astimezone(timezone.utc) > end:
        off_hours -= timedelta(days=1)
    return business.astimezone(timezone.utc), off_hours.astimezone(timezone.utc)
