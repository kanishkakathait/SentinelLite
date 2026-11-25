from __future__ import annotations

from collections import defaultdict
from datetime import time
from typing import Callable, Iterable
from zoneinfo import ZoneInfo

from core.models import DetectionResult, RuleDefinition, SecurityEvent


def is_authentication(event: SecurityEvent) -> bool:
    return event.event_category == "authentication" and event.authentication_result in {"success", "failure"}


def group_events(events: Iterable[SecurityEvent], key: Callable[[SecurityEvent], tuple[object, ...]]):
    groups: dict[tuple[object, ...], list[SecurityEvent]] = defaultdict(list)
    for event in events:
        groups[key(event)].append(event)
    return groups


def rolling_episodes(
    events: Iterable[SecurityEvent], window_seconds: int, ready: Callable[[list[SecurityEvent]], bool]
) -> list[list[SecurityEvent]]:
    current: list[SecurityEvent] = []
    results: list[list[SecurityEvent]] = []
    for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
        current.append(event)
        while current and (event.timestamp - current[0].timestamp).total_seconds() > window_seconds:
            current.pop(0)
        if ready(current):
            results.append(list(current))
            current = []
    return results


def session_episodes(events: Iterable[SecurityEvent], window_seconds: int) -> list[list[SecurityEvent]]:
    sessions: list[list[SecurityEvent]] = []
    current: list[SecurityEvent] = []
    for event in sorted(events, key=lambda item: (item.timestamp, item.event_id)):
        if current and (event.timestamp - current[-1].timestamp).total_seconds() > window_seconds:
            sessions.append(current)
            current = []
        current.append(event)
    if current:
        sessions.append(current)
    return sessions


def outside_hours(event: SecurityEvent, config: dict) -> bool:
    zone = ZoneInfo(str(config.get("timezone", "Australia/Melbourne")))
    local = event.timestamp.astimezone(zone)
    start = time.fromisoformat(str(config.get("business_start", "08:00")))
    end = time.fromisoformat(str(config.get("business_end", "18:00")))
    if config.get("weekdays_only") and local.weekday() >= 5:
        return True
    local_time = local.time()
    if start <= end:
        return not start <= local_time < end
    return not (local_time >= start or local_time < end)


def common_value(events: list[SecurityEvent], attribute: str) -> str | None:
    values = {getattr(event, attribute) for event in events if getattr(event, attribute) is not None}
    return values.pop() if len(values) == 1 else None


def base_details(evidence: list[SecurityEvent]) -> dict[str, object]:
    ordered = sorted(evidence, key=lambda item: (item.timestamp, item.event_id))
    return {
        "event_count": len(ordered),
        "attempt_count": sum(event.authentication_result == "failure" for event in ordered),
        "first_event_timestamp": min(event.timestamp for event in ordered).isoformat(),
        "last_event_timestamp": max(event.timestamp for event in ordered).isoformat(),
        "targeted_accounts": sorted({event.username for event in ordered if event.username}),
        "supporting_event_ids": [event.event_id for event in ordered],
    }


def result(
    rule: RuleDefinition,
    evidence: list[SecurityEvent],
    explanation: str,
    justification: str,
    username: str | None = None,
    details: dict | None = None,
) -> DetectionResult:
    evidence = sorted(evidence, key=lambda item: (item.timestamp, item.event_id))
    merged_details = base_details(evidence)
    merged_details.update(details or {})
    return DetectionResult(
        rule=rule,
        evidence=evidence,
        explanation=explanation,
        severity_justification=justification,
        details=merged_details,
        source_ip=common_value(evidence, "source_ip"),
        username=username if username is not None else common_value(evidence, "username"),
        hostname=common_value(evidence, "hostname"),
        anchor_event_id=evidence[0].event_id,
    )


def detect_brute_force(events: list[SecurityEvent], rule: RuleDefinition) -> list[DetectionResult]:
    threshold = int(rule.config["failure_threshold"])
    window = int(rule.config["window_seconds"])
    failures = [event for event in events if event.source_ip and event.username and event.authentication_result == "failure"]
    groups = group_events(failures, lambda event: (event.source_ip, event.username))
    findings = []
    for (_, account), group in sorted(groups.items()):
        for episode in rolling_episodes(group, window, lambda current: len(current) >= threshold):
            count = len(episode)
            findings.append(result(
                rule, episode,
                f"{count} failed authentication attempts for {account} came from {episode[0].source_ip} between {episode[0].timestamp.isoformat()} and {episode[-1].timestamp.isoformat()}. This is suspicious behaviour requiring review, not proof of malicious intent.",
                f"Configured {rule.severity} severity because the repeated-failure threshold of {threshold} was met within {window} seconds.",
                username=account,
            ))
    return findings


def detect_success_after_failures(events: list[SecurityEvent], rule: RuleDefinition) -> list[DetectionResult]:
    threshold = int(rule.config["failure_threshold"])
    window = int(rule.config["window_seconds"])
    relevant = [event for event in events if event.source_ip and event.username and is_authentication(event)]
    groups = group_events(relevant, lambda event: (event.source_ip, event.username))
    findings = []
    for (_, account), group in sorted(groups.items()):
        ordered = sorted(group, key=lambda item: (item.timestamp, item.event_id))
        previous_success_index = -1
        for index, success in enumerate(ordered):
            if success.authentication_result != "success":
                continue
            failures = [
                event for event in ordered[previous_success_index + 1:index]
                if event.authentication_result == "failure"
                and 0 <= (success.timestamp - event.timestamp).total_seconds() <= window
            ]
            previous_success_index = index
            if len(failures) >= threshold:
                evidence = failures + [success]
                finding = result(
                    rule, evidence,
                    f"A successful login for {account} from {success.source_ip} followed {len(failures)} failed attempts within {window} seconds. The sequence is suspicious and requires validation with the user or system owner.",
                    f"Configured {rule.severity} severity because a success followed at least {threshold} failures; successful completion alone does not establish account compromise.",
                    username=account,
                    details={"successful_event_id": success.event_id},
                )
                finding.anchor_event_id = success.event_id
                findings.append(finding)
    return findings


def detect_unusual_hours(events: list[SecurityEvent], rule: RuleDefinition) -> list[DetectionResult]:
    config = rule.config
    groups = group_events(
        [event for event in events if event.source_ip and is_authentication(event)],
        lambda event: (event.source_ip, event.username, event.hostname),
    )
    findings = []
    accounts = set(config.get("included_accounts", []))
    hosts = set(config.get("included_hosts", []))
    for _, group in sorted(groups.items(), key=lambda item: str(item[0])):
        outside = [
            event for event in group
            if outside_hours(event, config)
            and (not accounts or event.username in accounts)
            and (not hosts or event.hostname in hosts)
        ]
        for session in session_episodes(outside, int(config["session_window_seconds"])):
            account = common_value(session, "username") or "an unspecified account"
            findings.append(result(
                rule, session,
                f"{len(session)} authentication event(s) for {account} occurred outside expected business hours ({config['business_start']}–{config['business_end']} {config['timezone']}). Unusual timing is contextual and can have legitimate explanations.",
                f"Configured {rule.severity} severity because timing alone is a weak contextual indicator, not evidence of compromise.",
            ))
    return findings


def detect_privileged(events: list[SecurityEvent], rule: RuleDefinition) -> list[DetectionResult]:
    privileged = {name.casefold() for name in rule.config["privileged_accounts"]}
    selected = [
        event for event in events
        if event.username and event.username.casefold() in privileged and is_authentication(event)
    ]
    groups = group_events(selected, lambda event: (event.username, event.source_ip, event.hostname))
    findings = []
    for _, group in sorted(groups.items(), key=lambda item: str(item[0])):
        for session in session_episodes(group, int(rule.config["session_window_seconds"])):
            account = common_value(session, "username")
            findings.append(result(
                rule, session,
                f"Observed {len(session)} authentication event(s) involving configured privileged account {account}. Review the administrative context; privileged activity alone is not classified as malicious.",
                "Informational severity supports accountable review while avoiding the false assumption that every privileged login is malicious.",
                username=account,
            ))
    return findings


def detect_multiple_accounts(events: list[SecurityEvent], rule: RuleDefinition) -> list[DetectionResult]:
    threshold = int(rule.config["distinct_account_threshold"])
    window = int(rule.config["window_seconds"])
    failures = [event for event in events if event.source_ip and event.username and event.authentication_result == "failure"]
    groups = group_events(failures, lambda event: (event.source_ip,))
    findings = []
    for _, group in sorted(groups.items()):
        episodes = rolling_episodes(
            group, window, lambda current: len({event.username for event in current}) >= threshold
        )
        for episode in episodes:
            accounts = sorted({event.username for event in episode})
            findings.append(result(
                rule, episode,
                f"Source {episode[0].source_ip} attempted authentication against {len(accounts)} distinct accounts within {window} seconds. This password-spraying-like or enumeration pattern differs from repetition against one account and may also have legitimate explanations.",
                f"Configured {rule.severity} severity because {len(accounts)} distinct accounts met the configured threshold of {threshold}.",
                username="",
                details={"targeted_accounts": accounts, "distinct_account_count": len(accounts)},
            ))
    return findings


def detect_correlated(events: list[SecurityEvent], rule: RuleDefinition) -> list[DetectionResult]:
    threshold = int(rule.config["failure_threshold"])
    window = int(rule.config["window_seconds"])
    privileged = {name.casefold() for name in rule.config["privileged_accounts"]}
    relevant = [event for event in events if event.source_ip and event.username and is_authentication(event)]
    groups = group_events(relevant, lambda event: (event.source_ip, event.username))
    findings = []
    for (_, account), group in sorted(groups.items()):
        ordered = sorted(group, key=lambda item: (item.timestamp, item.event_id))
        previous_success_index = -1
        for index, success in enumerate(ordered):
            if success.authentication_result != "success":
                continue
            failures = [
                event for event in ordered[previous_success_index + 1:index]
                if event.authentication_result == "failure"
                and 0 <= (success.timestamp - event.timestamp).total_seconds() <= window
            ]
            previous_success_index = index
            indicators = []
            if len(failures) >= threshold:
                indicators.append(f"{len(failures)} preceding failures")
            if outside_hours(success, rule.config):
                indicators.append("success outside expected business hours")
            if account.casefold() in privileged:
                indicators.append("configured privileged account")
            if len(failures) >= threshold and len(indicators) >= int(rule.config["minimum_indicators"]):
                evidence = failures + [success]
                finding = result(
                    rule, evidence,
                    f"Correlated suspicious authentication for {account}: {'; '.join(indicators)}. These indicators increase investigative priority but do not establish compromise without validation.",
                    f"Configured {rule.severity} severity because {len(indicators)} independent contextual indicators were present: {', '.join(indicators)}.",
                    username=account,
                    details={"indicators": indicators, "successful_event_id": success.event_id},
                )
                finding.anchor_event_id = success.event_id
                findings.append(finding)
    return findings


DETECTORS = {
    "SL-AUTH-001": detect_brute_force,
    "SL-AUTH-002": detect_success_after_failures,
    "SL-AUTH-003": detect_unusual_hours,
    "SL-AUTH-004": detect_privileged,
    "SL-AUTH-005": detect_multiple_accounts,
    "SL-AUTH-006": detect_correlated,
}
