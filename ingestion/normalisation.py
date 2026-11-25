from __future__ import annotations

import hashlib
import json
from datetime import datetime
from ipaddress import ip_address
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from core.models import SecurityEvent
from core.time_utils import ensure_utc, to_storage, utc_now

FIELD_ALIASES = {
    "timestamp": ("timestamp", "event_timestamp", "time", "@timestamp"),
    "event_source": ("event_source", "source", "log_source"),
    "hostname": ("hostname", "host", "host_name"),
    "source_ip": ("source_ip", "src_ip", "source_address", "src"),
    "destination_ip": ("destination_ip", "dest_ip", "dst_ip", "destination_address", "dest"),
    "username": ("username", "user", "account", "account_name"),
    "event_category": ("event_category", "category"),
    "event_action": ("event_action", "action"),
    "authentication_result": ("authentication_result", "auth_result", "result", "outcome"),
    "raw_message": ("raw_message", "raw", "message"),
}


def _record_value(record: dict[str, Any], field: str) -> Any:
    normalised = {
        str(key).strip().lower().replace(" ", "_").replace("-", "_"): value
        for key, value in record.items()
    }
    for alias in FIELD_ALIASES[field]:
        if alias in normalised:
            return normalised[alias]
    return None


def _text(value: Any, maximum: int = 500) -> str | None:
    if value is None:
        return None
    if isinstance(value, (dict, list, tuple)):
        raise ValueError("Log fields must contain scalar values")
    cleaned = str(value).strip()
    if not cleaned:
        return None
    if len(cleaned) > maximum:
        raise ValueError(f"Log field exceeds {maximum} characters")
    return cleaned


def _ip_field(value: Any, field: str) -> str | None:
    address = _text(value, 100)
    if address is None:
        return None
    try:
        return str(ip_address(address))
    except ValueError as error:
        raise ValueError(f"{field} must be a valid IPv4 or IPv6 address") from error


def parse_timestamp(value: Any, default_timezone: str) -> datetime:
    raw = _text(value, 100)
    if not raw:
        raise ValueError("Missing event timestamp")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("Malformed event timestamp") from error
    if parsed.tzinfo is None:
        try:
            parsed = parsed.replace(tzinfo=ZoneInfo(default_timezone))
        except ZoneInfoNotFoundError as error:
            raise ValueError("Unknown default timezone") from error
    return parsed


def _authentication_result(value: Any) -> str | None:
    result = _text(value, 100)
    if result is None:
        return None
    normalised = result.casefold()
    if normalised in {"success", "succeeded", "accepted", "pass", "passed", "true", "1"}:
        return "success"
    if normalised in {"failure", "failed", "fail", "denied", "false", "0"}:
        return "failure"
    return normalised


def _simulated(record: dict[str, Any], forced: bool) -> bool:
    if forced:
        return True
    value = record.get("simulated", False)
    if isinstance(value, str):
        return value.casefold() in {"true", "1", "yes"}
    return bool(value)


def normalise_record(
    record: dict[str, Any],
    source_format: str,
    default_timezone: str,
    simulated: bool = False,
    ingestion_timestamp: datetime | None = None,
) -> SecurityEvent:
    if not isinstance(record, dict):
        raise ValueError("Each record must be an object")
    timestamp = ensure_utc(parse_timestamp(_record_value(record, "timestamp"), default_timezone))
    event_source = _text(_record_value(record, "event_source"), 200) or "unspecified"
    raw = _text(_record_value(record, "raw_message"), 20_000)
    if raw is None:
        raw = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str)[:20_000]
    identity = {
        "event_timestamp": to_storage(timestamp),
        "event_source": event_source,
        "hostname": _text(_record_value(record, "hostname")),
        "source_ip": _ip_field(_record_value(record, "source_ip"), "Source IP"),
        "destination_ip": _ip_field(_record_value(record, "destination_ip"), "Destination IP"),
        "username": _text(_record_value(record, "username"), 300),
        "event_category": (_text(_record_value(record, "event_category"), 100) or "uncategorised").casefold(),
        "event_action": (_text(_record_value(record, "event_action"), 100) or "observed").casefold(),
        "authentication_result": _authentication_result(_record_value(record, "authentication_result")),
        "raw_message": raw,
    }
    event_id = hashlib.sha256(
        json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return SecurityEvent(
        event_id=event_id,
        timestamp=timestamp,
        event_source=identity["event_source"],
        hostname=identity["hostname"],
        source_ip=identity["source_ip"],
        destination_ip=identity["destination_ip"],
        username=identity["username"],
        event_category=identity["event_category"],
        event_action=identity["event_action"],
        authentication_result=identity["authentication_result"],
        raw_message=raw,
        ingestion_timestamp=ingestion_timestamp or utc_now(),
        simulated=_simulated(record, simulated),
    )
