from __future__ import annotations

import re
from datetime import datetime
from zoneinfo import ZoneInfo

AUTH_PREFIX = re.compile(
    r"^(?P<timestamp>(?:\d{4}-\d{2}-\d{2}T\S+)|(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))"
    r"\s+(?P<hostname>\S+)\s+sshd(?:\[\d+\])?:\s+(?P<message>.+)$"
)
AUTH_RESULT = re.compile(
    r"^(?P<result>Failed|Accepted)\s+(?:password|publickey|keyboard-interactive/pam)\s+"
    r"for\s+(?:invalid user\s+)?(?P<username>\S+)\s+from\s+(?P<source_ip>\S+)\s+port\s+\d+",
    re.IGNORECASE,
)


def parse_linux_auth_line(line: str, default_timezone: str, reference_year: int | None = None, allow_generic_ssh: bool = False) -> dict[str, str | None]:
    match = AUTH_PREFIX.match(line.strip())
    if not match:
        raise ValueError("Not a supported sshd authentication record")
    result = AUTH_RESULT.match(match["message"])
    timestamp = match["timestamp"]
    if not timestamp[0].isdigit():
        year = reference_year or datetime.now(ZoneInfo(default_timezone)).year
        parsed = datetime.strptime(f"{year} {timestamp}", "%Y %b %d %H:%M:%S")
        timestamp = parsed.replace(tzinfo=ZoneInfo(default_timezone)).isoformat()
    if not result:
        if not allow_generic_ssh:
            raise ValueError("Unsupported sshd message; expected Failed or Accepted authentication")
        return {
            "timestamp": timestamp,
            "event_source": "linux_sshd", "hostname": match["hostname"],
            "username": None, "source_ip": None,
            "event_category": "system", "event_action": "sshd_message",
            "authentication_result": None, "raw_message": line.strip(),
        }
    success = result["result"].casefold() == "accepted"
    return {
        "timestamp": timestamp,
        "event_source": "linux_sshd",
        "hostname": match["hostname"],
        "source_ip": result["source_ip"],
        "username": result["username"],
        "event_category": "authentication",
        "event_action": "login",
        "authentication_result": "success" if success else "failure",
        "raw_message": line.strip(),
    }
