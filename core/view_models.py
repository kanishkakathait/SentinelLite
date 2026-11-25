from __future__ import annotations

from typing import Any

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


def sort_alerts(records: list[dict[str, Any]], sort_order: str) -> list[dict[str, Any]]:
    modes = {
        "Newest first": lambda item: (item["alert_timestamp"], item["alert_id"]),
        "Oldest first": lambda item: (item["alert_timestamp"], item["alert_id"]),
        "Severity, newest first": lambda item: (SEVERITY_RANK.get(item["severity"], -1), item["alert_timestamp"], item["alert_id"]),
        "Severity, oldest first": lambda item: (SEVERITY_RANK.get(item["severity"], -1), item["alert_timestamp"], item["alert_id"]),
        "Lowest severity first": lambda item: (-SEVERITY_RANK.get(item["severity"], -1), item["alert_timestamp"], item["alert_id"]),
    }
    if sort_order not in modes:
        raise ValueError("Unsupported alert sort order")
    return sorted(records, key=modes[sort_order], reverse=sort_order != "Oldest first")


def paginate(records: list[Any], page: int, page_size: int) -> tuple[list[Any], int, int]:
    if page_size <= 0:
        raise ValueError("Page size must be positive")
    total_pages = max(1, (len(records) + page_size - 1) // page_size)
    current_page = max(1, min(page, total_pages))
    start = (current_page - 1) * page_size
    return records[start:start + page_size], current_page, total_pages


def filter_vulnerabilities(records: list[dict[str, Any]], severity: str | None = None, status: str | None = None,
                           priority: str | None = None, owner: str | None = None,
                           keyword: str = "", sort_order: str = "Highest priority") -> list[dict[str, Any]]:
    def matches(item: dict[str, Any]) -> bool:
        if severity and severity != "All" and item["severity"] != severity:
            return False
        if status and status != "All" and item["remediation_status"] != status:
            return False
        if priority and priority != "All" and item["priority_level"] != priority:
            return False
        if owner and owner != "All" and item["remediation_owner"] != owner:
            return False
        return keyword.casefold() in " ".join(str(item.get(field) or "") for field in ("title", "affected_asset", "cve_id", "description", "remediation_owner")).casefold()

    filtered = [item for item in records if matches(item)]
    if sort_order == "Highest priority":
        return sorted(filtered, key=lambda item: (item["priority_score"], item["vulnerability_id"]), reverse=True)
    if sort_order == "Earliest due":
        return sorted(filtered, key=lambda item: (not bool(item.get("due_date")), item.get("due_date") or "9999-12-31", item["vulnerability_id"]))
    if sort_order == "Newest discovery":
        return sorted(filtered, key=lambda item: (item["discovery_date"], item["priority_score"]), reverse=True)
    if sort_order == "Severity":
        return sorted(filtered, key=lambda item: (SEVERITY_RANK.get(item["severity"], -1), item["priority_score"], item["vulnerability_id"]), reverse=True)
    raise ValueError("Unsupported vulnerability sort order")
