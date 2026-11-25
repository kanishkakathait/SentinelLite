SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def most_severe(values: list[str], default: str = "medium") -> str:
    return min(values, key=lambda value: SEVERITY_ORDER.get(value, 99), default=default)
