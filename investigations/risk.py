SEVERITY_POINTS = {"critical": 40, "high": 30, "medium": 20, "low": 10, "informational": 0}
EXPOSURE_POINTS = {"Internet-facing": 20, "Internal": 10, "Isolated": 5}
EVIDENCE_POINTS = {"Confirmed": 10, "Observed": 6, "Reported": 2}


def calculate_priority(severity: str, asset_criticality: int, exposure: str, evidence: str) -> dict[str, object]:
    if severity not in SEVERITY_POINTS:
        raise ValueError("Unknown severity")
    if not isinstance(asset_criticality, int) or not 1 <= asset_criticality <= 5:
        raise ValueError("Asset criticality must be between 1 and 5")
    if exposure not in EXPOSURE_POINTS or evidence not in EVIDENCE_POINTS:
        raise ValueError("Unknown exposure or evidence level")
    severity_points = SEVERITY_POINTS[severity]
    asset_points = asset_criticality * 6
    exposure_points = EXPOSURE_POINTS[exposure]
    evidence_points = EVIDENCE_POINTS[evidence]
    score = severity_points + asset_points + exposure_points + evidence_points
    level = "P1" if score >= 80 else "P2" if score >= 60 else "P3" if score >= 40 else "P4"
    return {
        "score": score,
        "level": level,
        "components": {
            "severity": severity_points, "asset_criticality": asset_points,
            "exposure": exposure_points, "evidence": evidence_points,
        },
    }
