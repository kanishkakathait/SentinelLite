NAV_GROUPS = (
    ("MONITORING", (
        ("SOC Overview", "soc-overview", "◈"),
        ("Security Events", "security-events", "▤"),
        ("Threat Detection", "threat-detection", "⌁"),
        ("Security Simulation Lab", "simulation-lab", "⌬"),
        ("Security Alerts", "security-alerts", "⚠"),
    )),
    ("INVESTIGATION", (
        ("Incident Investigation", "incident-investigation", "◎"),
        ("Vulnerability & Risk Register", "vulnerability-risk-register", "◇"),
    )),
    ("MANAGEMENT", (
        ("Security Reports", "security-reports", "▥"),
        ("Detection Rules", "detection-rules", "⌘"),
        ("Settings & Documentation", "settings-documentation", "◌"),
    )),
)
NAV_ITEMS = [item for _, items in NAV_GROUPS for item in items]
NAV_BY_LABEL = {label: (slug, icon) for label, slug, icon in NAV_ITEMS}
