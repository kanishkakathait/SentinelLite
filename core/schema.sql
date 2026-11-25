PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    config_json TEXT NOT NULL DEFAULT '{}',
    documentation TEXT NOT NULL,
    recommended_actions_json TEXT NOT NULL DEFAULT '[]',
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_events (
    event_id TEXT PRIMARY KEY,
    event_timestamp TEXT NOT NULL,
    event_source TEXT NOT NULL,
    hostname TEXT,
    source_ip TEXT,
    destination_ip TEXT,
    username TEXT,
    event_category TEXT NOT NULL,
    event_action TEXT NOT NULL,
    authentication_result TEXT,
    raw_message TEXT NOT NULL,
    ingestion_timestamp TEXT NOT NULL,
    simulated INTEGER NOT NULL DEFAULT 0 CHECK (simulated IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(event_timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON security_events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_username ON security_events(username);
CREATE INDEX IF NOT EXISTS idx_events_auth_result ON security_events(authentication_result);

CREATE TABLE IF NOT EXISTS ingestion_batches (
    batch_id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    format TEXT NOT NULL,
    received_records INTEGER NOT NULL,
    accepted_records INTEGER NOT NULL,
    duplicate_records INTEGER NOT NULL,
    rejected_records INTEGER NOT NULL,
    errors_json TEXT NOT NULL DEFAULT '[]',
    simulated INTEGER NOT NULL DEFAULT 0 CHECK (simulated IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS security_alerts (
    alert_id TEXT PRIMARY KEY,
    deduplication_key TEXT NOT NULL UNIQUE,
    rule_id TEXT NOT NULL REFERENCES detection_rules(rule_id),
    detection_name TEXT NOT NULL,
    alert_timestamp TEXT NOT NULL,
    created_at TEXT NOT NULL,
    severity TEXT NOT NULL,
    source_ip TEXT,
    username TEXT,
    hostname TEXT,
    status TEXT NOT NULL DEFAULT 'New',
    explanation TEXT NOT NULL,
    severity_justification TEXT NOT NULL,
    details_json TEXT NOT NULL DEFAULT '{}',
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    superseded_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(alert_timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON security_alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON security_alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_entities ON security_alerts(source_ip, username);
CREATE INDEX IF NOT EXISTS idx_alerts_active ON security_alerts(active);

CREATE TABLE IF NOT EXISTS alert_events (
    alert_id TEXT NOT NULL REFERENCES security_alerts(alert_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL REFERENCES security_events(event_id),
    evidence_role TEXT NOT NULL DEFAULT 'supporting',
    PRIMARY KEY (alert_id, event_id)
);

CREATE INDEX IF NOT EXISTS idx_alert_events_event ON alert_events(event_id);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT,
    affected_users_json TEXT NOT NULL DEFAULT '[]',
    affected_hosts_json TEXT NOT NULL DEFAULT '[]',
    source_ips_json TEXT NOT NULL DEFAULT '[]',
    recommended_actions TEXT NOT NULL DEFAULT '',
    resolution_summary TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS incident_alerts (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    alert_id TEXT NOT NULL REFERENCES security_alerts(alert_id),
    PRIMARY KEY (incident_id, alert_id)
);

CREATE TABLE IF NOT EXISTS investigation_notes (
    note_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT REFERENCES incidents(incident_id) ON DELETE CASCADE,
    alert_id TEXT REFERENCES security_alerts(alert_id) ON DELETE CASCADE,
    category TEXT NOT NULL,
    note TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK (
        (incident_id IS NOT NULL AND alert_id IS NULL)
        OR (incident_id IS NULL AND alert_id IS NOT NULL)
    )
);

CREATE TABLE IF NOT EXISTS status_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL CHECK (entity_type IN ('alert', 'incident', 'vulnerability')),
    entity_id TEXT NOT NULL,
    previous_status TEXT,
    new_status TEXT NOT NULL,
    changed_at TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    vulnerability_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    affected_asset TEXT NOT NULL,
    severity TEXT NOT NULL,
    cve_id TEXT,
    cvss_score REAL,
    discovery_date TEXT NOT NULL,
    asset_criticality INTEGER NOT NULL CHECK (asset_criticality BETWEEN 1 AND 5),
    exposure TEXT NOT NULL,
    evidence TEXT NOT NULL,
    priority_score REAL NOT NULL,
    priority_level TEXT NOT NULL,
    remediation_recommendation TEXT NOT NULL,
    remediation_owner TEXT NOT NULL,
    remediation_status TEXT NOT NULL,
    due_date TEXT,
    remediation_evidence TEXT NOT NULL DEFAULT '',
    verification_date TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_status ON vulnerabilities(remediation_status);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_due_date ON vulnerabilities(due_date);

CREATE TABLE IF NOT EXISTS remediation_actions (
    action_id INTEGER PRIMARY KEY AUTOINCREMENT,
    vulnerability_id TEXT NOT NULL REFERENCES vulnerabilities(vulnerability_id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    owner TEXT NOT NULL,
    status TEXT NOT NULL,
    due_date TEXT,
    evidence TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    details TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS application_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
