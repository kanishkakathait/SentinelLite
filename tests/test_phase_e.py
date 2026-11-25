from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import plotly.graph_objects as go
from streamlit.testing.v1 import AppTest

from core.services import AppServices
from core.view_models import filter_vulnerabilities
from pages.common import style_chart

APP = Path(__file__).resolve().parent.parent / "app.py"


def vulnerability_examples():
    return [
        {"vulnerability_id": "V-001", "title": "Legacy API package", "affected_asset": "api-prod", "severity": "critical", "priority_level": "P1", "priority_score": 90, "remediation_status": "Open", "remediation_owner": "Alice", "due_date": "2026-12-02", "discovery_date": "2026-11-01"},
        {"vulnerability_id": "V-002", "title": "Incorrect security headers", "affected_asset": "vpn-prod", "severity": "high", "priority_level": "P2", "priority_score": 68, "remediation_status": "In Progress", "remediation_owner": "Bob", "due_date": "2026-12-01", "discovery_date": "2026-10-01"},
        {"vulnerability_id": "V-003", "title": "Verbose errors", "affected_asset": "staff-portal", "severity": "low", "priority_level": "P4", "priority_score": 35, "remediation_status": "Verified", "remediation_owner": "Alice", "due_date": None, "discovery_date": "2026-11-20"},
    ]


def test_vulnerability_filters_sort_and_null_due_dates():
    records = vulnerability_examples()
    assert [item["vulnerability_id"] for item in filter_vulnerabilities(records, sort_order="Highest priority")] == ["V-001", "V-002", "V-003"]
    assert filter_vulnerabilities(records, severity="high")[0]["vulnerability_id"] == "V-002"
    assert filter_vulnerabilities(records, priority="P1")[0]["vulnerability_id"] == "V-001"
    assert filter_vulnerabilities(records, owner="Alice")[0]["vulnerability_id"] == "V-001"
    assert [item["vulnerability_id"] for item in filter_vulnerabilities(records, keyword="api-prod")] == ["V-001"]
    assert filter_vulnerabilities(records, status="Verified")[0]["vulnerability_id"] == "V-003"
    assert [item["vulnerability_id"] for item in filter_vulnerabilities(records, sort_order="Earliest due")] == ["V-002", "V-001", "V-003"]
    assert filter_vulnerabilities(records, sort_order="Severity")[0]["severity"] == "critical"
    with pytest.raises(ValueError, match="Unsupported"):
        filter_vulnerabilities(records, sort_order="formula-injection")


def test_risk_metrics_and_remediation_notes_persist(services):
    services.vulnerabilities.seed_demonstration_records()
    records = services.vulnerabilities.list()
    metrics = services.vulnerabilities.metrics()
    assert metrics["open"] == sum(item["remediation_status"] in {"Open", "In Progress"} for item in records)
    assert metrics["high_priority"] == sum(item["priority_level"] in {"P1", "P2"} and item["remediation_status"] in {"Open", "In Progress"} for item in records)
    assert metrics["progress"]["Verified"] == sum(item["remediation_status"] == "Verified" for item in records)
    services.vulnerabilities.update("DEMO-VULN-001", "Verified", "Identity owner", "2026-12-01", "Validated test fix in an explicitly supplied demo record", "2026-11-25")
    restarted = AppServices(services.database.path)
    record = restarted.vulnerabilities.get("DEMO-VULN-001")
    assert record["remediation_status"] == "Verified"
    assert record["remediation_owner"] == "Identity owner"
    assert record["remediation_evidence"] == "Validated test fix in an explicitly supplied demo record"
    action = restarted.database.fetch_one("SELECT status AS remediation_status, owner AS remediation_owner FROM remediation_actions WHERE vulnerability_id = ? ORDER BY action_id DESC LIMIT 1", ("DEMO-VULN-001",))
    assert action["remediation_status"] == "Verified"
    assert action["remediation_owner"] == "Identity owner"


def test_reduced_motion_persists_and_disables_plotly_transition(tmp_path, monkeypatch):
    database = tmp_path / "motion-settings.db"
    monkeypatch.setenv("SENTINELLITE_DB_PATH", str(database))
    application = AppTest.from_file(str(APP), default_timeout=60)
    application.run()
    application.toggle[1].set_value(True).run()
    assert not application.exception
    assert AppServices(database).settings.get("reduced_motion") == "true"
    with patch("pages.common.st.session_state", {"reduced_motion": True}):
        figure = style_chart(go.Figure())
        assert figure.layout.transition.duration == 0
    with patch("pages.common.st.session_state", {"reduced_motion": False}):
        figure = style_chart(go.Figure())
        assert figure.layout.transition.duration == 250


def test_full_register_filter_is_dashboard_data_not_a_supplied_score(services):
    services.vulnerabilities.seed_demonstration_records()
    records = services.vulnerabilities.list()
    frames = []
    for severity in ("critical", "high", "medium", "low"):
        frames.extend(filter_vulnerabilities(records, severity=severity))
    assert len(frames) == len(records)
    assert {item["priority_score"] for item in records} == {item["priority_score"] for item in frames}
    assert services.vulnerabilities.metrics()["high_priority"] >= 1
