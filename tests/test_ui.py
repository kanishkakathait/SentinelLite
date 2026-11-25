from __future__ import annotations

from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from core.services import AppServices

APPLICATION = Path(__file__).resolve().parent.parent / "app.py"
PAGES = [
    "SOC Overview", "Security Events", "Threat Detection", "Security Simulation Lab", "Security Alerts",
    "Incident Investigation", "Vulnerability & Risk Register", "Security Reports",
    "Detection Rules", "Settings & Documentation",
]


@pytest.mark.parametrize("page", PAGES)
def test_all_navigation_pages_render_with_real_records(tmp_path, monkeypatch, page):
    database = tmp_path / f"{page.replace(' ', '_')}.db"
    monkeypatch.setenv("SENTINELLITE_DB_PATH", str(database))
    services = AppServices(database)
    services.load_demonstration()
    alert_ids = [alert["alert_id"] for alert in services.alerts.list()[:2]]
    incident_id = services.incidents.create("UI test incident", "Created from actual synthetic alert records.", "high", alert_ids)
    services.incidents.add_note(incident_id, "Supporting evidence", "Test analyst observation")
    application = AppTest.from_file(str(APPLICATION), default_timeout=90)
    application.run()
    application.session_state["navigation"] = page
    application.run()
    assert not application.exception, f"{page}: {application.exception}"


def test_demo_mode_loads_idempotent_synthetic_data(tmp_path, monkeypatch):
    database = tmp_path / "demo.db"
    monkeypatch.setenv("SENTINELLITE_DB_PATH", str(database))
    application = AppTest.from_file(str(APPLICATION), default_timeout=90)
    application.run()
    application.toggle[0].set_value(True).run()
    assert not application.exception
    persistence = AppServices(database)
    assert persistence.events.count() == 1100
    assert len(persistence.alerts.list()) == 21
    assert len(persistence.vulnerabilities.list()) == 5
