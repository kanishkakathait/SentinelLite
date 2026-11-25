from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import urlopen

from core.services import AppServices
from playwright.sync_api import sync_playwright

PROJECT_ROOT = Path(__file__).resolve().parent.parent
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(PROJECT_ROOT / ".playwright-browsers"))


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def prepare_demonstration() -> tuple[str, str]:
    services = AppServices(os.environ["SENTINELLITE_DB_PATH"])
    services.load_demonstration()
    alert = next(item for item in services.alerts.list() if item["rule_id"] == "SL-AUTH-002")
    incidents = services.incidents.list()
    if incidents:
        incident_id = incidents[0]["incident_id"]
    else:
        incident_id = services.incidents.create(
            "Potential credential misuse — suspicious success",
            "A successful login followed five failures for the same account and reserved-documentation source IP. The conclusion requires user and system-owner validation.",
            "high",
            [alert["alert_id"]],
            "Validate the login with the account owner; review related authentication events and authorised access pathways.",
        )
        services.incidents.update_status(incident_id, "Investigating", note="Initial triage of labelled synthetic evidence")
        services.incidents.add_note(incident_id, "Initial observations", "Five failures precede a success within five minutes. Both the source and account are consistent across the selected evidence.")
        services.incidents.add_note(incident_id, "False-positive considerations", "A user retrying a forgotten password, stale saved credentials, or authorised testing could explain this sequence.")
        services.incidents.add_note(incident_id, "Risk assessment", "The finding is high priority for triage but account compromise is not established. Evidence is limited to synthetic authentication logs.")
        services.incidents.add_note(incident_id, "Final conclusion", "Investigation is in progress. Validate with the account owner before considering credential resets or access changes.")
    return alert["alert_id"], incident_id


def capture() -> None:
    workspace = tempfile.TemporaryDirectory(prefix="sentinellite-screenshots-", dir=PROJECT_ROOT / "data" / "generated")
    os.environ["SENTINELLITE_DB_PATH"] = str(Path(workspace.name) / "screenshots.db")
    port = free_port()
    log_path = PROJECT_ROOT / "data" / "generated" / "screenshot-server.log"
    process = None
    try:
        alert_id, incident_id = prepare_demonstration()
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [sys.executable, "-m", "streamlit", "run", "app.py", "--server.headless", "true", "--server.port", str(port), "--browser.gatherUsageStats", "false"],
                cwd=PROJECT_ROOT, env=os.environ.copy(), stdout=log, stderr=subprocess.STDOUT,
            )
            base_url = f"http://127.0.0.1:{port}/"
            for attempt in range(90):
                if process.poll() is not None:
                    raise RuntimeError(f"Streamlit stopped before capture; inspect {log_path}")
                try:
                    with urlopen(base_url, timeout=1):
                        break
                except URLError:
                    time.sleep(1)
            else:
                raise TimeoutError("Streamlit did not become ready within 90 seconds")
            views = [
                ("soc-overview", "Security operations centre", {}, "soc-overview.png"),
                ("security-events", "Security events", {}, "security-events.png"),
                ("threat-detection", "Threat detection", {}, "threat-detection.png"),
                ("simulation-lab", "Security Simulation Lab", {}, "simulation-lab.png"),
                ("security-alerts", "Security alerts", {"alert_id": alert_id}, "alert-investigation.png"),
                ("incident-investigation", "Incident investigation", {"incident_id": incident_id}, "incident-management.png"),
                ("vulnerability-risk-register", "Vulnerability & risk register", {}, "vulnerability-register.png"),
                ("security-events", "Security events", {}, "public-data-validation.png"),
                ("security-reports", "Security reports", {"incident_id": incident_id}, "security-reports.png"),
            ]
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width": 1440, "height": 1000}, device_scale_factor=1)
                for slug, title, parameters, filename in views:
                    query = urlencode({"page": slug, "demo": "synthetic", **parameters})
                    page.goto(f"{base_url}?{query}", wait_until="networkidle", timeout=90_000)
                    page.locator("h1").filter(has_text=title).first.wait_for(timeout=90_000)
                    page.wait_for_timeout(2000)
                    if filename == "incident-management.png":
                        page.get_by_role("tab", name="Visual timeline").click()
                    if filename == "simulation-lab.png":
                        page.get_by_role("button", name="Run simulation scenario", exact=True).click()
                        page.get_by_text("Step 4 · Inspect actual persisted alerts", exact=True).wait_for(timeout=60_000)
                    if filename == "public-data-validation.png":
                        page.get_by_role("tab", name="Public dataset validation", exact=True).click()
                        page.get_by_role("button", name="Import and validate public security log", exact=True).click()
                        page.get_by_text("Triggered detections scoped to this file", exact=True).wait_for(timeout=60_000)
                    if filename == "alert-investigation.png":
                        page.get_by_text(f"Full alert ID: {alert_id}", exact=True).evaluate(
                            "element => element.scrollIntoView({block: 'start', behavior: 'instant'})"
                        )
                    page.wait_for_timeout(750)
                    destination = PROJECT_ROOT / "docs" / "screenshots" / filename
                    page.screenshot(path=destination, full_page=filename != "alert-investigation.png")
                    if not destination.exists() or destination.stat().st_size < 10_000:
                        raise RuntimeError(f"Screenshot appears incomplete: {destination}")
                    print(f"Captured {destination.relative_to(PROJECT_ROOT)}")
                browser.close()
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        workspace.cleanup()


if __name__ == "__main__":
    capture()
