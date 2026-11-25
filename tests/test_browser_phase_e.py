from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import pytest

pytest.importorskip("playwright.sync_api", reason="Optional Playwright development tooling is required for browser checks")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ARTIFACTS = PROJECT_ROOT / "docs" / "screenshots"


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@contextmanager
def application_server():
    generated = PROJECT_ROOT / "data" / "generated"
    generated.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="responsive-browser-", dir=generated) as workspace:
        port = free_port()
        env = os.environ.copy()
        env["SENTINELLITE_DB_PATH"] = str(Path(workspace) / "responsive.db")
        env["PLAYWRIGHT_BROWSERS_PATH"] = str(PROJECT_ROOT / ".playwright-browsers")
        log_path = Path(workspace) / "server.log"
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen([sys.executable, "-m", "streamlit", "run", "app.py", "--server.headless", "true", "--server.port", str(port), "--browser.gatherUsageStats", "false"], cwd=PROJECT_ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
            try:
                for _ in range(80):
                    if process.poll() is not None:
                        raise RuntimeError("The application server stopped before readiness; inspect the captured launch log")
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1):
                            break
                    except urllib.error.URLError:
                        time.sleep(0.25)
                else:
                    raise TimeoutError("The application did not start within the settled readiness period")
                os.environ["PLAYWRIGHT_BROWSERS_PATH"] = env["PLAYWRIGHT_BROWSERS_PATH"]
                from playwright.sync_api import sync_playwright
                yield f"http://127.0.0.1:{port}/", sync_playwright
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


@pytest.mark.parametrize("label,viewport", [("desktop", 1440), ("tablet", 900), ("mobile", 390)])
def test_phase_e_responsive_browser_layouts(label, viewport):
    with application_server() as (url, start_browser), start_browser() as playwright_module:
        browser = playwright_module.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": viewport, "height": 1000}, device_scale_factor=1, reduced_motion="reduce")
        page.goto(url + "?page=soc-overview&demo=synthetic", wait_until="networkidle", timeout=90_000)
        page.locator("h1").filter(has_text="Security operations centre").wait_for(timeout=90_000)
        page.get_by_text("1,100", exact=True).first.wait_for(timeout=15_000)
        assert page.locator('[data-testid="stException"]').count() == 0
        widths = page.evaluate("({content: document.documentElement.scrollWidth, viewport: document.documentElement.clientWidth})")
        assert widths["content"] <= widths["viewport"] + 2, f"Unexpected horizontal overflow at {viewport}px: {widths}"
        if label == "mobile":
            assert page.evaluate("matchMedia('(prefers-reduced-motion: reduce)').matches") is True
            motion = page.locator(".kpi-shell").first.evaluate("element => getComputedStyle(element).animationName")
            assert motion == "none"
        page.screenshot(path=ARTIFACTS / f"responsive-{label}.png", full_page=False)
        browser.close()
