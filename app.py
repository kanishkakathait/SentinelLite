from __future__ import annotations

import os

import streamlit as st

from core.config import DATABASE_PATH, PROJECT_ROOT
from core.navigation import NAV_BY_LABEL, NAV_GROUPS
from core.services import AppServices
from pages import detection_rules, incidents, overview, reports, security_alerts, security_events, settings, simulation_lab, threat_detection, vulnerabilities
from pages.common import brand_logo
from pages.navigation import navigate_to

st.set_page_config(page_title="SentinelLite", page_icon="🛡️", layout="wide", initial_sidebar_state="auto")


@st.cache_resource
def get_services(database_path: str) -> AppServices:
    return AppServices(database_path)


services = get_services(os.environ.get("SENTINELLITE_DB_PATH", str(DATABASE_PATH)))
st.markdown(f"<style>{(PROJECT_ROOT / 'assets' / 'style.css').read_text(encoding='utf-8')}</style>", unsafe_allow_html=True)

st.sidebar.markdown(
    '<div class="brand-block">'
    f'{brand_logo()}<div><div class="brand-title">SentinelLite</div>'
    '<div class="brand-subtitle">SECURITY OPERATIONS<br>&amp; INCIDENT RESPONSE</div></div></div>',
    unsafe_allow_html=True,
)
st.sidebar.caption("LOCAL-FIRST SECURITY MONITORING · EDUCATIONAL USE")

if st.query_params.get("demo") == "synthetic" and "demo_mode" not in st.session_state:
    st.session_state["demo_mode"] = True

demo_enabled = st.sidebar.toggle("Demo Mode", key="demo_mode", help="Load clearly labelled synthetic events, detections, and demonstration vulnerabilities. Generated records remain plainly marked simulated.")
if demo_enabled and not st.session_state.get("demo_loaded"):
    with st.sidebar.status("Loading synthetic demonstration…") as demo_status:
        result = services.load_demonstration()
        st.write(result["ingestion"].issue_summary)
        st.write(f"{result['detection'].active} active detections")
        demo_status.update(label="Synthetic demonstration ready", state="complete", expanded=False)
    st.session_state["demo_loaded"] = True
if not demo_enabled:
    st.session_state["demo_loaded"] = False
if "reduced_motion" not in st.session_state:
    st.session_state["reduced_motion"] = services.settings.get("reduced_motion", "false") == "true"


def persist_motion_preference() -> None:
    services.settings.set("reduced_motion", "true" if st.session_state["reduced_motion"] else "false")


st.sidebar.toggle("Reduced motion", key="reduced_motion", on_change=persist_motion_preference, help="Disable Plotly transitions and apply reduced-motion accessibility styling.")
st.sidebar.markdown(
    f'<div class="system-status"><span><i class="status-dot{(" demo" if demo_enabled else "")}"></i>SQLITE READY</span><strong>{"SIMULATED" if demo_enabled else "LOCAL MODE"}</strong></div>',
    unsafe_allow_html=True,
)

PAGE_RENDERERS = {
    "SOC Overview": overview.render,
    "Security Events": security_events.render,
    "Threat Detection": threat_detection.render,
    "Security Simulation Lab": simulation_lab.render,
    "Security Alerts": security_alerts.render,
    "Incident Investigation": incidents.render,
    "Vulnerability & Risk Register": vulnerabilities.render,
    "Security Reports": reports.render,
    "Detection Rules": detection_rules.render,
    "Settings & Documentation": settings.render,
}

requested_page = st.query_params.get("page")
if requested_page in {slug for slug, _ in NAV_BY_LABEL.values()} and st.session_state.get("navigation_query") != requested_page:
    page_label = next(label for label, (slug, _) in NAV_BY_LABEL.items() if slug == requested_page)
    st.session_state["navigation"] = page_label
    st.session_state["navigation_query"] = requested_page
navigation = st.session_state.get("navigation", "SOC Overview")
if navigation not in PAGE_RENDERERS:
    navigation = "SOC Overview"
for group_label, items in NAV_GROUPS:
    st.sidebar.markdown(f'<p class="nav-group-label">{group_label}</p>', unsafe_allow_html=True)
    for label, slug, icon in items:
        st.sidebar.button(
            f"{icon}  {label}", key=f"navigation_{slug}", on_click=navigate_to,
            args=(label,), type="primary" if label == navigation else "secondary",
            use_container_width=True, help=f"Open {label}" if label != navigation else f"Current page: {label}",
        )
st.sidebar.divider()
st.sidebar.caption(f"SQLite · {services.events.count():,} stored events")
st.sidebar.caption("No automatic containment · Data remains on this device")
if demo_enabled:
    st.sidebar.caption("SIMULATED DATA · Demo records persist when the switch is off.")
PAGE_RENDERERS[navigation](services)
