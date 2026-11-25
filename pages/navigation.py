from __future__ import annotations

import streamlit as st

from core.navigation import NAV_BY_LABEL


def navigate_to(page_label: str) -> None:
    if page_label not in NAV_BY_LABEL:
        raise ValueError(f"Unknown navigation target: {page_label}")
    slug, _ = NAV_BY_LABEL[page_label]
    st.session_state["navigation"] = page_label
    st.session_state["navigation_query"] = slug
    st.query_params["page"] = slug
    if page_label != "Security Alerts":
        st.query_params.pop("alert_id", None)
    if page_label not in {"Incident Investigation", "Security Reports"}:
        st.query_params.pop("incident_id", None)
