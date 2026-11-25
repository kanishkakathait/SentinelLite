from __future__ import annotations

from dataclasses import replace

import pandas as pd
import streamlit as st

from detection.engine import DetectionEngine
from pages.common import page_header, render_events


def render_rules_table(services) -> None:
    rows = []
    for rule in services.rules.list():
        rows.append({
            "rule_id": rule.rule_id, "name": rule.name, "severity": rule.severity,
            "enabled": rule.enabled, "thresholds": rule.config,
        })
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


def render(services) -> None:
    page_header("Detection rules", "Versioned YAML defaults with persistent enablement, supported thresholds, investigator guidance, and non-persistent dry-run examples.")
    st.caption("Sigma-inspired structured detections; this is not a full Sigma parser or a claim of Sigma-specification compatibility.")
    render_rules_table(services)
    rules = {rule.rule_id: rule for rule in services.rules.list()}
    rule_id = st.selectbox("Manage detection rule", list(rules))
    rule = rules[rule_id]
    st.subheader(rule.name)
    st.write(rule.description)
    st.caption(f"Severity: {rule.severity.title()} · Enabled: {rule.enabled} · Rule ID: {rule.rule_id}")
    with st.form(f"rule_configuration_{rule_id}"):
        enabled = st.checkbox("Rule enabled", value=rule.enabled)
        updated_config = {}
        for key, value in rule.config.items():
            label = key.replace("_", " ").title()
            if isinstance(value, bool):
                updated_config[key] = st.checkbox(label, value=value, key=f"{rule_id}_{key}")
            elif isinstance(value, int):
                maximum = 604800 if "seconds" in key else 1000 if "threshold" in key else 3
                minimum = 2 if key == "minimum_indicators" else 1
                updated_config[key] = int(st.number_input(label, min_value=minimum, max_value=maximum, value=value, key=f"{rule_id}_{key}"))
            elif isinstance(value, list):
                text = st.text_area(f"{label} (one item per line)", value="\n".join(value), key=f"{rule_id}_{key}")
                updated_config[key] = [item.strip() for item in text.splitlines() if item.strip()]
            else:
                updated_config[key] = st.text_input(label, value=str(value), key=f"{rule_id}_{key}")
        st.caption("Times use HH:MM and an IANA timezone such as Australia/Melbourne. A full detection rerun syncs dashboard and alert results after saving.")
        if st.form_submit_button("Save rule and rerun detection", type="primary", use_container_width=True):
            try:
                candidate = replace(rule, enabled=enabled, config=updated_config)
                DetectionEngine._validate_rule(candidate)
                services.rules.update(rule_id, enabled, updated_config)
                result = services.detection.run()
                st.success(f"Rule saved. Detection now has {result.active} active findings; analyst work was preserved.")
            except ValueError as error:
                st.error(str(error))
    documentation, actions, test = st.tabs(["Documentation & limitations", "Investigation recommendations", "Test against a sample scenario"])
    with documentation:
        st.write(rule.documentation)
        st.markdown("**Reprocessing model:** Detections recompute all episodes after ingestion. Stable results retain alert IDs and analyst state; superseded detections become inactive history. Thresholds are local contextual settings, not universal security standards.")
    with actions:
        for action in rule.recommended_actions:
            st.write(f"• {action}")
        st.warning("A detection is suspicious activity requiring investigation, not proof of compromise or authority to execute a response.")
    with test:
        st.caption("Runs only this detector against an included labelled synthetic scenario. Results are not written to the alert database and therefore cannot change real investigation state.")
        if st.button("Run sample dry test", key=f"dry_test_{rule_id}", use_container_width=True):
            try:
                events = services.rule_test_events(rule_id)
                findings = services.detection.dry_run(rule_id, events)
                st.metric("Dry-run findings", len(findings))
                for finding in findings:
                    with st.container(border=True):
                        st.write(finding.explanation)
                        st.caption(finding.severity_justification)
                        render_events(finding.evidence, f"dry_test_{rule_id}_{finding.deduplication_key}")
            except (ValueError, StopIteration) as error:
                st.error(f"Unable to run sample scenario: {error}")
