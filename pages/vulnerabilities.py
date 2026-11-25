from __future__ import annotations

from datetime import date

import pandas as pd
import plotly.express as px
import streamlit as st

from core.config import PROJECT_ROOT, REMEDIATION_STATUSES, SEVERITIES
from core.view_models import filter_vulnerabilities
from pages.common import SEVERITY_COLOURS, metric_card, page_header, semantic_table_styles, style_chart

STATUS_COLOURS = {"Open": "#A2B3C7", "In Progress": "#A78BFA", "Remediated": "#67E8F9", "Verified": "#73DFBD"}


def create_vulnerability(services) -> None:
    with st.expander("Create a vulnerability record"):
        with st.form("create_vulnerability"):
            identifier = st.text_input("Vulnerability ID (optional; generated if blank)", max_chars=100)
            title = st.text_input("Title", max_chars=300)
            description = st.text_area("Description", max_chars=20_000)
            asset = st.text_input("Affected asset", max_chars=300)
            columns = st.columns(3)
            severity = columns[0].selectbox("Severity", SEVERITIES)
            cve = columns[1].text_input("CVE identifier (optional)", placeholder="CVE-YYYY-NNNN")
            has_cvss = columns[2].checkbox("Official CVSS score supplied")
            cvss = st.number_input("CVSS base score from a trusted source", 0.0, 10.0, 0.0, 0.1) if has_cvss else None
            columns = st.columns(3)
            discovery = columns[0].date_input("Discovery date", value=date.today())
            criticality = columns[1].slider("Asset criticality", 1, 5, 3)
            exposure = columns[2].selectbox("Exposure", ["Internet-facing", "Internal", "Isolated"])
            evidence = st.selectbox("Available evidence", ["Confirmed", "Observed", "Reported"])
            recommendation = st.text_area("Remediation recommendation")
            owner = st.text_input("Remediation owner")
            status = st.selectbox("Initial remediation status", REMEDIATION_STATUSES)
            due = st.date_input("Remediation due date (optional)", value=None, key="new_vulnerability_due")
            verification = st.date_input("Verification date (required for Verified)", value=None, key="new_vulnerability_verified")
            with st.expander("Additional remediation notes or existing evidence (optional)"):
                remediation_notes = st.text_area("Notes and supplied evidence, not automatic scanner findings", max_chars=20_000)
            if st.form_submit_button("Create vulnerability", type="primary", use_container_width=True):
                try:
                    vulnerability_id = services.vulnerabilities.create({
                        "vulnerability_id": identifier or None, "title": title, "description": description,
                        "affected_asset": asset, "severity": severity, "cve_id": cve or None, "cvss_score": cvss,
                        "discovery_date": discovery.isoformat(), "asset_criticality": criticality,
                        "exposure": exposure, "evidence": evidence, "remediation_recommendation": recommendation,
                        "remediation_owner": owner, "remediation_status": status, "remediation_evidence": remediation_notes,
                        "due_date": due.isoformat() if due else None,
                        "verification_date": verification.isoformat() if verification else None,
                    })
                    st.success("Vulnerability record created.")
                    st.text(f"Created vulnerability ID: {vulnerability_id}")
                except (ValueError, TypeError) as error:
                    st.error(str(error))
    with st.expander("Import a structured vulnerability CSV"):
        st.caption("Fields mirror the creation form. All entries are manual supplied evidence, never scanner output or free-form executable content.")
        uploaded = st.file_uploader("Vulnerability register CSV", type=["csv"])
        if st.button("Import vulnerability records"):
            if not uploaded:
                st.error("Choose a CSV file first.")
            else:
                try:
                    result = services.vulnerabilities.import_csv(uploaded.getvalue())
                    st.success(f"Created {result['created']} records and skipped {result['duplicates']} duplicates.")
                    if result["errors"]:
                        st.dataframe(pd.DataFrame(result["errors"]), use_container_width=True, hide_index=True)
                except ValueError as error:
                    st.error(str(error))
    template = PROJECT_ROOT / "data" / "sample" / "vulnerability_template.csv"
    if template.exists():
        st.download_button("Download structured CSV template", template.read_bytes(), "vulnerability_template.csv", "text/csv")


def risk_overview(services) -> None:
    records = services.vulnerabilities.list()
    metrics = services.vulnerabilities.metrics()
    cards = [
        ("vuln_open", "⚠", "Open Vulnerabilities", metrics["open"], "Open and In Progress", "warning", None),
        ("vuln_priority", "△", "High-Priority (P1 / P2)", metrics["high_priority"], "Open P1 and P2 records", "danger" if metrics["high_priority"] else "success", None),
        ("vuln_overdue", "◷", "Overdue Remediation", metrics["overdue"], "Past due date and unfinished", "danger" if metrics["overdue"] else "success", None),
        ("vuln_remediated", "✓", "Remediated", metrics["progress"]["Remediated"], "Closed by remediation work", "success", None),
        ("vuln_verified", "◎", "Verified Remediation", metrics["progress"]["Verified"], "Includes a verification date", "success", None),
    ]
    for column, arguments in zip(st.columns(5), cards):
        with column:
            metric_card(*arguments)
    if st.button("Add clearly labelled demo vulnerabilities", key="add_demo_vulnerabilities"):
        inserted = services.vulnerabilities.seed_demonstration_records()
        st.success(f"Added {inserted} DEMO records with synthetic metadata. These are manual examples, not scanner results.")
        st.rerun()
    if not records:
        st.info("No manual vulnerability records exist. Create/import entries or add explicit DEMO examples to explore this view.")
        return
    st.subheader("Filter the risk register")
    owners = ["All"] + sorted({item["remediation_owner"] for item in records if item["remediation_owner"]})
    controls = st.columns([1, 1, 1, 1, 2, 1.5])
    severity = controls[0].selectbox("Severity", ["All", *SEVERITIES], key="vulnerability_severity_filter")
    status = controls[1].selectbox("Status", ["All", *REMEDIATION_STATUSES], key="vulnerability_status_filter")
    priority = controls[2].selectbox("Priority", ["All", "P1", "P2", "P3", "P4"], key="vulnerability_priority_filter")
    owner = controls[3].selectbox("Owner", owners, key="vulnerability_owner_filter")
    keyword = controls[4].text_input("Search assets, descriptions, CVE, owners or titles", placeholder="Search supplied records")
    sort_order = controls[5].selectbox("Sort by", ["Highest priority", "Earliest due", "Newest discovery", "Severity"])
    filtered = filter_vulnerabilities(records, severity, status, priority, owner, keyword.strip(), sort_order)
    st.caption(f"Showing {len(filtered):,} of {len(records):,} manual records. Priority and severity are independent of official CVSS.")
    left, right = st.columns([1, 1])
    with left:
        st.caption("Severity distribution · current filters")
        if filtered:
            distribution = pd.DataFrame(filtered).groupby("severity").size().reindex(SEVERITIES, fill_value=0).rename("records").reset_index()
            figure = px.bar(distribution, x="severity", y="records", color="severity", color_discrete_map=SEVERITY_COLOURS, labels={"severity": "Severity", "records": "Manual records"})
            figure.update_layout(showlegend=False, height=290, xaxis={"title": "Severity"}, yaxis={"title": "Records"})
            st.plotly_chart(style_chart(figure), use_container_width=True, config={"displaylogo": False})
        else:
            st.info("No severity results match the filters.")
    with right:
        st.caption("Remediation progress · current filters")
        if filtered:
            status_frame = pd.DataFrame(filtered).groupby("remediation_status").size().rename("records").reset_index()
            complete = status_frame.loc[status_frame["remediation_status"].isin({"Remediated", "Verified"}), "records"].sum()
            total = status_frame["records"].sum()
            st.metric("Remediated or verified", f"{complete}/{total}", help="This is a count and fraction of the current filtered manual register, not a probability of effectiveness.")
            st.progress(complete / total if total else 0)
            figure = px.bar(status_frame, x="records", y="remediation_status", orientation="h", color="remediation_status", color_discrete_map=STATUS_COLOURS, labels={"records": "Records", "remediation_status": "Remediation status"})
            figure.update_layout(showlegend=False, height=290, xaxis={"title": "Records"}, yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(style_chart(figure), use_container_width=True, config={"displaylogo": False})
        else:
            st.info("No remediation results match the filters.")
    st.subheader("Vulnerability and remediation table")
    if not filtered:
        st.info("No manual records match the selected filters. Clear a filter or create an entry.")
        return
    display = pd.DataFrame([{
        "vulnerability_id": item["vulnerability_id"], "title": item["title"], "affected_asset": item["affected_asset"],
        "severity": item["severity"], "priority": item["priority_level"], "score": item["priority_score"],
        "status": item["remediation_status"], "owner": item["remediation_owner"], "due_date": item["due_date"] or "Not specified",
    } for item in filtered])
    st.dataframe(semantic_table_styles(display.rename(columns={"priority": "severity_priority", "status": "remediation_status"})), use_container_width=True, hide_index=True, column_config={"vulnerability_id": "Record ID", "title": "Title", "affected_asset": "Asset", "severity": "Severity", "severity_priority": "Priority", "score": "Custom score", "remediation_status": "Status", "owner": "Owner", "due_date": "Remediation due"})
    with st.expander("Edit a remediation record", expanded=True):
        selected = st.selectbox("Select an existing vulnerability record", [item["vulnerability_id"] for item in filtered], key="vulnerability_editor_id")
        item = services.vulnerabilities.get(selected)
        st.subheader(item["title"])
        st.text(f"{item['affected_asset']} · {item['severity']} severity · {item['priority_level']} priority ({item['priority_score']}/100 custom points)")
        st.text(f"Description: {item['description']}")
        if item["cve_id"] or item["cvss_score"] is not None:
            st.text(f"Supplied CVE / CVSS: {item['cve_id'] or 'No CVE ID supplied'} / {item['cvss_score'] if item['cvss_score'] is not None else 'Not scored'}")
        if item["remediation_recommendation"]:
            st.caption("Current recommendation")
            st.text(item["remediation_recommendation"])
        with st.form(f"update_vulnerability_{selected}"):
            owner = st.text_input("Assigned remediation owner", value=item["remediation_owner"])
            values = st.columns(3)
            status = values[0].selectbox("Remediation status", REMEDIATION_STATUSES, index=REMEDIATION_STATUSES.index(item["remediation_status"]))
            due = values[1].date_input("Due date (optional)", value=date.fromisoformat(item["due_date"]) if item["due_date"] else None, key=f"update_due_{selected}")
            verification = values[2].date_input("Verification date (required for Verified)", value=date.fromisoformat(item["verification_date"]) if item["verification_date"] else None, key=f"update_verify_{selected}")
            notes = st.text_area("Remediation notes and evidence", value=item["remediation_evidence"], max_chars=20_000, placeholder="Document validation, approvals, remediation work actually performed, evidence paths you have authority to reference, and uncertainty.")
            st.caption("Owner/status/notes updates are persisted locally, with a remediation-action timestamp. Verified status requires an explicit verification date. No scanner or external remediation is performed.")
            if st.form_submit_button("Save remediation update", type="primary", use_container_width=True):
                try:
                    services.vulnerabilities.update(selected, status, owner, due.isoformat() if due else None, notes, verification.isoformat() if verification else None)
                    st.success("Owner, status, notes, and verification details saved.")
                    st.rerun()
                except ValueError as error:
                    st.error(str(error))


def render(services) -> None:
    page_header("Vulnerability & risk register", "Track manual vulnerability records, evidence and remediation with a transparent local priority model, not automated findings or a CVSS calculator.", eyebrow="Investigation / Exposure & remediation")
    overview, create, methodology = st.tabs(["Risk overview", "Create / import", "Priority model"])
    with overview:
        risk_overview(services)
    with create:
        create_vulnerability(services)
    with methodology:
        st.write("Priority = severity points + asset criticality × 6 + exposure points + evidence points. The result is out of 100 and is not an official CVSS score.")
        st.table(pd.DataFrame([
            {"Component": "Severity", "Scale": "Critical 40 · High 30 · Medium 20 · Low 10 · Informational 0"},
            {"Component": "Asset criticality", "Scale": "1–5 × 6 → 6–30 points"},
            {"Component": "Exposure", "Scale": "Internet-facing 20 · Internal 10 · Isolated 5"},
            {"Component": "Available evidence", "Scale": "Confirmed 10 · Observed 6 · Reported 2"},
            {"Component": "Priority bands", "Scale": "P1 ≥80 · P2 ≥60 · P3 ≥40 · P4 <40"},
        ]))
        st.caption("CVSS can be stored separately when supplied by a trusted source. Priority is an explainable triage aid, not organisational risk acceptance, threat intelligence, or a vulnerability scan.")
