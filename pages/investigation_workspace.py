from __future__ import annotations

import html

import streamlit as st

from pages.common import render_events

NOTE_CATEGORIES = (
    "Initial observations", "Supporting evidence", "Possible explanations",
    "False-positive considerations", "Risk assessment", "Recommended response", "Final conclusion",
)


def render_timeline_entries(entries: list[dict], incident_id: str, services, limit: int = 100) -> None:
    st.caption("Markers: 🔴 failed authentication · 🟢 success · 🟠 detection · 🔵 alert creation · 🟣 analyst action")
    visible = entries[:limit]
    if len(visible) < len(entries):
        st.warning(f"Showing {len(visible)} visual nodes out of {len(entries)} timeline entries for performance. The accessible table and full report include all entries.")
    for index, entry in enumerate(visible):
        marker = entry.get("marker", "event")
        left, right = st.columns([5, 1.4])
        with left:
            st.markdown(
                f'<div class="timeline-node {html.escape(str(marker))}">'
                f'<div class="timeline-time">{html.escape(str(entry["timestamp"]))}</div>'
                f'<div class="timeline-title">{html.escape(str(entry["title"]))}</div></div>',
                unsafe_allow_html=True,
            )
        right.caption("Inspect the underlying stored record")
        def select_entry(entry=entry):
            st.session_state["timeline_focus"] = {"incident_id": incident_id, "entry": entry}
        right.button("Inspect evidence", key=f"timeline_{incident_id}_{index}_{entry['reference']}", on_click=select_entry)
    selected = st.session_state.get("timeline_focus")
    if selected and selected.get("incident_id") == incident_id:
        entry = selected["entry"]
        with st.expander(f"Timeline evidence · {entry['type']} · {entry['title']}", expanded=True):
            render_timeline_detail(services, entry, incident_id)


def render_timeline_detail(services, entry: dict, incident_id: str) -> None:
    entity_type = entry.get("entity_type")
    timestamp = entry["timestamp"]
    reference = entry.get("reference", "Not supplied")
    st.text(f"Type: {entry['type']} · Exact timestamp: {timestamp} · Reference: {reference}")
    if entity_type == "security_event":
        event = services.events.get(reference)
        if not event:
            st.info("The underlying event no longer exists in the current database. The timeline excerpt remains below.")
        else:
            st.code(event.raw_message, language="text", wrap_lines=True)
            st.text(f"Source IP: {event.source_ip or 'Not supplied'} · Account: {event.username or 'Not supplied'} · Host: {event.hostname or 'Not supplied'}")
            st.text(f"Result: {event.authentication_result or 'Not supplied'} · Category: {event.event_category} · Source: {event.event_source}")
    elif entity_type == "alert":
        try:
            alert = services.alerts.get(reference)
        except ValueError:
            st.info("The linked alert is unavailable in the current database; the timeline reference has been preserved.")
        else:
            st.text(f"{alert['detection_name']} · {alert['severity']} · {alert['status']}")
            st.text(f"Full alert ID: {alert['alert_id']}")
            st.text(alert["explanation"])
            with st.expander("Supporting event details"):
                render_events(services.alerts.evidence(reference), f"timeline_alert_{reference}")
    elif entity_type == "investigation_note":
        matches = [note for note in services.incidents.notes(incident_id) if str(note["note_id"]) == str(reference)]
        if matches:
            note = matches[0]
            st.text(f"{note['category']} · {note['author']} · Created {note['created_at']}")
            if note.get("last_edited_at"):
                st.text(f"Last edit recorded at {note['last_edited_at']}")
            st.text(note["note"])
        else:
            st.info("The note was not found in this incident; its timeline excerpt has not been modified.")
    else:
        st.text(entry.get("detail") or "No additional detail has been recorded.")
    st.text("Raw timeline excerpt (plain text):")
    st.text(str(entry.get("detail") or "No additional detail has been recorded."))


def render_incident_notes(services, incident_id: str) -> None:
    st.subheader("Analyst notes")
    st.caption("Notes persist in SQLite. Edits retain their creation timestamp and are independently recorded in the audit log.")
    for note in services.incidents.notes(incident_id):
        with st.container(border=True):
            st.text(f"Note {note['note_id']} · {note['category']} · {note['author']}")
            st.text(f"Created: {note['created_at']}" + (f" · Last edited: {note['last_edited_at']}" if note.get("last_edited_at") else ""))
            st.text(note["note"])
    with st.expander("Add an investigation note", expanded=not services.incidents.notes(incident_id)):
        with st.form(f"new_note_{incident_id}"):
            category = st.selectbox("Note category", NOTE_CATEGORIES, key=f"new_note_category_{incident_id}")
            content = st.text_area("New note", max_chars=20_000, placeholder="Evidence, uncertainties, alternate causes, risk, next steps, or conclusion.")
            author = st.text_input("Analyst", value=services.settings.get("analyst_name", "Analyst"), max_chars=200)
            if st.form_submit_button("Save investigation note", type="primary"):
                try:
                    services.incidents.add_note(incident_id, category, content, author)
                    st.success("Investigation note saved.")
                    st.rerun()
                except ValueError as error:
                    st.error(str(error))
    notes = services.incidents.notes(incident_id)
    if not notes:
        st.info("No investigation notes have been recorded yet.")
        return
    choices = {note["note_id"]: f"{note['created_at']} · {note['category']}" for note in notes}
    with st.expander("Edit an existing note"):
        selected_id = st.selectbox("Select a note to edit", list(choices), format_func=lambda identifier: choices[identifier], key=f"edit_note_selection_{incident_id}")
        note = next(item for item in notes if item["note_id"] == selected_id)
        with st.form(f"edit_note_{incident_id}_{selected_id}"):
            author = st.text_input("Analyst", value=note["author"], max_chars=200, key=f"edit_note_author_{selected_id}")
            category = st.selectbox("Category", NOTE_CATEGORIES, index=NOTE_CATEGORIES.index(note["category"]) if note["category"] in NOTE_CATEGORIES else 0, key=f"edit_note_category_{selected_id}")
            content = st.text_area("Investigation note", value=note["note"], max_chars=20_000, key=f"edit_note_body_{selected_id}")
            if st.form_submit_button("Save edited note", type="primary"):
                try:
                    services.incidents.update_note(incident_id, selected_id, category, content, author)
                    st.success("Note updated and audit record saved.")
                    st.rerun()
                except ValueError as error:
                    st.error(str(error))
