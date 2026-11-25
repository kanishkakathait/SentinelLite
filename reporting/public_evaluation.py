from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from core.models import SecurityEvent
from ingestion.linux_auth_parser import parse_linux_auth_line
from ingestion.normalisation import normalise_record
from ingestion.public_datasets import sha256_bytes
from reporting.report_generator import markdown_text


@dataclass
class PublicDatasetEvaluation:
    manifest: dict[str, Any]
    ingestion: Any
    detection: Any
    linked_alerts: list[dict[str, Any]]
    normalised_event_ids: set[str]
    authentication_event_count: int
    raw_record_lines: int

    @property
    def rules(self) -> list[tuple[str, str, int]]:
        names = {rule_id: next(alert["detection_name"] for alert in self.linked_alerts if alert["rule_id"] == rule_id) for rule_id in {alert["rule_id"] for alert in self.linked_alerts}}
        return [(rule_id, names[rule_id], count) for rule_id, count in Counter(alert["rule_id"] for alert in self.linked_alerts).most_common()]

    def report_markdown(self) -> str:
        manifest = self.manifest
        lines = [
            "# SentinelLite — Public Log Validation",
            "",
            "## 1. Provenance",
            f"- **Dataset:** {markdown_text(manifest['label'])}",
            f"- **Description and provenance:** {markdown_text(manifest['provenance'])}",
            f"- **Upstream OpenSSH blob:** {markdown_text(manifest['upstream_git_blob_shas']['OpenSSH_2k.log'])}",
            f"- **Local SHA-256:** {markdown_text(manifest['downloaded_sha256'])}",
            f"- **Raw records modified to engineer detections:** {markdown_text(manifest['raw_records_modified'])}",
            f"- **Licence:** {markdown_text(manifest['license'])}",
            f"- **Required citation:** {markdown_text(manifest['citation'])}",
            "",
            "The original raw log and upstream licence/README text are retained locally. This is not a full LogHub repository download, a live log collector, or an organisation-owned corpus.",
            "",
            "## 2. Ingestion and Normalisation",
            markdown_text(manifest["timestamp_note"]),
            "",
            "| Record measure | Record-derived count |", "|---|---:|",
            f"| Source log records in this file | {self.raw_record_lines} |",
            f"| Records received by ingestion | {self.ingestion.received} |",
            f"| Accepted into event storage (new) | {self.ingestion.accepted} |",
            f"| Exact duplicate records skipped | {self.ingestion.duplicates} |",
            f"| Rejected malformed/unsupported records | {self.ingestion.rejected} |",
            f"| Unique normalised event IDs for this input | {len(self.normalised_event_ids)} |",
            f"| Parsed authentication records | {self.authentication_event_count} |",
            f"| Imported public dataset is simulated | {markdown_text(manifest.get('simulated', False))} |",
            "",
            "The adapter preserves valid general SSH/syslog messages as system events when they do not match the supported Failed/Accepted authentication forms, leaving absent IP/user fields null instead of inventing them.",
            "",
            "## 3. Evidence-linked Detection Outcomes",
            "",
            "| Finding type | Count |", "|---|---:|",
            f"| Active alerts associated with this input's evidence IDs | {len(self.linked_alerts)} |",
            f"| Detection findings in full-store reconciliation | {self.detection.findings} |",
            f"| Globally created alerts in that reconciliation | {self.detection.created} |",
            f"| Refreshed alert records in that reconciliation | {self.detection.refreshed} |",
            f"| Newly superseded alert records | {self.detection.superseded} |",
            "",
            "The first row selects only alerts linked to this input. All-store counters include other data already persisted in the application and must not be confused with this import's isolated effect. Replaying identical input results in duplicates and may reproduce/refresh existing alerts without new events.",
            "",
            "| Rule ID | Detection name | Associated active alerts |", "|---|---|---:|",
        ]
        if self.linked_alerts:
            lines.extend(f"| {markdown_text(rule_id)} | {markdown_text(name)} | {count} |" for rule_id, name, count in self.rules)
        else:
            lines.append("| — | No active alerts linked to the source evidence | 0 |")
        lines.extend([
            "",
            "## 4. Ground-Truth and Confidence Limitations",
            markdown_text(self.manifest["timestamp_note"]),
            "",
            "**Trusted ground truth is not provided for this import. Precision, recall, and false-positive rates are not calculated.** There is no numeric correctness claim solely because these public records produced alerts. Repeated source lines with identical timestamp/content are exact duplicate records for this application because no separate normalised event ID exists.",
            "",
            "## 5. Interpretation and Next Checks",
            "- Authentication failures or unusual clusters require investigation and do not independently establish account compromise, malicious source ownership, or successful access.",
            "- Consider public/lab context, routine administration, user mistakes, gateway effects, missing fields, and timezone uncertainty before drawing conclusions.",
            "- This bounded public log cannot demonstrate performance on an organisation's full telemetry, all attack variants, cloud workloads, or current endpoint telemetry.",
            "- Preserve incident uncertainty, verify raw timestamps and source fields, and follow authorised procedures before any response outside this application.",
            "",
            "### Rejected-record samples",
        ])
        if self.ingestion.errors:
            lines.extend(f"- Record {issue.record}: {markdown_text(issue.message)}" for issue in self.ingestion.errors)
        else:
            lines.append("- None reported for this import.")
        lines.extend(["", "---", "**SentinelLite** · Local educational validation · No external scanning, paid service, or automatic containment was performed."])
        return "\n".join(lines) + "\n"


def evaluate_public_bytes(services, manifest: dict[str, Any], content: bytes) -> PublicDatasetEvaluation:
    if sha256_bytes(content) != manifest["downloaded_sha256"]:
        raise ValueError("The supplied public log does not match its provenance checksum")
    if manifest.get("raw_records_modified") is not False:
        raise ValueError("Public dataset metadata must explicitly confirm unmodified source records")
    year = int(manifest["timestamp_year_reference"])
    if year < 1900 or year > 9999:
        raise ValueError("Reference year for sorting must be a valid datetime year")
    timezone = manifest["reference_timezone"]
    parsed_events: list[SecurityEvent] = []
    text = content.decode("utf-8")
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            record = parse_linux_auth_line(line, timezone, reference_year=year, allow_generic_ssh=True)
            event = normalise_record(record, "loghub_openssh", timezone, simulated=False)
        except ValueError:
            continue
        parsed_events.append(event)
    event_ids = {event.event_id for event in parsed_events}
    ingestion = services.ingestion.ingest_bytes(
        "OpenSSH_2k.log", content, default_timezone=timezone,
        simulated=False, reference_year=year, allow_generic_ssh=True,
    )
    detection = services.detection.run()
    linked = services.alerts.for_events(event_ids)
    authentication_events = sum(events.event_category == "authentication" for events in parsed_events)
    return PublicDatasetEvaluation(manifest, ingestion, detection, linked, event_ids, authentication_events, len(text.splitlines()))


def load_and_evaluate_public_log(services) -> PublicDatasetEvaluation:
    from ingestion.public_datasets import load_loghub_events
    manifest, content = load_loghub_events()
    return evaluate_public_bytes(services, manifest, content)
