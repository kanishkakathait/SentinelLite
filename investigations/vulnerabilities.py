from __future__ import annotations

import csv
import io
import re
import sqlite3
import uuid
from datetime import date
from typing import Any

from core.config import REMEDIATION_STATUSES, SEVERITIES
from core.database import Database
from core.time_utils import to_storage, utc_now
from investigations.risk import calculate_priority


class VulnerabilityService:
    def __init__(self, database: Database):
        self.database = database

    def create(self, record: dict[str, Any]) -> str:
        vulnerability_id = str(record.get("vulnerability_id") or f"VULN-{uuid.uuid4().hex[:12].upper()}").strip()
        required = ("title", "description", "affected_asset", "remediation_recommendation", "remediation_owner")
        if any(not str(record.get(field) or "").strip() for field in required):
            raise ValueError("Title, description, asset, remediation recommendation, and owner are required")
        if len(vulnerability_id) > 100 or any(len(str(record.get(field, ""))) > 20_000 for field in record):
            raise ValueError("Vulnerability fields exceed their size limits")
        severity = str(record["severity"])
        if severity not in SEVERITIES:
            raise ValueError("Invalid vulnerability severity")
        cvss = record.get("cvss_score")
        cvss = float(cvss) if cvss not in (None, "") else None
        if cvss is not None and not 0 <= cvss <= 10:
            raise ValueError("CVSS score must be between 0.0 and 10.0")
        cve = str(record.get("cve_id") or "").strip().upper() or None
        if cve and not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            raise ValueError("CVE identifier must use the form CVE-YYYY-NNNN")
        discovery_date = str(record.get("discovery_date") or date.today().isoformat())[:10]
        date.fromisoformat(discovery_date)
        due_date = record.get("due_date") or None
        if due_date:
            due_date = str(due_date)[:10]
            date.fromisoformat(due_date)
        status = str(record.get("remediation_status") or "Open")
        if status not in REMEDIATION_STATUSES:
            raise ValueError("Invalid remediation status")
        priority = calculate_priority(
            severity, int(record["asset_criticality"]), str(record["exposure"]), str(record["evidence"])
        )
        verification_date = record.get("verification_date") or None
        if verification_date:
            verification_date = str(verification_date)[:10]
            date.fromisoformat(verification_date)
        if status == "Verified" and not verification_date:
            raise ValueError("Verified vulnerabilities require a verification date")
        now = to_storage(utc_now())
        self.database.execute(
            """
            INSERT INTO vulnerabilities (
                vulnerability_id, title, description, affected_asset, severity, cve_id, cvss_score,
                discovery_date, asset_criticality, exposure, evidence, priority_score, priority_level,
                remediation_recommendation, remediation_owner, remediation_status, due_date,
                remediation_evidence, verification_date, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                vulnerability_id, str(record["title"]).strip(), str(record["description"]).strip(),
                str(record["affected_asset"]).strip(), severity, cve, cvss, discovery_date,
                int(record["asset_criticality"]), str(record["exposure"]), str(record["evidence"]),
                priority["score"], priority["level"], str(record["remediation_recommendation"]).strip(),
                str(record["remediation_owner"]).strip(), status, due_date,
                str(record.get("remediation_evidence") or "").strip(), verification_date, now, now,
            ),
        )
        return vulnerability_id

    def list(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.database.fetch_all("SELECT * FROM vulnerabilities ORDER BY priority_score DESC, vulnerability_id")]

    def get(self, vulnerability_id: str) -> dict[str, Any]:
        row = self.database.fetch_one("SELECT * FROM vulnerabilities WHERE vulnerability_id = ?", (vulnerability_id,))
        if not row:
            raise ValueError("Vulnerability not found")
        return dict(row)

    def update(self, vulnerability_id: str, status: str, owner: str, due_date: str | None, evidence: str, verification_date: str | None) -> None:
        if status not in REMEDIATION_STATUSES:
            raise ValueError("Invalid remediation status")
        if not owner.strip():
            raise ValueError("A remediation owner is required")
        if due_date:
            date.fromisoformat(due_date)
        if verification_date:
            date.fromisoformat(verification_date)
        if status == "Verified" and not verification_date:
            raise ValueError("Verified vulnerabilities require a verification date")
        with self.database.connection() as connection:
            row = connection.execute("SELECT remediation_status FROM vulnerabilities WHERE vulnerability_id = ?", (vulnerability_id,)).fetchone()
            if not row:
                raise ValueError("Vulnerability not found")
            now = to_storage(utc_now())
            connection.execute(
                """
                UPDATE vulnerabilities SET remediation_status = ?, remediation_owner = ?, due_date = ?,
                    remediation_evidence = ?, verification_date = ?, updated_at = ? WHERE vulnerability_id = ?
                """, (status, owner.strip(), due_date or None, evidence.strip(), verification_date or None, now, vulnerability_id),
            )
            connection.execute(
                "INSERT INTO remediation_actions (vulnerability_id, action, owner, status, due_date, evidence, created_at, updated_at) VALUES (?, 'Remediation review', ?, ?, ?, ?, ?, ?)",
                (vulnerability_id, owner.strip(), status, due_date or None, evidence.strip(), now, now),
            )
            if row["remediation_status"] != status:
                connection.execute(
                    "INSERT INTO status_history (entity_type, entity_id, previous_status, new_status, changed_at, note) VALUES ('vulnerability', ?, ?, ?, ?, ?)",
                    (vulnerability_id, row["remediation_status"], status, now, "Remediation status updated"),
                )

    def import_csv(self, content: bytes) -> dict[str, Any]:
        if len(content) > 10 * 1024 * 1024:
            raise ValueError("File exceeds the 10 MiB upload limit")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("Risk-register imports must be valid UTF-8 CSV") from error
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise ValueError("CSV input has no header")
        created, duplicates, errors = 0, 0, []
        for line, row in enumerate(reader, start=2):
            try:
                identifier = str(row.get("vulnerability_id") or "").strip()
                row["vulnerability_id"] = identifier or None
                if identifier and self.database.fetch_one("SELECT 1 FROM vulnerabilities WHERE vulnerability_id = ?", (identifier,)):
                    duplicates += 1
                    continue
                self.create(row)
                created += 1
            except sqlite3.IntegrityError as error:
                if "UNIQUE constraint failed" in str(error):
                    duplicates += 1
                elif len(errors) < 100:
                    errors.append({"record": line, "message": str(error)})
            except (ValueError, TypeError, KeyError) as error:
                if len(errors) < 100:
                    errors.append({"record": line, "message": str(error)})
        return {"created": created, "duplicates": duplicates, "errors": errors}

    def seed_demonstration_records(self) -> int:
        inserted = 0
        examples = [
            ("DEMO-VULN-001", "Outdated authentication package", "demo-idp-01", "high", 80, 5, "Internet-facing", "Confirmed", "Upgrade the authentication package and review active sessions.", "Identity platform owner", "In Progress", 7),
            ("DEMO-VULN-002", "Missing security headers", "demo-web-01", "medium", 50, 3, "Internet-facing", "Observed", "Apply the approved security-header baseline and retest.", "Web platform owner", "Open", 14),
            ("DEMO-VULN-003", "Unsupported database extension", "demo-db-01", "high", 75, 4, "Internal", "Confirmed", "Remove or upgrade the extension after application compatibility testing.", "Database owner", "Remediated", -1),
            ("DEMO-VULN-004", "Verbose service error responses", "demo-api-01", "low", 35, 2, "Internal", "Observed", "Suppress implementation details in error responses.", "API service owner", "Verified", -2),
            ("DEMO-VULN-005", "Unpatched remote access service", "demo-vpn-01", "critical", 95, 5, "Internet-facing", "Confirmed", "Apply the vendor patch and review remote access logs.", "Network security owner", "Open", -1),
        ]
        for identifier, title, asset, severity, _, criticality, exposure, evidence, recommendation, owner, status, due_offset in examples:
            if any(item["vulnerability_id"] == identifier for item in self.list()):
                continue
            record = {
                "vulnerability_id": identifier, "title": f"[DEMO] {title}",
                "description": "Synthetic demonstration record for portfolio evaluation; not the result of a vulnerability scan.",
                "affected_asset": asset, "severity": severity, "cve_id": None, "cvss_score": None,
                "discovery_date": date.today().isoformat(), "asset_criticality": criticality,
                "exposure": exposure, "evidence": evidence, "remediation_recommendation": recommendation,
                "remediation_owner": owner, "remediation_status": status,
                "due_date": (date.today().toordinal() + due_offset),
            }
            record["due_date"] = date.fromordinal(record["due_date"]).isoformat()
            if status == "Verified":
                record["verification_date"] = date.today().isoformat()
            self.create(record)
            inserted += 1
        return inserted

    def metrics(self) -> dict[str, Any]:
        records = self.list()
        today = date.today().isoformat()
        return {
            "open": sum(item["remediation_status"] in {"Open", "In Progress"} for item in records),
            "high_priority": sum(item["remediation_status"] in {"Open", "In Progress"} and item["priority_level"] in {"P1", "P2"} for item in records),
            "overdue": sum(bool(item["due_date"] and item["due_date"] < today and item["remediation_status"] not in {"Remediated", "Verified"}) for item in records),
            "progress": {status: sum(item["remediation_status"] == status for item in records) for status in REMEDIATION_STATUSES},
        }
