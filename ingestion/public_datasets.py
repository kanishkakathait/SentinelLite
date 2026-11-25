from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from core.config import PROJECT_ROOT
from core.time_utils import to_storage, utc_now

DATASET_NAME = "loghub_open_ssh_2k"
DATASET_LABEL = "LogHub OpenSSH 2k — public lab authentication log"
DATASET_DIRECTORY = PROJECT_ROOT / "data" / "public" / "loghub_openssh"
DATASET_DOWNLOADS = {
    "OpenSSH_2k.log": "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log",
    "README.md": "https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/README.md",
    "LICENSE_LOGHUB.txt": "https://raw.githubusercontent.com/logpai/loghub/master/LICENSE",
}
EXPECTED_BYTES = {"OpenSSH_2k.log": 225216}
UPSTREAM_BLOBS = {
    "OpenSSH_2k.log": "587f66b1ebf40fd59f385addc69a8b0671f34b9c",
    "README.md": "8392c409e528c55f1e0051d2e1d5f5118036333e",
    "LICENSE_LOGHUB.txt": "f46d7c88d37a5a0d3877ab12147dae1d6ba0bbac",
}
MAX_DOWNLOAD_BYTES = 3 * 1024 * 1024
DATASET_REFERENCE_YEAR = 2015
DATASET_CITATION = "Jieming Zhu, Shilin He, Pinjia He, Jinyang Liu, Michael R. Lyu. Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics. IEEE International Symposium on Software Reliability Engineering (ISSRE), 2023."


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def download_bytes(url: str, maximum_bytes: int = MAX_DOWNLOAD_BYTES) -> bytes:
    request = Request(url, headers={"User-Agent": "SentinelLite-educational-dataset-validator"})
    try:
        with urlopen(request, timeout=25) as response:
            content = response.read(maximum_bytes + 1)
    except URLError as error:
        raise ValueError(f"Unable to retrieve the public LogHub resource: {error.reason}") from error
    if len(content) > maximum_bytes:
        raise ValueError("Public dataset download exceeded the configured 3 MiB limit")
    return content


def public_dataset_manifest() -> dict[str, Any]:
    return {
        "dataset": DATASET_NAME, "label": DATASET_LABEL,
        "provenance": "LogPAI/LogHub OpenSSH laboratory logs collected for more than 28 days. Full upstream 2,000-line sample, not a subset or fabricated relabelling.",
        "source_urls": DATASET_DOWNLOADS, "upstream_git_blob_shas": UPSTREAM_BLOBS,
        "license": "LogHub: datasets freely available for research or academic work, subject to attribution. Refer to the included LICENSE_LOGHUB.txt.",
        "citation": DATASET_CITATION,
        "raw_records_modified": False, "selection": "Complete OpenSSH_2k.log, including exact original line order and contents; legacy syslog records contain no year or timezone offset.",
        "timestamp_year_reference": DATASET_REFERENCE_YEAR,
        "timestamp_year_is_source_fact": False,
        "reference_timezone": "UTC",
        "timezone_is_source_fact": False,
        "simulated": False,
        "timestamp_note": "Year 2015 and UTC are explicit normalisation conventions for reproducible ordering, not verified collection-year or server-offset facts. Raw timestamps remain available for provenance.",
        "ground_truth": "No trusted incident/scenario labels supplied. Do not report precision, recall, or false-positive rate for this import.",
        "retrieved_at_utc": to_storage(utc_now()),
    }


def ensure_loghub_dataset(directory: Path = DATASET_DIRECTORY) -> dict[str, Any]:
    directory = Path(directory)
    metadata_path = directory / "manifest.json"
    if metadata_path.exists():
        manifest = json.loads(metadata_path.read_text(encoding="utf-8"))
        manifest["simulated"] = False
        for filename, file_sha in manifest["files"].items():
            path = directory / filename
            if not path.is_file() or sha256_bytes(path.read_bytes()) != file_sha:
                raise ValueError(f"Existing public dataset file failed checksum validation: {filename}")
        return manifest
    if directory.exists() and any(directory.iterdir()):
        raise ValueError("Public dataset directory is not empty. Review its contents rather than overwriting it.")
    directory.mkdir(parents=True, exist_ok=True)
    downloads = {filename: download_bytes(url) for filename, url in DATASET_DOWNLOADS.items()}
    license_text = downloads["LICENSE_LOGHUB.txt"].decode("utf-8")
    if "freely available for research or academic work" not in license_text:
        raise ValueError("Unexpected upstream licence text; no dataset will be imported without verified attribution terms")
    if len(downloads["OpenSSH_2k.log"]) != EXPECTED_BYTES["OpenSSH_2k.log"]:
        raise ValueError("Unexpected OpenSSH sample size. Review the upstream blob rather than importing an unverified replacement.")
    manifest = public_dataset_manifest()
    manifest["files"] = {filename: sha256_bytes(content) for filename, content in downloads.items()}
    manifest["raw_record_lines"] = len(downloads["OpenSSH_2k.log"].splitlines())
    manifest["downloaded_sha256"] = manifest["files"]["OpenSSH_2k.log"]
    for filename, content in downloads.items():
        (directory / filename).write_bytes(content)
    metadata_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    return manifest


def load_loghub_events() -> tuple[dict[str, Any], bytes]:
    manifest = ensure_loghub_dataset()
    return manifest, (DATASET_DIRECTORY / "OpenSSH_2k.log").read_bytes()
