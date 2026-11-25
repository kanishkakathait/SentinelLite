from __future__ import annotations

import json
from typing import Iterator


def _constant(value: str) -> None:
    raise ValueError(f"Invalid JSON constant: {value}")


def iter_json_records(text: str, suffix: str) -> Iterator[tuple[int, object]]:
    stripped = text.strip()
    if not stripped:
        return
    if suffix != ".jsonl":
        try:
            document = json.loads(stripped, parse_constant=_constant)
        except json.JSONDecodeError:
            document = None
        else:
            records = document.get("events") if isinstance(document, dict) and "events" in document else document
            if isinstance(records, dict):
                records = [records]
            if not isinstance(records, list):
                raise ValueError("JSON input must be an object, an array, or contain an events array")
            for record_number, record in enumerate(records, start=1):
                yield record_number, record
            return
    for record_number, line in enumerate(text.splitlines(), start=1):
        if line.strip():
            try:
                record = json.loads(line, parse_constant=_constant)
            except ValueError as error:
                yield record_number, error
                continue
            yield record_number, record
