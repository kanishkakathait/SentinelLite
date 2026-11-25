from __future__ import annotations

import csv
import io
from typing import Iterator


def iter_csv_records(text: str) -> Iterator[tuple[int, dict[str, str | None]]]:
    reader = csv.DictReader(io.StringIO(text, newline=""))
    if not reader.fieldnames:
        return
    if any(not name or not name.strip() for name in reader.fieldnames):
        raise ValueError("CSV headers must be non-empty")
    for record_number, row in enumerate(reader, start=2):
        yield record_number, {str(key): value for key, value in row.items() if key is not None}
