from __future__ import annotations

import pytest

from core.services import AppServices
from ingestion.normalisation import normalise_record


@pytest.fixture
def services(tmp_path):
    return AppServices(tmp_path / "test.db")


@pytest.fixture
def event_factory():
    def create(timestamp="2026-11-25T10:00:00+11:00", source_ip="203.0.113.10", username="alice", result="failure", hostname="test-host", source="test-auth"):
        return normalise_record({
            "timestamp": timestamp, "event_source": source, "hostname": hostname,
            "source_ip": source_ip, "username": username, "event_category": "authentication",
            "event_action": "login", "authentication_result": result,
            "raw_message": f"test {result} for {username} from {source_ip or 'not supplied'} at {timestamp}",
        }, "test", "Australia/Melbourne")
    return create
