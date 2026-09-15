import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aire_detection.models import EventType, NormalizedEvent


@pytest.fixture
def base_time():
    return datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def make_event(event_type: EventType, timestamp, **kwargs) -> NormalizedEvent:
    defaults = dict(source="test-source", sensor="test-sensor")
    defaults.update(kwargs)
    return NormalizedEvent(event_type=event_type, timestamp=timestamp, **defaults)


@pytest.fixture
def event_factory(base_time):
    def _factory(event_type: EventType, offset_seconds: float = 0, **kwargs):
        ts = base_time + timedelta(seconds=offset_seconds)
        return make_event(event_type, ts, **kwargs)
    return _factory
