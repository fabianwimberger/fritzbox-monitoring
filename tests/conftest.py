"""Shared fixtures for the exporter tests."""

import os
import tempfile
from pathlib import Path

import pytest

# Keep the collector from reading or writing a real state file at import time.
_STATE_DIR = tempfile.mkdtemp(prefix="fritzbox-exporter-test-")
os.environ["STATE_FILE"] = str(Path(_STATE_DIR) / "state.json")


@pytest.fixture(scope="session")
def collector():
    """Return a single collector.

    The metrics register themselves on the default Prometheus registry, so a
    second instance would raise on duplicate timeseries. Tests use distinct
    channel IDs to keep their metric state independent.
    """
    from exporter import FritzboxCollector

    return FritzboxCollector()
