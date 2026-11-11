import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)


@pytest.fixture(autouse=True)
def isolated_state(tmp_path, monkeypatch):
    """Every test gets its own state dir so users/history/offsets never leak."""
    monkeypatch.setenv("ALPHA_SENTINEL_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.delenv("ALPHA_SENTINEL_COLLECTOR_KEY", raising=False)
    return tmp_path / "state"
