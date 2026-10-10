"""Shared test fixtures: keep every test away from the real SCRS_state.json."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def scrs_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the router's shared-state file at a per-test temp path."""
    path = tmp_path / "SCRS_state.json"
    monkeypatch.setattr("agents.threat_agent.router.get_scrs_path", lambda: path)
    return path
