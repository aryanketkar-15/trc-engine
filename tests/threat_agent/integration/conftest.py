"""tests/threat_agent/integration/conftest.py
==============================================================================
TRC Engine -- Phase 1  |  Integration Test Fixtures (Day-2)
------------------------------------------------------------------------------
Shared pytest fixtures for the threat_agent integration test suite.

Key fixture: ``mock_get_kb_entry``
    Patches agents.threat_agent.retrieval.get_kb_entry() with a
    deterministic stub so /approve and /scenarios integration tests can
    exercise the citation-validation path without a live FAISS index
    (the real implementation is Week-2 work on feature/threat-agent-retrieval).

    The fixture provides two canned KBCandidate responses keyed by
    pattern_id — one per domain fixture (Smart Door Lock + Infusion Pump)
    as required by §2.11 / §6 of the build plan.

    Any pattern_id not in the canned map raises KBEntryNotFoundError,
    which lets tests exercise the "citation not found" failure path.

Usage in a test file:
    def test_approve_validates_citation(
        client: TestClient,
        mock_get_kb_entry: MagicMock,
    ) -> None:
        ...
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Environment setup — MUST be before any import that triggers get_settings().
# pydantic-settings reads env vars at Settings() construction time.
# These placeholder values satisfy required field validation in tests.
# Real values are NOT needed — tests that touch FAISS are skip-marked.
# ---------------------------------------------------------------------------
import os

os.environ.setdefault("OPENAI_API_KEY", "sk-test-placeholder-for-integration-tests")
os.environ.setdefault("FAISS_INDEX_PATH", "kb/data/threat_agent.faiss")
os.environ.setdefault("KB_DATA_DIR", "kb/data")

# ---------------------------------------------------------------------------

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from agents.threat_agent.exceptions import KBEntryNotFoundError
from agents.threat_agent.schemas import KBCandidate, KBSource, STRIDECategory

# ── Canned KB entries — one per domain fixture ────────────────────────────────
# Keys are canonical pattern_ids; values are KBCandidate kwargs dicts.
# Extend this map as new test scenarios are added — do not hardcode these
# inside individual tests.

_CANNED_KB_ENTRIES: dict[str, dict[str, Any]] = {
    # ── Fixture 1: Smart Door Lock (BLE / IoT domain) ─────────────────────────
    "CAPEC-94": {
        "pattern_id": "CAPEC-94",
        "source": KBSource.CAPEC,
        "title": "Adversary in the Middle (AiTM)",
        "description": (
            "An adversary positions themselves between two communicating "
            "parties to intercept and potentially alter communications."
        ),
        "retrieval_score": 0.87,
        "asset_id": "ASSET-BLE-CONTROLLER-01",
        "stride_hint": STRIDECategory.TAMPERING,
        "mitre_tactics": ["TA0006"],
    },
    "ATT&CK T1190": {
        "pattern_id": "ATT&CK T1190",
        "source": KBSource.ATT_AND_CK,
        "title": "Exploit Public-Facing Application",
        "description": (
            "Adversaries may attempt to exploit a weakness in an Internet-facing "
            "host or system to initially access a network."
        ),
        "retrieval_score": 0.82,
        "asset_id": "ASSET-OTA-ENDPOINT-01",
        "stride_hint": STRIDECategory.TAMPERING,
        "mitre_tactics": ["TA0001"],
    },
    "CWE-306": {
        "pattern_id": "CWE-306",
        "source": KBSource.CWE,
        "title": "Missing Authentication for Critical Function",
        "description": (
            "The software does not perform any authentication for functionality "
            "that requires a provable user identity or consumes a significant "
            "amount of resources."
        ),
        "retrieval_score": 0.79,
        "asset_id": "ASSET-BLE-CONTROLLER-01",
        "stride_hint": STRIDECategory.ELEVATION_OF_PRIVILEGE,
        "mitre_tactics": [],
    },
    # ── Fixture 2: Infusion Pump (medical device / hospital network domain) ────
    "CAPEC-60": {
        "pattern_id": "CAPEC-60",
        "source": KBSource.CAPEC,
        "title": "Reusing Session IDs (aka Session Replay)",
        "description": (
            "An attacker exploits a weakness in authentication to reuse a "
            "session ID and gain unauthorized access to a system."
        ),
        "retrieval_score": 0.84,
        "asset_id": "ASSET-INFUSION-PUMP-CONTROLLER-01",
        "stride_hint": STRIDECategory.SPOOFING,
        "mitre_tactics": ["TA0006"],
    },
    "CWE-912": {
        "pattern_id": "CWE-912",
        "source": KBSource.CWE,
        "title": "Hidden Functionality",
        "description": (
            "The software contains functionality that is not documented, "
            "not part of the specification, and not accessible through "
            "normal operation of the software."
        ),
        "retrieval_score": 0.71,
        "asset_id": "ASSET-INFUSION-PUMP-FIRMWARE-01",
        "stride_hint": STRIDECategory.INFORMATION_DISCLOSURE,
        "mitre_tactics": [],
    },
}


def _make_kb_candidate(data: dict[str, Any]) -> KBCandidate:
    """Construct a frozen KBCandidate from a canned-entry dict.

    Args:
        data: Dict matching KBCandidate field names.

    Returns:
        Validated, frozen KBCandidate instance.
    """
    return KBCandidate(**data)


def _stub_get_kb_entry(pattern_id: str, source: KBSource | str) -> KBCandidate:
    """Stub implementation of retrieval.get_kb_entry() for integration tests.

    Returns a canned KBCandidate for known pattern_ids.
    Raises KBEntryNotFoundError for unknown ids — matching production behaviour
    so tests can assert on the "citation not found" failure path.

    Args:
        pattern_id: Canonical KB pattern identifier.
        source:     KB source enum value or string (accepted both ways to
                    mirror the real function signature flexibility).

    Returns:
        KBCandidate for the given pattern_id.

    Raises:
        KBEntryNotFoundError: If pattern_id is not in the canned map.
    """
    source_str = source.value if isinstance(source, KBSource) else str(source)
    if pattern_id in _CANNED_KB_ENTRIES:
        return _make_kb_candidate(_CANNED_KB_ENTRIES[pattern_id])
    raise KBEntryNotFoundError(pattern_id=pattern_id, source=source_str)


# ── Pytest fixtures ────────────────────────────────────────────────────────────


@pytest.fixture()
def mock_get_kb_entry() -> MagicMock:  # type: ignore[return]
    """Patch retrieval.get_kb_entry() with a deterministic stub.

    Scope: function (default) — each test gets a fresh MagicMock so
    call-count assertions are isolated between tests.

    Yields:
        MagicMock wrapping _stub_get_kb_entry, with .side_effect set.
        Use mock_get_kb_entry.call_args_list to inspect calls in tests.

    Example::

        def test_approve_with_valid_citation(
            client: TestClient,
            mock_get_kb_entry: MagicMock,
        ) -> None:
            # Arrange — run_id with a known pattern_id in the canned map
            response = client.post("/api/v1/threat-agent/approve/RUN-001")
            assert response.status_code == 200
            mock_get_kb_entry.assert_called_once_with("CAPEC-94", KBSource.CAPEC)

        def test_approve_with_unknown_citation(
            client: TestClient,
            mock_get_kb_entry: MagicMock,
        ) -> None:
            # get_kb_entry raises KBEntryNotFoundError for unknown pattern
            response = client.post("/api/v1/threat-agent/approve/RUN-BAD")
            assert response.status_code == 422
    """
    with patch(
        "agents.threat_agent.retrieval.get_kb_entry",
        side_effect=_stub_get_kb_entry,
    ) as mock:
        yield mock


@pytest.fixture()
def all_canned_pattern_ids() -> list[str]:
    """Return the list of pattern_ids available in the canned KB map.

    Useful for parametrised tests that should succeed for every known entry.

    Returns:
        List of pattern_id strings from _CANNED_KB_ENTRIES.
    """
    return list(_CANNED_KB_ENTRIES.keys())


@pytest.fixture()
def smart_door_lock_pattern_ids() -> list[str]:
    """Return pattern_ids for Fixture 1 (Smart Door Lock) only."""
    return ["CAPEC-94", "ATT&CK T1190", "CWE-306"]


@pytest.fixture()
def infusion_pump_pattern_ids() -> list[str]:
    """Return pattern_ids for Fixture 2 (Infusion Pump) only."""
    return ["CAPEC-60", "CWE-912"]
