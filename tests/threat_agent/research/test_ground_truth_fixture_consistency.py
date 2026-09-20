"""
tests/threat_agent/research/test_ground_truth_fixture_consistency.py
────────────────────────────────────────────────────────────────────
Ground-Truth Fixture Asset Consistency Enforcement Test.

Verifies that tests/threat_agent/e2e/fixtures/smart_door_lock/input.json
faithfully covers every asset required by tests/threat_agent/research/ground_truth_t1_t6.json
(aligned with Section 2.4 and 2.5 of the company specification).

Prevents regression where ground-truth threats reference assets that do not
exist in the evaluation fixture, rendering matching structurally impossible.
"""

from __future__ import annotations

import json
from pathlib import Path

from agents.threat_agent.schemas import ThreatAgentInput

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_GROUND_TRUTH_PATH = _REPO_ROOT / "tests" / "threat_agent" / "research" / "ground_truth_t1_t6.json"
_FIXTURE_PATH = (
    _REPO_ROOT
    / "tests"
    / "threat_agent"
    / "e2e"
    / "fixtures"
    / "smart_door_lock"
    / "input.json"
)

# Expected conceptual mappings per company document Section 2.4 / 2.5
_EXPECTED_ASSET_CONCEPTS: dict[str, list[str]] = {
    "AS-1": ["unlock", "command", "ble"],
    "AS-2": ["e-key", "credential", "key", "token"],
    "AS-3": ["firmware", "image", "bootloader"],
    "AS-4": ["audit", "log", "event"],
    "AS-5": ["pii", "user", "schedule", "privacy"],
    "AS-6": ["crypto", "key", "secure element"],
}


def test_ground_truth_fixture_asset_coverage() -> None:
    """Assert every asset_id referenced in ground truth exists in the fixture and matches conceptually."""
    assert _GROUND_TRUTH_PATH.exists(), f"Ground truth missing: {_GROUND_TRUTH_PATH}"
    assert _FIXTURE_PATH.exists(), f"Fixture missing: {_FIXTURE_PATH}"

    gt_data = json.loads(_GROUND_TRUTH_PATH.read_text(encoding="utf-8"))
    fixture_agent_input = ThreatAgentInput.model_validate_json(
        _FIXTURE_PATH.read_text(encoding="utf-8")
    )

    fixture_assets_by_id = {a.asset_id: a for a in fixture_agent_input.assets}

    # 1. Verify all 6 company-spec assets exist in the fixture
    for expected_id in ["AS-1", "AS-2", "AS-3", "AS-4", "AS-5", "AS-6"]:
        assert expected_id in fixture_assets_by_id, (
            f"Required asset {expected_id} is missing from smart_door_lock/input.json! "
            f"Existing fixture assets: {list(fixture_assets_by_id.keys())}"
        )

    # 2. Verify every asset referenced in ground truth threats exists in the fixture
    gt_asset_ids = {t["asset_id"] for t in gt_data}
    missing_assets = gt_asset_ids - set(fixture_assets_by_id.keys())
    assert not missing_assets, (
        f"Ground-truth threats reference assets not present in the fixture: {missing_assets}. "
        f"Fixture assets: {list(fixture_assets_by_id.keys())}"
    )

    # 3. Assert conceptual alignment to prevent coincidental ID reuse
    for asset_id, keywords in _EXPECTED_ASSET_CONCEPTS.items():
        asset = fixture_assets_by_id[asset_id]
        combined_text = f"{asset.name} {asset.asset_type} {asset.damage_scenario}".lower()
        has_concept = any(kw in combined_text for kw in keywords)
        assert has_concept, (
            f"Asset {asset_id} in fixture ('{asset.name}') does not conceptually match "
            f"expected concept keywords {keywords}. Combined text: {combined_text}"
        )

    # 4. Verify the fixture contains at least 6 assets
    assert len(fixture_agent_input.assets) >= 6, (
        f"Fixture only defines {len(fixture_agent_input.assets)} assets; expected at least 6."
    )


def test_ground_truth_each_threat_has_valid_target_asset() -> None:
    """Verify each individual threat T1-T6 maps to an active fixture asset."""
    gt_data = json.loads(_GROUND_TRUTH_PATH.read_text(encoding="utf-8"))
    fixture_agent_input = ThreatAgentInput.model_validate_json(
        _FIXTURE_PATH.read_text(encoding="utf-8")
    )
    fixture_ids = {a.asset_id for a in fixture_agent_input.assets}

    for threat in gt_data:
        tid = threat["threat_id"]
        target_asset = threat["asset_id"]
        assert target_asset in fixture_ids, (
            f"Ground-truth threat {tid} ('{threat['title']}') targets asset '{target_asset}', "
            f"which is missing from the Smart Door Lock fixture."
        )
