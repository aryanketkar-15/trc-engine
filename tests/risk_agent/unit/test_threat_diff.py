"""The proposed diff a person reviews before a re-generated threat list replaces an approved one."""

from __future__ import annotations

from typing import Any

from scrp.integrity import diff_threats


def _t(tid: str, asset: str, ref: str, attack: str = "attack") -> dict[str, Any]:
    return {
        "tid": tid,
        "asset_id": asset,
        "kb_reference": ref,
        "attack_vector": attack,
        "stride_category": "Tampering",
        "evidence_chain": {"citation": ref},
        "confidence_score": 0.7,
    }


def test_added_removed_changed_and_unchanged() -> None:
    current = [
        _t("OLD-1", "AS-1", "CAPEC-1"),
        _t("OLD-2", "AS-1", "CAPEC-2"),
        _t("OLD-3", "AS-2", "CAPEC-3"),
    ]
    proposed = [
        _t("NEW-1", "AS-1", "CAPEC-1"),
        _t("NEW-2", "AS-1", "CAPEC-2", attack="a different attack"),
        _t("NEW-4", "AS-3", "CAPEC-4"),
    ]
    out = diff_threats(current, proposed)
    assert [t["tid"] for t in out["added"]] == ["NEW-4"]
    assert [t["tid"] for t in out["removed"]] == ["OLD-3"]
    assert out["unchanged"] == 1
    change = out["changed"][0]
    assert change["tid"] == "NEW-2" and change["replaces"] == "OLD-2"
    assert change["diff"] == [
        {"field": "attack_vector", "current": "attack", "proposed": "a different attack"}
    ]


def test_same_catalogue_item_on_another_asset_is_a_different_threat() -> None:
    out = diff_threats([_t("A", "AS-1", "CAPEC-1")], [_t("B", "AS-2", "CAPEC-1")])
    assert len(out["added"]) == 1 and len(out["removed"]) == 1 and not out["changed"]


def test_empty_inputs() -> None:
    assert diff_threats([], []) == {"added": [], "removed": [], "changed": [], "unchanged": 0}
