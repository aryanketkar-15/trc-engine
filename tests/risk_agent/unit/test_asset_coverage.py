"""The TARA report says, for every asset of the use case, whether it has a threat and why not."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from agents.risk_agent import report
from scrp.state_manager import StateManager
from tests.risk_agent.unit.test_risk_engine import _threat


def _assets(*ids: str) -> list[SimpleNamespace]:
    return [SimpleNamespace(asset_id=i, name=f"Asset {i}") for i in ids]


def _state(tmp_path: Path) -> StateManager:
    sm = StateManager(tmp_path / "s.json")
    kept = _threat("AS-1", "THR-A")
    sm.commit_approved_run(kept.run_id, [kept])
    # a scenario for AS-2 that the reviewer rejected: it stays in the revision history
    gone = _threat("AS-2", "THR-B")
    sm.log_rejection(gone.run_id, "citation does not fit", [gone])
    return sm


def test_asset_with_threat_is_covered(tmp_path: Path) -> None:
    data = report.build_report(_state(tmp_path), use_case_assets=_assets("AS-1", "AS-2", "AS-3"))
    by_id = {c["asset_id"]: c for c in data["coverage"]}
    assert by_id["AS-1"]["approved_threats"] == 1
    assert by_id["AS-1"]["note"] == ""


def test_asset_whose_cards_were_all_rejected_says_so(tmp_path: Path) -> None:
    data = report.build_report(_state(tmp_path), use_case_assets=_assets("AS-1", "AS-2", "AS-3"))
    row = next(c for c in data["coverage"] if c["asset_id"] == "AS-2")
    assert row["approved_threats"] == 0 and row["rejected_or_discarded"] == 1
    assert "rejected or discarded" in row["note"] and "no threat applies" in row["note"]


def test_asset_never_analysed_is_told_apart_from_a_rejected_one(tmp_path: Path) -> None:
    data = report.build_report(_state(tmp_path), use_case_assets=_assets("AS-1", "AS-2", "AS-3"))
    row = next(c for c in data["coverage"] if c["asset_id"] == "AS-3")
    assert row["approved_threats"] == 0 and row["rejected_or_discarded"] == 0
    assert "none was rejected" in row["note"]


def test_summary_counts_assets_without_a_threat(tmp_path: Path) -> None:
    data = report.build_report(_state(tmp_path), use_case_assets=_assets("AS-1", "AS-2", "AS-3"))
    assert data["summary"]["assets_without_threat"] == 2


def test_no_asset_list_means_no_coverage_section(tmp_path: Path) -> None:
    data = report.build_report(_state(tmp_path))
    assert data["coverage"] == [] and data["summary"]["assets_without_threat"] == 0
    assert "## Asset coverage" not in report.to_markdown(data)


def test_markdown_lists_every_asset_with_its_note(tmp_path: Path) -> None:
    data = report.build_report(_state(tmp_path), use_case_assets=_assets("AS-1", "AS-2", "AS-3"))
    text = report.to_markdown(data)
    assert "## Asset coverage" in text
    assert "| AS-1 | Asset AS-1 | 1 | - |" in text
    assert "| AS-2 | Asset AS-2 | 0 |" in text and "| AS-3 | Asset AS-3 | 0 |" in text
