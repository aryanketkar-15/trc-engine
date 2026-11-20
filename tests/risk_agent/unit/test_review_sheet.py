"""The expert review sheet: export, fill like a reviewer, count."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

openpyxl = pytest.importorskip("openpyxl")

from scrp.state_manager import StateManager  # noqa: E402
from tests.risk_agent.unit.test_risk_engine import _threat  # noqa: E402

_PATH = Path(__file__).resolve().parents[3] / "scripts" / "review_sheet.py"
_spec = importlib.util.spec_from_file_location("review_sheet", _PATH)
sheet = importlib.util.module_from_spec(_spec)  # type: ignore[arg-type]
sys.modules["review_sheet"] = sheet
_spec.loader.exec_module(sheet)  # type: ignore[union-attr]


@pytest.fixture
def state_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(sheet, "pattern_texts", lambda ids: {i: ("Title " + i, "Text " + i) for i in ids})
    sm = StateManager(tmp_path / "s.json")
    threats = [
        _threat("AS-1", tid).model_copy(update={"use_case_id": "UC-01"}) for tid in ("THR-A", "THR-B")
    ]
    sm.commit_approved_run(threats[0].run_id, threats)
    return tmp_path / "s.json"


def _assets() -> list[SimpleNamespace]:
    return [SimpleNamespace(asset_id="AS-1", name="Unlock"), SimpleNamespace(asset_id="AS-2", name="Keys")]


def _make(state_file: Path, tmp_path: Path) -> Path:
    return sheet.export(state_file, "UC-01", tmp_path / "review.xlsx", None, _assets())


def test_export_has_one_row_per_threat_and_per_asset(state_file: Path, tmp_path: Path) -> None:
    wb = openpyxl.load_workbook(_make(state_file, tmp_path))
    assert wb.sheetnames == ["Instructions", "Threats", "Assets", "Reviewer"]
    assert wb["Threats"].max_row == 3  # header + 2 threats
    assert [c.value for c in wb["Threats"][2][:2]] == ["THR-A", "AS-1"]
    assert wb["Assets"].max_row == 3
    assert wb["Threats"]["F2"].value == "Title CAPEC-94"
    assert wb["Threats"].data_validations.dataValidation  # drop-down lists are there


def test_empty_sheet_counts_as_no_review(state_file: Path, tmp_path: Path) -> None:
    result = sheet.summarise(_make(state_file, tmp_path))
    assert result["threats"] == 2 and result["threats_answered"] == 0
    assert result["counted_as_review"] is False
    assert result["pattern_fits"]["answered"] == 0  # empty is "not answered", not "Yes"


def test_answers_are_counted_as_given(state_file: Path, tmp_path: Path) -> None:
    path = _make(state_file, tmp_path)
    wb = openpyxl.load_workbook(path)
    ws = wb["Threats"]
    ws["M2"], ws["N2"], ws["O2"], ws["P2"], ws["Q2"] = "Yes", "Loosely", "About right", "Too easy", "ok"
    ws["M3"], ws["N3"] = "Partly", "No"
    wb["Assets"]["E2"] = "No"
    wb["Assets"]["E3"], wb["Assets"]["F3"] = "Yes", "replay of the unlock command"
    wb["Reviewer"]["B1"], wb["Reviewer"]["B2"] = "Dr. Example", "Security engineer"
    wb.save(path)

    r = sheet.summarise(path)
    assert r["counted_as_review"] is True
    assert r["realistic"]["counts"] == {"Yes": 1, "Partly": 1}
    assert r["pattern_fits"]["counts"] == {"Loosely": 1, "No": 1}
    assert r["impact"]["answered"] == 1 and r["feasibility"]["counts"] == {"Too easy": 1}
    assert r["assets_with_missing_threat"] == 1
    assert r["missing_threats"] == [{"asset": "AS-2", "missing": "replay of the unlock command"}]
    assert r["comments"] == [{"threat": "THR-A", "comment": "ok"}]


def test_answers_outside_the_lists_are_ignored(state_file: Path, tmp_path: Path) -> None:
    path = _make(state_file, tmp_path)
    wb = openpyxl.load_workbook(path)
    wb["Threats"]["N2"] = "Definitely"
    wb["Reviewer"]["B1"] = "Dr. Example"
    wb.save(path)
    assert sheet.summarise(path)["pattern_fits"]["answered"] == 0


def test_markdown_states_when_it_is_not_a_review(state_file: Path, tmp_path: Path) -> None:
    text = sheet.to_markdown(sheet.summarise(_make(state_file, tmp_path)))
    assert "not counted as a review" in text
