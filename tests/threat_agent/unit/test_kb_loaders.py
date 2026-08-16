"""
tests/threat_agent/unit/test_kb_loaders.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1 | Unit Tests: KB Loaders  (Aryan)
──────────────────────────────────────────────────────────────────────────────
Tests every loader against real seed data files AND synthetic edge-case inputs.

Coverage map:
  BaseLoader helpers
    ✅ _load_json: valid file returns list
    ✅ _load_json: missing file raises FileNotFoundError
    ✅ _load_json: non-list JSON raises ValueError
    ✅ _parse_stride_hint: valid string returns enum
    ✅ _parse_stride_hint: None returns None
    ✅ _parse_stride_hint: unknown string raises MalformedKBEntryError
    ✅ _validate_entry: all present passes
    ✅ _validate_entry: missing field raises MalformedKBEntryError

  KBEntry
    ✅ embedding_text includes title + description + stride_hint + tactics
    ✅ to_metadata_dict / from_metadata_dict roundtrip
    ✅ from_metadata_dict handles null stride_hint

  CAPECLoader.load()
    ✅ returns non-empty list from real capec_seed.json
    ✅ all entries are KBEntry with source=CAPEC
    ✅ STRIDE hints parsed correctly
    ✅ pattern_ids start with CAPEC-
    ✅ MalformedKBEntryError on entry with missing title

  ATTCKLoader.load()
    ✅ returns non-empty list from real attck_seed.json
    ✅ all entries have non-empty mitre_tactics
    ✅ source=ATT&CK on all entries

  CWELoader.load()
    ✅ returns non-empty list from real cwe_seed.json
    ✅ mitre_tactics is empty list (CWE has no direct tactic mapping)

  STRIDELoader.load()
    ✅ returns non-empty list from real stride_seed.json
    ✅ all entries have non-null stride_hint (enforced by loader)
    ✅ MalformedKBEntryError on entry with null stride_hint

  All loaders
    ✅ FileNotFoundError on nonexistent path
    ✅ combined entry count == 24 (8 CAPEC + 6 ATT&CK + 4 CWE + 6 STRIDE)

Run:
    pytest tests/threat_agent/unit/test_kb_loaders.py -v
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from agents.threat_agent.exceptions import MalformedKBEntryError
from agents.threat_agent.schemas import KBSource, STRIDECategory
from kb.loaders.attck_loader import ATTCKLoader
from kb.loaders.base_loader import _STRIDE_STR_MAP, KBEntry
from kb.loaders.capec_loader import CAPECLoader
from kb.loaders.cwe_loader import CWELoader
from kb.loaders.stride_loader import STRIDELoader

# ── Real seed file paths ───────────────────────────────────────────────────

_DATA_DIR = Path("kb/data")
_CAPEC_SEED = _DATA_DIR / "capec_seed.json"
_ATTCK_SEED = _DATA_DIR / "attck_seed.json"
_CWE_SEED = _DATA_DIR / "cwe_seed.json"
_STRIDE_SEED = _DATA_DIR / "stride_seed.json"


# ── Helpers ────────────────────────────────────────────────────────────────


def _write_tmp_json(data: object) -> Path:
    """Write a JSON object to a temp file and return its path."""
    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=".json",
        delete=False,
        encoding="utf-8",
    ) as tmp:
        json.dump(data, tmp)
        tmp.flush()
        return Path(tmp.name)


def _make_minimal_capec_entry(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "pattern_id": "CAPEC-TEST-001",
        "title": "Test CAPEC Pattern",
        "description": "A test attack pattern for unit testing.",
        "stride_hint": "Spoofing",
        "mitre_tactics": ["TA0001"],
    }
    base.update(overrides)
    return base


# ══════════════════════════════════════════════════════════════════════════════
# § 0 — KBEntry dataclass
# ══════════════════════════════════════════════════════════════════════════════


class TestKBEntry:
    def test_embedding_text_includes_title_and_description(self) -> None:
        entry = KBEntry(
            pattern_id="CAPEC-62",
            source=KBSource.CAPEC,
            title="Cross-Site Request Forgery",
            description="Adversary forces victim browser to submit requests.",
            stride_hint=STRIDECategory.TAMPERING,
            mitre_tactics=["TA0001"],
        )
        text = entry.embedding_text()
        assert "Cross-Site Request Forgery" in text
        assert "Adversary forces victim" in text

    def test_embedding_text_includes_stride_hint_keyword(self) -> None:
        entry = KBEntry(
            pattern_id="CAPEC-TEST",
            source=KBSource.CAPEC,
            title="Some Pattern",
            description="Description.",
            stride_hint=STRIDECategory.SPOOFING,
        )
        assert "Spoofing" in entry.embedding_text()

    def test_embedding_text_includes_mitre_tactics(self) -> None:
        entry = KBEntry(
            pattern_id="ATT-TEST",
            source=KBSource.ATT_AND_CK,
            title="Some Technique",
            description="Description.",
            stride_hint=None,
            mitre_tactics=["TA0001", "TA0003"],
        )
        text = entry.embedding_text()
        assert "TA0001" in text
        assert "TA0003" in text

    def test_embedding_text_no_stride_no_tactics(self) -> None:
        entry = KBEntry(
            pattern_id="CWE-306",
            source=KBSource.CWE,
            title="Missing Auth",
            description="Missing authentication for critical function.",
            stride_hint=None,
            mitre_tactics=[],
        )
        text = entry.embedding_text()
        assert "Missing Auth" in text
        assert "Missing authentication" in text

    def test_to_metadata_dict_roundtrip(self) -> None:
        entry = KBEntry(
            pattern_id="CAPEC-94",
            source=KBSource.CAPEC,
            title="AiTM",
            description="Adversary in the Middle attack.",
            stride_hint=STRIDECategory.SPOOFING,
            mitre_tactics=["TA0006"],
        )
        d = entry.to_metadata_dict()
        restored = KBEntry.from_metadata_dict(d)
        assert restored.pattern_id == entry.pattern_id
        assert restored.source == entry.source
        assert restored.stride_hint == entry.stride_hint
        assert restored.mitre_tactics == entry.mitre_tactics

    def test_from_metadata_dict_null_stride_hint(self) -> None:
        d = {
            "pattern_id": "CWE-306",
            "source": "CWE",
            "title": "Missing Auth",
            "description": "Description.",
            "stride_hint": None,
            "mitre_tactics": [],
        }
        entry = KBEntry.from_metadata_dict(d)
        assert entry.stride_hint is None

    def test_from_metadata_dict_all_stride_categories(self) -> None:
        """All valid STRIDE strings must round-trip through from_metadata_dict."""
        for raw, expected in _STRIDE_STR_MAP.items():
            d = {
                "pattern_id": "TEST-001",
                "source": "CAPEC",
                "title": "T",
                "description": "D",
                "stride_hint": raw,
                "mitre_tactics": [],
            }
            entry = KBEntry.from_metadata_dict(d)
            assert entry.stride_hint == expected, (
                f"Failed for raw hint '{raw}'"
            )


# ══════════════════════════════════════════════════════════════════════════════
# § 1 — CAPECLoader
# ══════════════════════════════════════════════════════════════════════════════


class TestCAPECLoader:
    def test_loads_real_seed_file(self) -> None:
        entries = CAPECLoader().load(_CAPEC_SEED)
        assert len(entries) > 0

    def test_all_entries_have_capec_source(self) -> None:
        entries = CAPECLoader().load(_CAPEC_SEED)
        assert all(e.source == KBSource.CAPEC for e in entries)

    def test_all_pattern_ids_start_with_capec(self) -> None:
        entries = CAPECLoader().load(_CAPEC_SEED)
        assert all(e.pattern_id.startswith("CAPEC-") for e in entries)

    def test_all_entries_have_non_empty_title_and_description(self) -> None:
        entries = CAPECLoader().load(_CAPEC_SEED)
        for e in entries:
            assert e.title.strip(), f"{e.pattern_id} has empty title"
            assert e.description.strip(), f"{e.pattern_id} has empty description"

    def test_stride_hints_are_valid_enums(self) -> None:
        entries = CAPECLoader().load(_CAPEC_SEED)
        for e in entries:
            if e.stride_hint is not None:
                assert isinstance(e.stride_hint, STRIDECategory)

    def test_expected_entry_count(self) -> None:
        """Seed file should have exactly 8 entries."""
        entries = CAPECLoader().load(_CAPEC_SEED)
        assert len(entries) == 8

    def test_missing_title_raises_malformed_error(self) -> None:
        bad_entry = _make_minimal_capec_entry(title="")
        path = _write_tmp_json([bad_entry])
        with pytest.raises(MalformedKBEntryError) as exc_info:
            CAPECLoader().load(path)
        assert "title" in str(exc_info.value).lower()

    def test_missing_description_raises_malformed_error(self) -> None:
        bad_entry = _make_minimal_capec_entry(description="")
        path = _write_tmp_json([bad_entry])
        with pytest.raises(MalformedKBEntryError):
            CAPECLoader().load(path)

    def test_invalid_stride_hint_raises_malformed_error(self) -> None:
        bad_entry = _make_minimal_capec_entry(stride_hint="NotACategory")
        path = _write_tmp_json([bad_entry])
        with pytest.raises(MalformedKBEntryError) as exc_info:
            CAPECLoader().load(path)
        assert "NotACategory" in str(exc_info.value)

    def test_null_stride_hint_is_allowed(self) -> None:
        entry = _make_minimal_capec_entry(stride_hint=None)
        path = _write_tmp_json([entry])
        entries = CAPECLoader().load(path)
        assert entries[0].stride_hint is None

    def test_missing_mitre_tactics_defaults_to_empty_list(self) -> None:
        entry = _make_minimal_capec_entry()
        del entry["mitre_tactics"]  # type: ignore[misc]
        path = _write_tmp_json([entry])
        entries = CAPECLoader().load(path)
        assert entries[0].mitre_tactics == []

    def test_nonexistent_file_raises_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            CAPECLoader().load(Path("nonexistent/path/capec.json"))


# ══════════════════════════════════════════════════════════════════════════════
# § 2 — ATTCKLoader
# ══════════════════════════════════════════════════════════════════════════════


class TestATTCKLoader:
    def test_loads_real_seed_file(self) -> None:
        entries = ATTCKLoader().load(_ATTCK_SEED)
        assert len(entries) > 0

    def test_all_entries_have_attck_source(self) -> None:
        entries = ATTCKLoader().load(_ATTCK_SEED)
        assert all(e.source == KBSource.ATT_AND_CK for e in entries)

    def test_all_entries_have_non_empty_mitre_tactics(self) -> None:
        """ATT&CK entries should have at least one tactic ID."""
        entries = ATTCKLoader().load(_ATTCK_SEED)
        for e in entries:
            assert len(e.mitre_tactics) > 0, (
                f"{e.pattern_id} has no MITRE tactics — "
                "ATT&CK entries must have tactic IDs."
            )

    def test_tactic_ids_match_mitre_format(self) -> None:
        entries = ATTCKLoader().load(_ATTCK_SEED)
        for e in entries:
            for tactic_id in e.mitre_tactics:
                assert tactic_id.startswith("TA"), (
                    f"{e.pattern_id} has malformed tactic ID: {tactic_id}"
                )

    def test_expected_entry_count(self) -> None:
        entries = ATTCKLoader().load(_ATTCK_SEED)
        assert len(entries) == 6

    def test_nonexistent_file_raises_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            ATTCKLoader().load(Path("no/such/attck.json"))


# ══════════════════════════════════════════════════════════════════════════════
# § 3 — CWELoader
# ══════════════════════════════════════════════════════════════════════════════


class TestCWELoader:
    def test_loads_real_seed_file(self) -> None:
        entries = CWELoader().load(_CWE_SEED)
        assert len(entries) > 0

    def test_all_entries_have_cwe_source(self) -> None:
        entries = CWELoader().load(_CWE_SEED)
        assert all(e.source == KBSource.CWE for e in entries)

    def test_cwe_entries_have_empty_mitre_tactics(self) -> None:
        """CWE entries describe weaknesses — no direct ATT&CK tactic mapping."""
        entries = CWELoader().load(_CWE_SEED)
        for e in entries:
            assert e.mitre_tactics == [], (
                f"{e.pattern_id} has unexpected MITRE tactics: "
                f"{e.mitre_tactics}"
            )

    def test_all_pattern_ids_start_with_cwe(self) -> None:
        entries = CWELoader().load(_CWE_SEED)
        assert all(e.pattern_id.startswith("CWE-") for e in entries)

    def test_expected_entry_count(self) -> None:
        entries = CWELoader().load(_CWE_SEED)
        assert len(entries) == 4

    def test_nonexistent_file_raises_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            CWELoader().load(Path("no/such/cwe.json"))


# ══════════════════════════════════════════════════════════════════════════════
# § 4 — STRIDELoader
# ══════════════════════════════════════════════════════════════════════════════


class TestSTRIDELoader:
    def test_loads_real_seed_file(self) -> None:
        entries = STRIDELoader().load(_STRIDE_SEED)
        assert len(entries) > 0

    def test_all_entries_have_stride_source(self) -> None:
        entries = STRIDELoader().load(_STRIDE_SEED)
        assert all(e.source == KBSource.STRIDE for e in entries)

    def test_all_entries_have_non_null_stride_hint(self) -> None:
        """STRIDE entries must ALWAYS have a stride_hint — it's mandatory."""
        entries = STRIDELoader().load(_STRIDE_SEED)
        for e in entries:
            assert e.stride_hint is not None, (
                f"{e.pattern_id} is missing stride_hint — "
                "STRIDE loader must reject such entries."
            )

    def test_all_six_stride_categories_are_covered(self) -> None:
        entries = STRIDELoader().load(_STRIDE_SEED)
        covered = {e.stride_hint for e in entries}
        expected = set(STRIDECategory)
        assert covered == expected, (
            f"Missing STRIDE categories: {expected - covered}"
        )

    def test_expected_entry_count(self) -> None:
        entries = STRIDELoader().load(_STRIDE_SEED)
        assert len(entries) == 6

    def test_null_stride_hint_raises_malformed_error(self) -> None:
        bad = {
            "pattern_id": "STRIDE-X-001",
            "title": "Bad Entry",
            "description": "Missing hint.",
            "stride_hint": None,
            "mitre_tactics": [],
        }
        path = _write_tmp_json([bad])
        with pytest.raises(MalformedKBEntryError):
            STRIDELoader().load(path)

    def test_nonexistent_file_raises_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            STRIDELoader().load(Path("no/such/stride.json"))


# ══════════════════════════════════════════════════════════════════════════════
# § 5 — Combined loader invariants
# ══════════════════════════════════════════════════════════════════════════════


class TestCombinedLoaders:
    def test_total_seed_entry_count_is_24(self) -> None:
        """Full seed KB must have exactly 24 entries across all sources."""
        total = (
            len(CAPECLoader().load(_CAPEC_SEED))
            + len(ATTCKLoader().load(_ATTCK_SEED))
            + len(CWELoader().load(_CWE_SEED))
            + len(STRIDELoader().load(_STRIDE_SEED))
        )
        assert total == 24, (
            f"Expected 24 total seed entries, got {total}. "
            "Update this test if you add new seed entries."
        )

    def test_all_pattern_ids_are_globally_unique(self) -> None:
        """pattern_id must be unique across all KB sources combined."""
        all_entries = (
            CAPECLoader().load(_CAPEC_SEED)
            + ATTCKLoader().load(_ATTCK_SEED)
            + CWELoader().load(_CWE_SEED)
            + STRIDELoader().load(_STRIDE_SEED)
        )
        ids = [e.pattern_id for e in all_entries]
        assert len(ids) == len(set(ids)), (
            f"Duplicate pattern_ids found: "
            f"{[i for i in ids if ids.count(i) > 1]}"
        )

    def test_all_entries_have_non_empty_embedding_text(self) -> None:
        """embedding_text() must return a non-empty string for every entry."""
        all_entries = (
            CAPECLoader().load(_CAPEC_SEED)
            + ATTCKLoader().load(_ATTCK_SEED)
            + CWELoader().load(_CWE_SEED)
            + STRIDELoader().load(_STRIDE_SEED)
        )
        for entry in all_entries:
            text = entry.embedding_text()
            assert text.strip(), (
                f"{entry.source}::{entry.pattern_id} produced empty "
                "embedding_text(). This entry will not be retrievable."
            )

    def test_non_list_json_raises_value_error(self) -> None:
        path = _write_tmp_json({"not": "a list"})
        with pytest.raises(ValueError, match="JSON array"):
            CAPECLoader().load(path)
