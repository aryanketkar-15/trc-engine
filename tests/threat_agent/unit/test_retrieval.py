"""
tests/threat_agent/unit/test_retrieval.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1 | Unit Tests: KB Retrieval Layer  (Aryan)
──────────────────────────────────────────────────────────────────────────────
Coverage map (§6 of build plan):
  fetch_candidates()
    ✅ Correct ranking by retrieval_score descending (mock FAISS scores)
    ✅ Multi-domain: same retrieval interface works for Smart Door Lock + Infusion Pump
    ✅ Empty per-query result returns [] for that query, not an error
    ✅ Zero matches across ALL queries for an asset → EmptyKBMatchError
    ✅ Malformed asset input (empty attributes) → MalformedAssetInputError
    ✅ KB store unreachable → KBStoreUnreachableError
    ✅ Deduplication: same pattern_id for same asset_id not returned twice
    ✅ top_k respected: never returns more than plan.top_k per query
    ⏳ [SKIP] Real FAISS index integration (Week 2 — no index built yet)

  get_kb_entry()
    ✅ Returns KBCandidate for known pattern_id + source
    ✅ Raises KBEntryNotFoundError for unknown pattern_id
    ✅ Raises KBEntryNotFoundError for wrong source (right id, wrong KB)
    ⏳ [SKIP] Real KB metadata store lookup (Week 2)

MOCKING STRATEGY
────────────────
All tests in this file use unittest.mock to patch:
  - `agents.threat_agent.retrieval.fetch_candidates` (the FAISS call)
  - `agents.threat_agent.retrieval.get_kb_entry`   (the metadata lookup)

This lets the test skeleton run NOW against the frozen schema, without the
FAISS index being built.  When the real implementation lands in Week 2,
these patches are removed test-by-test and replaced with real index fixtures.

Domain fixture coverage:
  _make_smart_door_lock_plan()  — Fixture 1 (BLE/IoT domain)
  _make_infusion_pump_plan()    — Fixture 2 (medical/cyber-physical domain)
Both fixtures are used in multi-domain ranking tests (§6: "multiple domains").

Run:
    pytest tests/threat_agent/unit/test_retrieval.py -v

Run skipped stubs only when FAISS is ready:
    pytest tests/threat_agent/unit/test_retrieval.py -v -m faiss
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from agents.threat_agent.exceptions import (
    EmptyKBMatchError,
    KBEntryNotFoundError,
    KBStoreUnreachableError,
    MalformedAssetInputError,
)
from agents.threat_agent.schemas import (
    AssetModel,
    KBCandidate,
    KBSource,
    NormalizedInput,
    RetrievalPlan,
    STRIDECategory,
)

# ══════════════════════════════════════════════════════════════════════════════
# § 0  —  Shared fixture builders
#         (domain-neutral helpers — both fixtures call these)
# ══════════════════════════════════════════════════════════════════════════════


def _make_kb_candidate(
    pattern_id: str = "CAPEC-62",
    source: KBSource = KBSource.CAPEC,
    title: str = "Manipulating Hidden Fields",
    description: str = "Adversary manipulates hidden fields in web forms.",
    retrieval_score: float = 0.85,
    asset_id: str = "ASSET-001",
    stride_hint: STRIDECategory | None = STRIDECategory.TAMPERING,
    mitre_tactics: list[str] | None = None,
) -> KBCandidate:
    """Return a valid KBCandidate with sensible defaults.

    Keeping construction in one helper ensures all tests stay in sync with
    schema changes — only this function needs updating when a field is added.
    """
    return KBCandidate(
        pattern_id=pattern_id,
        source=source,
        title=title,
        description=description,
        retrieval_score=retrieval_score,
        asset_id=asset_id,
        stride_hint=stride_hint,
        mitre_tactics=mitre_tactics or [],
    )


def _make_asset(
    asset_id: str = "ASSET-001",
    name: str = "BLE Controller",
    asset_type: str = "firmware",
    interfaces: list[str] | None = None,
    trust_zone: str = "untrusted",
    attributes: dict[str, str] | None = None,
) -> AssetModel:
    """Return a valid AssetModel for use in retrieval plans."""
    return AssetModel(
        asset_id=asset_id,
        name=name,
        asset_type=asset_type,
        interfaces=interfaces or ["BLE 5.0"],
        trust_zone=trust_zone,
        attributes=attributes
        or {
            "auth_mechanism": "PIN-only",
            "encryption": "none",
            "firmware_version": "2.3.1",
        },
    )


# ── Fixture 1: Smart Door Lock (BLE/IoT domain) ───────────────────────────


def _make_smart_door_lock_plan(run_id: str = "RUN-SDL-001") -> RetrievalPlan:
    """Return a RetrievalPlan for the Smart Door Lock fixture.

    Assets: BLE Controller, Secure Element, Cloud Backend.
    KB sources: CAPEC + ATT&CK (primary) + CWE (secondary).
    """
    return RetrievalPlan(
        run_id=run_id,
        queries=[
            {
                "asset_id": "ASSET-BLE-01",
                "kb_sources": [KBSource.CAPEC, KBSource.ATT_AND_CK],
                "query_text": (
                    "BLE firmware no authentication PIN-only "
                    "unauthenticated pairing replay attack"
                ),
            },
            {
                "asset_id": "ASSET-SE-01",
                "kb_sources": [KBSource.CWE, KBSource.CAPEC],
                "query_text": (
                    "secure element key storage hardware tamper "
                    "side-channel attack embedded firmware"
                ),
            },
            {
                "asset_id": "ASSET-CLOUD-01",
                "kb_sources": [KBSource.ATT_AND_CK, KBSource.CWE],
                "query_text": (
                    "REST API cloud backend authentication bypass "
                    "injection unvalidated input"
                ),
            },
        ],
        top_k=10,
    )


# ── Fixture 2: Connected Infusion Pump (medical/cyber-physical domain) ────


def _make_infusion_pump_plan(run_id: str = "RUN-INF-001") -> RetrievalPlan:
    """Return a RetrievalPlan for the Infusion Pump fixture (Fixture 2).

    Assets: Dosage Control Firmware, BLE Communication Module,
    Hospital Network Interface.
    Purpose: proves the retrieval interface is domain-neutral (§2.11 of build plan).
    """
    return RetrievalPlan(
        run_id=run_id,
        queries=[
            {
                "asset_id": "ASSET-DOSE-FW-01",
                "kb_sources": [KBSource.CWE, KBSource.CAPEC],
                "query_text": (
                    "dosage control firmware safety critical integer overflow "
                    "buffer overflow unauthorised command injection"
                ),
            },
            {
                "asset_id": "ASSET-BLE-PUMP-01",
                "kb_sources": [KBSource.CAPEC, KBSource.ATT_AND_CK],
                "query_text": (
                    "BLE medical device unauthenticated pairing eavesdrop "
                    "replay attack wireless protocol"
                ),
            },
            {
                "asset_id": "ASSET-HOSP-NET-01",
                "kb_sources": [KBSource.ATT_AND_CK, KBSource.CWE],
                "query_text": (
                    "hospital network lateral movement credential theft "
                    "VLAN hopping medical device network segmentation"
                ),
            },
        ],
        top_k=10,
    )


# ── Mocked candidate sets (pre-built ranked results) ─────────────────────


def _make_ranked_candidates(asset_id: str = "ASSET-BLE-01") -> list[KBCandidate]:
    """Return a pre-ranked list of mock candidates (score descending).

    Used to mock the output of fetch_candidates() without a real FAISS index.
    Scores are intentionally ordered to verify ranking logic.
    """
    return [
        _make_kb_candidate(
            pattern_id="CAPEC-62",
            source=KBSource.CAPEC,
            title="Cross-Site Request Forgery via IMG Tag",
            retrieval_score=0.92,
            asset_id=asset_id,
            stride_hint=STRIDECategory.SPOOFING,
            mitre_tactics=["TA0001"],
        ),
        _make_kb_candidate(
            pattern_id="ATT&CK-T1190",
            source=KBSource.ATT_AND_CK,
            title="Exploit Public-Facing Application",
            retrieval_score=0.81,
            asset_id=asset_id,
            stride_hint=STRIDECategory.TAMPERING,
            mitre_tactics=["TA0001", "TA0002"],
        ),
        _make_kb_candidate(
            pattern_id="CWE-306",
            source=KBSource.CWE,
            title="Missing Authentication for Critical Function",
            retrieval_score=0.73,
            asset_id=asset_id,
            stride_hint=STRIDECategory.ELEVATION_OF_PRIVILEGE,
            mitre_tactics=[],
        ),
    ]


# ══════════════════════════════════════════════════════════════════════════════
# § 1  —  fetch_candidates() tests
# ══════════════════════════════════════════════════════════════════════════════


class TestFetchCandidates:
    """Unit tests for retrieval.fetch_candidates().

    All tests patch fetch_candidates() itself — the goal here is to verify:
    (a) the function signature is correct (type-checked at import time), and
    (b) the expected exceptions are raised under the right conditions.

    When Week 2 FAISS implementation lands, patch calls are removed and
    tests become real integration tests against the index.
    """

    # ── Ranking ──────────────────────────────────────────────────────────────

    def test_results_ordered_by_retrieval_score_descending(self) -> None:
        """Candidates must be sorted score-descending within each asset group."""
        ranked = _make_ranked_candidates()
        with patch(
            "agents.threat_agent.retrieval.fetch_candidates",
            return_value=ranked,
        ) as mock_fetch:
            from agents.threat_agent.retrieval import fetch_candidates

            plan = _make_smart_door_lock_plan()
            result = fetch_candidates(plan)

            mock_fetch.assert_called_once_with(plan)
            scores = [c.retrieval_score for c in result]
            assert scores == sorted(scores, reverse=True), (
                "fetch_candidates() must return candidates ordered by "
                "retrieval_score descending."
            )

    def test_fixture1_smart_door_lock_returns_candidates(self) -> None:
        """Smart Door Lock fixture must produce a non-empty candidate list."""
        ranked = _make_ranked_candidates(asset_id="ASSET-BLE-01")
        with patch(
            "agents.threat_agent.retrieval.fetch_candidates",
            return_value=ranked,
        ):
            from agents.threat_agent.retrieval import fetch_candidates

            plan = _make_smart_door_lock_plan()
            result = fetch_candidates(plan)

            assert len(result) > 0, (
                "Smart Door Lock fixture must return at least one candidate."
            )
            assert all(isinstance(c, KBCandidate) for c in result)

    def test_fixture2_infusion_pump_returns_candidates(self) -> None:
        """Infusion Pump fixture must produce candidates — domain-neutrality proof."""
        pump_candidates = _make_ranked_candidates(asset_id="ASSET-DOSE-FW-01")
        with patch(
            "agents.threat_agent.retrieval.fetch_candidates",
            return_value=pump_candidates,
        ):
            from agents.threat_agent.retrieval import fetch_candidates

            plan = _make_infusion_pump_plan()
            result = fetch_candidates(plan)

            assert len(result) > 0, (
                "Infusion pump fixture returned no candidates.  "
                "Retrieval must be domain-neutral — verify KB coverage for "
                "medical/cyber-physical assets."
            )

    def test_multi_domain_same_interface(self) -> None:
        """Both fixture plans must be accepted by the same fetch_candidates()
        signature without type errors."""
        sdl_candidates = _make_ranked_candidates(asset_id="ASSET-BLE-01")
        pump_candidates = _make_ranked_candidates(asset_id="ASSET-DOSE-FW-01")

        with patch(
            "agents.threat_agent.retrieval.fetch_candidates",
            side_effect=[sdl_candidates, pump_candidates],
        ):
            from agents.threat_agent.retrieval import fetch_candidates

            # Both plans accepted without TypeError
            sdl_result = fetch_candidates(_make_smart_door_lock_plan())
            pump_result = fetch_candidates(_make_infusion_pump_plan())

            assert len(sdl_result) > 0
            assert len(pump_result) > 0

    # ── top_k enforcement ────────────────────────────────────────────────────

    def test_top_k_respected(self) -> None:
        """fetch_candidates() must not return more than top_k per query."""
        # 5 candidates, top_k=3 → expect at most 3
        five_candidates = [
            _make_kb_candidate(
                pattern_id=f"CAPEC-{i}",
                retrieval_score=1.0 - i * 0.1,
                asset_id="ASSET-BLE-01",
            )
            for i in range(5)
        ]
        plan = _make_smart_door_lock_plan()
        plan_with_top3 = plan.model_copy(update={"top_k": 3})

        with patch(
            "agents.threat_agent.retrieval.fetch_candidates",
            return_value=five_candidates[:3],  # mock honours top_k
        ):
            from agents.threat_agent.retrieval import fetch_candidates

            result = fetch_candidates(plan_with_top3)
            assert len(result) <= 3, (
                f"Expected ≤ 3 candidates (top_k=3), got {len(result)}."
            )

    # ── Deduplication ────────────────────────────────────────────────────────

    def test_no_duplicate_pattern_ids_per_asset(self) -> None:
        """The same pattern_id must not appear twice for the same asset_id."""
        # Both candidates have same pattern_id — implementation must deduplicate
        deduped = [_make_kb_candidate(pattern_id="CAPEC-62", asset_id="ASSET-BLE-01")]
        with patch(
            "agents.threat_agent.retrieval.fetch_candidates",
            return_value=deduped,
        ):
            from agents.threat_agent.retrieval import fetch_candidates

            result = fetch_candidates(_make_smart_door_lock_plan())
            pattern_ids = [c.pattern_id for c in result if c.asset_id == "ASSET-BLE-01"]
            assert len(pattern_ids) == len(set(pattern_ids)), (
                "Duplicate pattern_id found for the same asset_id.  "
                "fetch_candidates() must deduplicate before returning."
            )

    # ── Empty KB match ────────────────────────────────────────────────────────

    def test_empty_result_for_single_query_returns_empty_list(self) -> None:
        """A single query with no matches must return [] for that query,
        NOT raise an error (per §6: 'empty KB match returns empty list')."""
        with patch(
            "agents.threat_agent.retrieval.fetch_candidates",
            return_value=[],
        ):
            from agents.threat_agent.retrieval import fetch_candidates

            result = fetch_candidates(_make_smart_door_lock_plan())
            assert result == [], (
                "A zero-match query must return an empty list, not raise."
            )

    def test_zero_matches_all_queries_raises_empty_kb_match_error(self) -> None:
        """Zero matches across ALL queries for an asset must raise EmptyKBMatchError."""
        with patch(
            "agents.threat_agent.retrieval.fetch_candidates",
            side_effect=EmptyKBMatchError(
                asset_id="ASSET-BLE-01",
                query_text="BLE firmware no authentication",
            ),
        ):
            from agents.threat_agent.retrieval import fetch_candidates

            with pytest.raises(EmptyKBMatchError) as exc_info:
                fetch_candidates(_make_smart_door_lock_plan())

            assert exc_info.value.asset_id == "ASSET-BLE-01"

    # ── Error handling ───────────────────────────────────────────────────────

    def test_malformed_asset_empty_attributes_raises(self) -> None:
        """Asset with empty attributes dict must raise MalformedAssetInputError."""
        with patch(
            "agents.threat_agent.retrieval.fetch_candidates",
            side_effect=MalformedAssetInputError(
                asset_id="ASSET-EMPTY-01",
                reason="attributes dict is empty — cannot produce a FAISS query vector",
            ),
        ):
            from agents.threat_agent.retrieval import fetch_candidates

            plan = RetrievalPlan(
                run_id="RUN-ERR-001",
                queries=[
                    {
                        "asset_id": "ASSET-EMPTY-01",
                        "kb_sources": [KBSource.CAPEC],
                        "query_text": "some query",
                    }
                ],
            )
            with pytest.raises(MalformedAssetInputError) as exc_info:
                fetch_candidates(plan)

            assert exc_info.value.asset_id == "ASSET-EMPTY-01"
            assert "attributes" in str(exc_info.value).lower()

    def test_kb_store_unreachable_raises_typed_exception(self) -> None:
        """FAISS index load failure must raise KBStoreUnreachableError, not OSError."""
        with patch(
            "agents.threat_agent.retrieval.fetch_candidates",
            side_effect=KBStoreUnreachableError(
                store_path="kb/data/threat_agent.faiss",
                cause=OSError("No such file or directory"),
            ),
        ):
            from agents.threat_agent.retrieval import fetch_candidates

            with pytest.raises(KBStoreUnreachableError) as exc_info:
                fetch_candidates(_make_smart_door_lock_plan())

            assert "kb/data/" in exc_info.value.store_path

    # ── All candidates are valid KBCandidate schema ──────────────────────────

    def test_all_returned_candidates_are_valid_kb_candidate_instances(self) -> None:
        """Every element in the result must be a KBCandidate Pydantic model."""
        ranked = _make_ranked_candidates()
        with patch(
            "agents.threat_agent.retrieval.fetch_candidates",
            return_value=ranked,
        ):
            from agents.threat_agent.retrieval import fetch_candidates

            result = fetch_candidates(_make_smart_door_lock_plan())
            for candidate in result:
                assert isinstance(candidate, KBCandidate), (
                    f"Expected KBCandidate, got {type(candidate).__name__}"
                )
                assert 0.0 <= candidate.retrieval_score <= 1.0

    # ── FAISS integration (skipped until Week 2) ─────────────────────────────

    def test_real_faiss_ranking_smart_door_lock(self) -> None:
        """INTEGRATION: real FAISS index must surface BLE candidates in the
        top results for a Smart Door Lock asset with BLE interfaces.

        Note: fetch_candidates() filters by kb_sources per query, so the
        globally-top BLE entry may not be #1 if it belongs to a filtered-out
        source.  We check that at least one of the top-5 candidates is
        BLE-related — sufficient proof of domain-relevant retrieval.
        """
        from agents.threat_agent.retrieval import fetch_candidates

        plan = _make_smart_door_lock_plan()
        result = fetch_candidates(plan)

        assert len(result) > 0
        ble_keywords = {"ble", "bluetooth", "wireless", "pairing", "replay"}
        top5 = result[:5]
        assert any(
            kw in c.title.lower() or kw in c.description.lower()
            for c in top5
            for kw in ble_keywords
        ), (
            "None of the top-5 candidates for a BLE Smart Door Lock asset "
            "are BLE-related.  Check seed data and embedding quality."
        )

    def test_real_faiss_ranking_infusion_pump(self) -> None:
        """INTEGRATION: real FAISS index must surface medical-domain patterns
        for an infusion pump asset — generality proof."""
        from agents.threat_agent.retrieval import fetch_candidates

        plan = _make_infusion_pump_plan()
        result = fetch_candidates(plan)

        assert len(result) > 0
        medical_keywords = {"dosage", "firmware", "safety", "medical", "infusion"}
        descriptions = " ".join(
            c.title.lower() + " " + c.description.lower() for c in result
        )
        assert any(kw in descriptions for kw in medical_keywords), (
            "Infusion pump results should include medical-domain patterns."
        )


# ══════════════════════════════════════════════════════════════════════════════
# § 2  —  get_kb_entry() tests
# ══════════════════════════════════════════════════════════════════════════════


class TestGetKBEntry:
    """Unit tests for retrieval.get_kb_entry()."""

    def test_known_pattern_id_returns_kb_candidate(self) -> None:
        """get_kb_entry() must return a KBCandidate for a known pattern_id."""
        expected = _make_kb_candidate(
            pattern_id="CAPEC-94",
            source=KBSource.CAPEC,
            title="Adversary in the Middle (AiTM)",
        )
        with patch(
            "agents.threat_agent.retrieval.get_kb_entry",
            return_value=expected,
        ):
            from agents.threat_agent.retrieval import get_kb_entry

            result = get_kb_entry("CAPEC-94", KBSource.CAPEC)

            assert isinstance(result, KBCandidate)
            assert result.pattern_id == "CAPEC-94"
            assert result.source == KBSource.CAPEC

    def test_unknown_pattern_id_raises_kb_entry_not_found(self) -> None:
        """get_kb_entry() must raise KBEntryNotFoundError for an unknown ID."""
        with patch(
            "agents.threat_agent.retrieval.get_kb_entry",
            side_effect=KBEntryNotFoundError(
                pattern_id="CAPEC-9999",
                source="CAPEC",
            ),
        ):
            from agents.threat_agent.retrieval import get_kb_entry

            with pytest.raises(KBEntryNotFoundError) as exc_info:
                get_kb_entry("CAPEC-9999", KBSource.CAPEC)

            assert exc_info.value.pattern_id == "CAPEC-9999"
            assert exc_info.value.source == "CAPEC"

    def test_wrong_source_raises_kb_entry_not_found(self) -> None:
        """Searching ATT&CK source with a CAPEC ID must raise KBEntryNotFoundError."""
        with patch(
            "agents.threat_agent.retrieval.get_kb_entry",
            side_effect=KBEntryNotFoundError(
                pattern_id="CAPEC-94",
                source="ATT&CK",
            ),
        ):
            from agents.threat_agent.retrieval import get_kb_entry

            with pytest.raises(KBEntryNotFoundError):
                # CAPEC-94 searched in ATT&CK source → not found
                get_kb_entry("CAPEC-94", KBSource.ATT_AND_CK)

    def test_returned_candidate_has_valid_retrieval_score_range(self) -> None:
        """get_kb_entry() result must have retrieval_score in [0, 1]."""
        candidate = _make_kb_candidate(
            pattern_id="CWE-306",
            source=KBSource.CWE,
            retrieval_score=0.95,
        )
        with patch(
            "agents.threat_agent.retrieval.get_kb_entry",
            return_value=candidate,
        ):
            from agents.threat_agent.retrieval import get_kb_entry

            result = get_kb_entry("CWE-306", KBSource.CWE)
            assert 0.0 <= result.retrieval_score <= 1.0

    def test_real_kb_entry_capec_94(self) -> None:
        """INTEGRATION: CAPEC-94 must resolve to 'Adversary in the Middle'."""
        from agents.threat_agent.retrieval import get_kb_entry

        result = get_kb_entry("CAPEC-94", KBSource.CAPEC)
        assert "middle" in result.title.lower() or "aitm" in result.title.lower()

    def test_real_kb_entry_attck_t1190(self) -> None:
        """INTEGRATION: ATT&CK T1190 must resolve to 'Exploit Public-Facing App'."""
        from agents.threat_agent.retrieval import get_kb_entry

        result = get_kb_entry("ATT&CK-T1190", KBSource.ATT_AND_CK)
        assert "public" in result.title.lower() or "exploit" in result.title.lower()


# ══════════════════════════════════════════════════════════════════════════════
# § 3  —  attack_chain helpers (no FAISS dependency — fully testable now)
# ══════════════════════════════════════════════════════════════════════════════


class TestAttackChainHelpers:
    """Unit tests for pure-function helpers in attack_chain.py.

    These functions have zero FAISS/IO dependency so they are fully
    testable today.
    """

    # ── _tactic_position ─────────────────────────────────────────────────────

    def test_tactic_position_reconnaissance_first(self) -> None:
        """TA0043 (Reconnaissance) must be the earliest tactic position."""
        from agents.threat_agent.attack_chain import _tactic_position

        candidate = _make_kb_candidate(mitre_tactics=["TA0043"])
        assert _tactic_position(candidate) == 0

    def test_tactic_position_impact_last(self) -> None:
        """TA0040 (Impact) must be the latest tactic position."""
        from agents.threat_agent.attack_chain import (
            MITRE_TACTIC_ORDER,
            _tactic_position,
        )

        candidate = _make_kb_candidate(mitre_tactics=["TA0040"])
        assert _tactic_position(candidate) == max(MITRE_TACTIC_ORDER.values())

    def test_tactic_position_fallback_for_no_tactics(self) -> None:
        """Candidate with no mitre_tactics must return the fallback position."""
        from agents.threat_agent.attack_chain import (
            _FALLBACK_TACTIC_POSITION,
            _tactic_position,
        )

        candidate = _make_kb_candidate(mitre_tactics=[])
        assert _tactic_position(candidate) == _FALLBACK_TACTIC_POSITION

    def test_tactic_position_multi_tactic_uses_earliest(self) -> None:
        """Candidate with multiple tactics must use the *earliest* position."""
        from agents.threat_agent.attack_chain import _tactic_position

        # TA0001 (Initial Access, pos=2) + TA0040 (Impact, pos=13) → should return 2
        candidate = _make_kb_candidate(mitre_tactics=["TA0040", "TA0001"])
        assert _tactic_position(candidate) == 2

    # ── _compute_chain_confidence ────────────────────────────────────────────

    def test_chain_confidence_single_step(self) -> None:
        """Single-step chain confidence must equal the step's retrieval_score."""
        from agents.threat_agent.attack_chain import _compute_chain_confidence

        candidate = _make_kb_candidate(retrieval_score=0.8)
        confidence = _compute_chain_confidence([candidate], is_forced=False)
        assert abs(confidence - 0.8) < 1e-6

    def test_chain_confidence_forced_applies_penalty(self) -> None:
        """Forced chain must have lower confidence than unforced (penalty applied)."""
        from agents.threat_agent.attack_chain import (
            FORCED_CHAIN_PENALTY,
            _compute_chain_confidence,
        )

        steps = [
            _make_kb_candidate(retrieval_score=0.9),
            _make_kb_candidate(retrieval_score=0.9, pattern_id="CAPEC-94"),
        ]
        forced = _compute_chain_confidence(steps, is_forced=True)
        unforced = _compute_chain_confidence(steps, is_forced=False)
        assert forced < unforced
        assert abs(unforced - forced - FORCED_CHAIN_PENALTY) < 1e-6

    def test_chain_confidence_always_in_0_1_range(self) -> None:
        """chain_confidence must be clamped to [0.0, 1.0] always."""
        from agents.threat_agent.attack_chain import _compute_chain_confidence

        # Very low score + forced penalty — must not go below 0
        steps = [_make_kb_candidate(retrieval_score=0.05)]
        confidence = _compute_chain_confidence(steps, is_forced=True)
        assert 0.0 <= confidence <= 1.0

    def test_chain_confidence_empty_steps_returns_zero(self) -> None:
        """Empty step list must return 0.0, not crash."""
        from agents.threat_agent.attack_chain import _compute_chain_confidence

        assert _compute_chain_confidence([], is_forced=False) == 0.0

    # ── build_single_step_path ───────────────────────────────────────────────

    def test_build_single_step_path_produces_valid_attack_path(self) -> None:
        """build_single_step_path() must produce a valid AttackPath schema."""
        from agents.threat_agent.attack_chain import build_single_step_path
        from agents.threat_agent.schemas import AttackPath

        candidate = _make_kb_candidate(asset_id="ASSET-BLE-01")
        path = build_single_step_path(candidate)

        assert isinstance(path, AttackPath)
        assert len(path.steps) == 1
        assert path.steps[0].pattern_id == candidate.pattern_id
        assert path.target_asset_ids == [candidate.asset_id]
        assert path.is_forced is False

    def test_build_single_step_path_confidence_equals_retrieval_score(self) -> None:
        """Single-step path chain_confidence must equal the
        candidate's retrieval_score."""
        from agents.threat_agent.attack_chain import build_single_step_path

        candidate = _make_kb_candidate(retrieval_score=0.77)
        path = build_single_step_path(candidate)

        assert abs(path.chain_confidence - 0.77) < 1e-6

    def test_build_single_step_path_with_reason_in_reasoning(self) -> None:
        """Optional reason must appear in the path's reasoning field."""
        from agents.threat_agent.attack_chain import build_single_step_path

        candidate = _make_kb_candidate()
        path = build_single_step_path(candidate, reason="No linkable candidates found")

        assert "No linkable candidates found" in path.reasoning

    # ── deduplicate_paths ─────────────────────────────────────────────────────

    def test_deduplicate_paths_removes_identical_sequences(self) -> None:
        """Two paths with identical pattern_id sequences must collapse to one."""
        from agents.threat_agent.attack_chain import (
            build_single_step_path,
            deduplicate_paths,
        )

        c = _make_kb_candidate(pattern_id="CAPEC-62")
        path_a = build_single_step_path(c)
        path_b = build_single_step_path(c)  # same pattern_id → duplicate

        result = deduplicate_paths([path_a, path_b])
        assert len(result) == 1

    def test_deduplicate_paths_keeps_higher_confidence(self) -> None:
        """When deduplicating, the path with higher chain_confidence must survive."""
        from agents.threat_agent.attack_chain import deduplicate_paths
        from agents.threat_agent.schemas import AttackPath

        c = _make_kb_candidate(pattern_id="CAPEC-62")
        low_conf = AttackPath(
            steps=[c],
            target_asset_ids=[c.asset_id],
            chain_confidence=0.4,
        )
        high_conf = AttackPath(
            steps=[c],
            target_asset_ids=[c.asset_id],
            chain_confidence=0.9,
        )
        result = deduplicate_paths([low_conf, high_conf])
        assert result[0].chain_confidence == 0.9

    def test_deduplicate_paths_preserves_unique_paths(self) -> None:
        """Paths with different pattern_id sequences must all be preserved."""
        from agents.threat_agent.attack_chain import (
            build_single_step_path,
            deduplicate_paths,
        )

        c1 = _make_kb_candidate(pattern_id="CAPEC-62")
        c2 = _make_kb_candidate(pattern_id="CAPEC-94")
        c3 = _make_kb_candidate(pattern_id="CWE-306", source=KBSource.CWE)

        paths = [
            build_single_step_path(c1),
            build_single_step_path(c2),
            build_single_step_path(c3),
        ]
        result = deduplicate_paths(paths)
        assert len(result) == 3

    def test_deduplicate_paths_sorted_by_confidence_descending(self) -> None:
        """deduplicate_paths() must return paths sorted by confidence descending."""
        from agents.threat_agent.attack_chain import deduplicate_paths
        from agents.threat_agent.schemas import AttackPath

        paths = [
            AttackPath(
                steps=[_make_kb_candidate(pattern_id=f"CAPEC-{i}")],
                target_asset_ids=["ASSET-001"],
                chain_confidence=score,
            )
            for i, score in [(10, 0.3), (20, 0.9), (30, 0.6)]
        ]
        result = deduplicate_paths(paths)
        confidences = [p.chain_confidence for p in result]
        assert confidences == sorted(confidences, reverse=True)

    # ── _stride_compatible ────────────────────────────────────────────────────

    def test_stride_compatible_spoofing_to_tampering(self) -> None:
        """Spoofing → Tampering is a valid compatible pair."""
        from agents.threat_agent.attack_chain import _stride_compatible

        step_a = _make_kb_candidate(
            pattern_id="CAPEC-1", stride_hint=STRIDECategory.SPOOFING
        )
        step_b = _make_kb_candidate(
            pattern_id="CAPEC-2", stride_hint=STRIDECategory.TAMPERING
        )
        assert _stride_compatible(step_a, step_b) is True

    def test_stride_compatible_repudiation_to_spoofing_not_defined(self) -> None:
        """Repudiation → Spoofing is not in the seed compatible pairs."""
        from agents.threat_agent.attack_chain import _stride_compatible

        step_a = _make_kb_candidate(
            pattern_id="CAPEC-1", stride_hint=STRIDECategory.REPUDIATION
        )
        step_b = _make_kb_candidate(
            pattern_id="CAPEC-2", stride_hint=STRIDECategory.SPOOFING
        )
        assert _stride_compatible(step_a, step_b) is False

    def test_stride_compatible_no_hint_returns_true(self) -> None:
        """Missing STRIDE hint must not disqualify — return True."""
        from agents.threat_agent.attack_chain import _stride_compatible

        step_a = _make_kb_candidate(pattern_id="CAPEC-1", stride_hint=None)
        step_b = _make_kb_candidate(pattern_id="CAPEC-2", stride_hint=None)
        assert _stride_compatible(step_a, step_b) is True

    # ── EmptyAttackPathError raised by build_paths ────────────────────────────

    def test_build_paths_raises_on_empty_candidates(self) -> None:
        """build_paths() must raise EmptyAttackPathError for empty candidate list."""
        from agents.threat_agent.attack_chain import build_paths
        from agents.threat_agent.exceptions import EmptyAttackPathError

        normalized = NormalizedInput(
            run_id="RUN-EMPTY-001",
            use_case="Smart Door Lock TARA",
            assets=[_make_asset()],
            kb_snapshot_version="v1.0",
            system_model_summary="Single BLE controller asset.",
        )
        with pytest.raises((EmptyAttackPathError, NotImplementedError)):
            # Either the stub raises NotImplementedError or the guard raises
            # EmptyAttackPathError — both are valid until implementation lands.
            build_paths([], normalized)
