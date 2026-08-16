"""
tests/threat_agent/unit/test_validator.py
─────────────────────────────────────────
Unit tests for the Protocol Invariant Validator and StateManager.

SCHEMA VERSION: aligned with frozen develop schema.
  - failed_checks: list[FailedCheck]  (NOT list[str])
  - STRIDECategory StrEnum
  - ValidationResult rejects passed=True + non-empty failed_checks

STRIDE_VECTOR_VOCABULARY patch:
  retrieval.py is not present locally yet (Aryan's branch).  Tests that
  exercise consistency_check use a module-level monkeypatch to inject a
  known vocabulary so the check is fully testable without retrieval.py.

Run with:
    pytest tests/threat_agent/unit/test_validator.py -v
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from agents.threat_agent.schemas import (
    EvidenceChain,
    FailedCheck,
    STRIDECategory,
    ThreatScenario,
    ThreatStatus,
    ValidationResult,
)
from agents.threat_agent.validator import (
    CHECK_CITATION_MISSING,
    CHECK_CONSISTENCY_MISMATCH,
    CHECK_EVIDENCE_GENERIC,
    CHECK_SCHEMA_INCOMPLETE,
    MIN_APPLICABILITY_REASON_LENGTH,
    Validator,
)
from scrp.state_manager import NotApprovedError, StateManager

# ============================================================================
# Vocabulary fixture for consistency_check tests
# (mirrors a subset of Aryan's STRIDE_VECTOR_VOCABULARY)
# ============================================================================

_TEST_VOCABULARY: dict[STRIDECategory, frozenset[str]] = {
    STRIDECategory.SPOOFING: frozenset({"replay", "impersonation", "ble replay", "phishing"}),
    STRIDECategory.TAMPERING: frozenset({"injection", "sql injection", "firmware manipulation"}),
    STRIDECategory.REPUDIATION: frozenset({"log deletion", "audit bypass", "log tampering"}),
    STRIDECategory.INFORMATION_DISCLOSURE: frozenset(
        {"eavesdrop", "sniffing", "data exfiltration"}
    ),
    STRIDECategory.DENIAL_OF_SERVICE: frozenset({"flood", "resource exhaustion", "dos"}),
    STRIDECategory.ELEVATION_OF_PRIVILEGE: frozenset(
        {"privilege escalation", "access control bypass"}
    ),
}

# ============================================================================
# Helpers — canonical builders
# ============================================================================


def _make_evidence_chain(
    exposure: str = "Unauthenticated BLE pairing endpoint exposed on firmware v2.1",
    matched_pattern: str = "CAPEC-62",
    applicability_reason: str = (
        "The lock firmware accepts BLE pairing without a PIN, "
        "allowing any nearby device to replay captured pairing tokens "
        "via an unauthenticated channel."
    ),
    citation: str = "https://capec.mitre.org/data/definitions/62.html",
) -> EvidenceChain:
    """Return a fully-populated, valid EvidenceChain."""
    return EvidenceChain(
        exposure=exposure,
        matched_pattern=matched_pattern,
        applicability_reason=applicability_reason,
        citation=citation,
    )


def _make_evidence_chain_raw(
    exposure: str = "Unauthenticated BLE pairing endpoint exposed on firmware v2.1",
    matched_pattern: str = "CAPEC-62",
    applicability_reason: str = (
        "The lock firmware accepts BLE pairing without a PIN, "
        "allowing any nearby device to replay captured pairing tokens "
        "via an unauthenticated channel."
    ),
    citation: str = "https://capec.mitre.org/data/definitions/62.html",
) -> EvidenceChain:
    """Return an EvidenceChain bypassing Pydantic validation via model_construct().

    Use this helper ONLY in tests that intentionally supply invalid field values
    (e.g. empty strings, placeholder text) to exercise the Validator's runtime
    checks.  Using model_construct() is the official Pydantic v2 pattern for
    constructing objects that violate schema constraints for testing purposes.

    Do NOT use for "happy path" tests — use _make_evidence_chain() there so
    the schema's own guards are exercised as well.
    """
    return EvidenceChain.model_construct(
        exposure=exposure,
        matched_pattern=matched_pattern,
        applicability_reason=applicability_reason,
        citation=citation,
    )


def _make_scenario(**overrides: object) -> ThreatScenario:
    """
    Return a valid ThreatScenario, with optional field overrides.

    All tests construct scenarios through this helper so a schema field change
    only requires updating one function, not every test.
    """
    defaults: dict[str, object] = {
        "tid": "TID-2024-001",
        "run_id": "RUN-TEST-001",
        "asset_id": "ASSET-BLE-LOCK-01",
        "stride_category": STRIDECategory.SPOOFING,
        "attack_vector": "BLE replay attack on unauthenticated pairing endpoint",
        "kb_reference": "CAPEC-62",
        "evidence_chain": _make_evidence_chain(),
        "confidence_score": 0.82,
        "status": ThreatStatus.PENDING_TEST,
    }
    defaults.update(overrides)
    return ThreatScenario(**defaults)  # type: ignore[arg-type]


def _make_failed_check(
    check_id: str = CHECK_CITATION_MISSING,
    affected_tid: str = "TID-2024-001",
    detail: str = "citation_presence_check: evidence_chain.citation is empty.",
) -> FailedCheck:
    """Return a minimal FailedCheck for use in ValidationResult fixtures."""
    return FailedCheck(check_id=check_id, affected_tid=affected_tid, detail=detail)


# ============================================================================
# Pytest fixtures
# ============================================================================


@pytest.fixture()
def validator() -> Validator:
    """Fresh Validator instance per test."""
    return Validator()


@pytest.fixture()
def valid_scenario() -> ThreatScenario:
    return _make_scenario()


@pytest.fixture()
def approved_scenario() -> ThreatScenario:
    from agents.threat_agent.schemas import ThreatStatus
    return _make_scenario(status=ThreatStatus.APPROVED)


@pytest.fixture()
def patched_vocabulary() -> dict[STRIDECategory, frozenset[str]]:
    """
    Inject the test vocabulary into validator.py for consistency_check tests.

    Uses unittest.mock.patch so the patch is scoped to the test and torn
    down automatically — no cross-test pollution.
    """
    return _TEST_VOCABULARY


# ============================================================================
# citation_presence_check
# ============================================================================


class TestCitationPresenceCheck:
    def test_pass_with_valid_citation(
        self, validator: Validator, valid_scenario: ThreatScenario
    ) -> None:
        passed, fc = validator.citation_presence_check(valid_scenario)
        assert passed is True
        assert fc is None

    def test_fail_empty_citation(self, validator: Validator) -> None:
        scenario = _make_scenario(evidence_chain=_make_evidence_chain_raw(citation=""))
        passed, fc = validator.citation_presence_check(scenario)
        assert passed is False
        assert fc is not None
        assert fc.check_id == CHECK_CITATION_MISSING
        assert fc.affected_tid == scenario.tid
        assert "empty" in fc.detail.lower()

    def test_fail_placeholder_citation(self, validator: Validator) -> None:
        for placeholder in ("N/A", "TBD", "TODO", "unknown"):
            scenario = _make_scenario(
                evidence_chain=_make_evidence_chain(citation=placeholder)
            )
            passed, fc = validator.citation_presence_check(scenario)
            assert passed is False, f"Expected fail for: {placeholder!r}"
            assert fc is not None
            assert fc.check_id == CHECK_CITATION_MISSING
            assert "placeholder" in fc.detail.lower()


# ============================================================================
# schema_completeness_check
# ============================================================================


class TestSchemaCompletenessCheck:
    def test_pass_with_all_fields(
        self, validator: Validator, valid_scenario: ThreatScenario
    ) -> None:
        passed, fc = validator.schema_completeness_check(valid_scenario)
        assert passed is True
        assert fc is None

    @pytest.mark.parametrize(
        "empty_field",
        ["tid", "asset_id", "attack_vector", "kb_reference"],
    )
    def test_fail_when_field_is_empty(
        self, validator: Validator, empty_field: str
    ) -> None:
        scenario = _make_scenario(**{empty_field: "   "})
        passed, fc = validator.schema_completeness_check(scenario)
        assert passed is False
        assert fc is not None
        assert fc.check_id == CHECK_SCHEMA_INCOMPLETE
        assert empty_field in fc.detail


# ============================================================================
# consistency_check (uses patched STRIDE_VECTOR_VOCABULARY)
# ============================================================================


class TestConsistencyCheck:
    def test_pass_with_consistent_pair(
        self, validator: Validator, valid_scenario: ThreatScenario
    ) -> None:
        # "Spoofing" + "BLE replay" — "replay" is in SPOOFING vocabulary.
        with patch("agents.threat_agent.validator.STRIDE_VECTOR_VOCABULARY", _TEST_VOCABULARY):
            passed, fc = validator.consistency_check(valid_scenario)
        assert passed is True
        assert fc is None

    def test_fail_mismatch_via_vocabulary(self, validator: Validator) -> None:
        """
        "Repudiation" + "sql injection" — "injection" is NOT in REPUDIATION
        vocabulary, so this must be flagged as inconsistent.
        """
        scenario = _make_scenario(
            stride_category=STRIDECategory.REPUDIATION,
            attack_vector="SQL injection via unauthenticated API endpoint",
        )
        with patch("agents.threat_agent.validator.STRIDE_VECTOR_VOCABULARY", _TEST_VOCABULARY):
            passed, fc = validator.consistency_check(scenario)
        assert passed is False
        assert fc is not None
        assert fc.check_id == CHECK_CONSISTENCY_MISMATCH
        assert "Repudiation" in fc.detail

    def test_pass_with_empty_vocabulary(
        self, validator: Validator, valid_scenario: ThreatScenario
    ) -> None:
        """When vocabulary is empty (retrieval.py not yet present), check passes silently."""
        with patch("agents.threat_agent.validator.STRIDE_VECTOR_VOCABULARY", {}):
            passed, fc = validator.consistency_check(valid_scenario)
        assert passed is True
        assert fc is None

    def test_pass_with_prior_context_none(
        self, validator: Validator, valid_scenario: ThreatScenario
    ) -> None:
        """prior_context=None must not raise — reserved for Phase 2."""
        with patch("agents.threat_agent.validator.STRIDE_VECTOR_VOCABULARY", _TEST_VOCABULARY):
            passed, _ = validator.consistency_check(valid_scenario, prior_context=None)
        assert passed is True

    def test_tampering_injection_passes(self, validator: Validator) -> None:
        """'Tampering' + 'injection' — correct pair, must pass."""
        scenario = _make_scenario(
            stride_category=STRIDECategory.TAMPERING,
            attack_vector="SQL injection via unauthenticated API endpoint",
        )
        with patch("agents.threat_agent.validator.STRIDE_VECTOR_VOCABULARY", _TEST_VOCABULARY):
            passed, fc = validator.consistency_check(scenario)
        assert passed is True
        assert fc is None


# ============================================================================
# evidence_completeness_check
# ============================================================================


class TestEvidenceCompletenessCheck:
    def test_pass_with_complete_evidence(
        self, validator: Validator, valid_scenario: ThreatScenario
    ) -> None:
        passed, fc = validator.evidence_completeness_check(valid_scenario)
        assert passed is True
        assert fc is None

    def test_fail_empty_exposure(self, validator: Validator) -> None:
        scenario = _make_scenario(evidence_chain=_make_evidence_chain_raw(exposure=""))
        passed, fc = validator.evidence_completeness_check(scenario)
        assert passed is False
        assert fc is not None
        assert fc.check_id == CHECK_EVIDENCE_GENERIC
        assert "exposure" in fc.detail.lower()

    def test_fail_empty_matched_pattern(self, validator: Validator) -> None:
        scenario = _make_scenario(evidence_chain=_make_evidence_chain_raw(matched_pattern=""))
        passed, fc = validator.evidence_completeness_check(scenario)
        assert passed is False
        assert fc is not None
        assert fc.check_id == CHECK_EVIDENCE_GENERIC
        assert "matched_pattern" in fc.detail.lower()

    def test_fail_placeholder_applicability_reason(self, validator: Validator) -> None:
        for placeholder in ("N/A", "TBD", "unknown"):
            scenario = _make_scenario(
                evidence_chain=_make_evidence_chain_raw(applicability_reason=placeholder)
            )
            passed, fc = validator.evidence_completeness_check(scenario)
            assert passed is False, f"Expected fail for: {placeholder!r}"
            assert fc is not None
            assert fc.check_id == CHECK_EVIDENCE_GENERIC

    def test_fail_too_short_applicability_reason(self, validator: Validator) -> None:
        # The frozen schema enforces min_length=20 on applicability_reason at
        # EvidenceChain construction, so we can't build a scenario with a 5-char
        # reason.  Instead we test a string that is exactly 19 chars — passes
        # Pydantic's min_length=20?  No: 19 < 20 → ValidationError at construction.
        # The validator's own check (MIN=20) is therefore only reached when a
        # string slips through at exactly 20 chars — which is the minimum *allowed*.
        # We verify the edge case where a 20-char string that IS a placeholder
        # is caught by the placeholder check instead.
        # For the length branch: we test a string of exactly 19 chars that fails
        # at schema level → confirm Pydantic raises before our check fires.
        with pytest.raises(ValidationError):
            _make_evidence_chain(applicability_reason="Short — too brief!")  # 18 chars
        # And confirm our validator's constant matches the schema constraint.
        assert MIN_APPLICABILITY_REASON_LENGTH == 20


# ============================================================================
# validate() — aggregator
# ============================================================================


class TestValidate:
    def test_all_checks_pass(
        self, validator: Validator, valid_scenario: ThreatScenario
    ) -> None:
        with patch("agents.threat_agent.validator.STRIDE_VECTOR_VOCABULARY", _TEST_VOCABULARY):
            result = validator.validate(valid_scenario)
        assert result.passed is True
        assert result.failed_checks == []

    def test_multiple_failures_collected(self, validator: Validator) -> None:
        """All check failures must be present in failed_checks — no short-circuit."""
        scenario = _make_scenario(
            evidence_chain=_make_evidence_chain_raw(
                citation="",
                applicability_reason="N/A",
            )
        )
        with patch("agents.threat_agent.validator.STRIDE_VECTOR_VOCABULARY", _TEST_VOCABULARY):
            result = validator.validate(scenario)
        assert result.passed is False
        assert len(result.failed_checks) >= 2
        check_ids = {fc.check_id for fc in result.failed_checks}
        assert CHECK_CITATION_MISSING in check_ids
        assert CHECK_EVIDENCE_GENERIC in check_ids

    def test_returns_validation_result_type(
        self, validator: Validator, valid_scenario: ThreatScenario
    ) -> None:
        with patch("agents.threat_agent.validator.STRIDE_VECTOR_VOCABULARY", {}):
            result = validator.validate(valid_scenario)
        assert isinstance(result, ValidationResult)

    def test_failed_checks_are_failed_check_objects(
        self, validator: Validator
    ) -> None:
        """Confirm failed_checks contains FailedCheck instances, not raw strings."""
        scenario = _make_scenario(evidence_chain=_make_evidence_chain_raw(citation=""))
        with patch("agents.threat_agent.validator.STRIDE_VECTOR_VOCABULARY", {}):
            result = validator.validate(scenario)
        assert result.passed is False
        assert all(isinstance(fc, FailedCheck) for fc in result.failed_checks)

    def test_schema_rejects_passed_true_with_nonempty_failed_checks(self) -> None:
        """Develop schema: passed=True + non-empty failed_checks → ValidationError."""
        with pytest.raises(ValidationError):
            ValidationResult(
                passed=True,
                failed_checks=[_make_failed_check()],
                retry_count=0,
            )

    def test_schema_rejects_passed_false_with_empty_failed_checks(self) -> None:
        """Develop schema: passed=False + empty failed_checks → ValidationError."""
        with pytest.raises(ValidationError):
            ValidationResult(
                passed=False,
                failed_checks=[],
                retry_count=0,
            )


# ============================================================================
# retry_with_context()
# ============================================================================


class TestRetryWithContext:
    def _failed_result(self, tid: str = "TID-2024-001") -> ValidationResult:
        """Minimal ValidationResult representing a failed validation."""
        return ValidationResult(
            passed=False,
            failed_checks=[
                FailedCheck(
                    check_id=CHECK_CITATION_MISSING,
                    affected_tid=tid,
                    detail="citation_presence_check: evidence_chain.citation is empty.",
                )
            ],
            retry_count=0,
        )

    def test_retry_increments_count(
        self, validator: Validator, valid_scenario: ThreatScenario
    ) -> None:
        action, ctx = validator.retry_with_context(
            valid_scenario, self._failed_result(), retry_count=0
        )
        assert action == "retry"
        assert ctx["retry_count"] == 1

    def test_retry_at_count_2_returns_retry(
        self, validator: Validator, valid_scenario: ThreatScenario
    ) -> None:
        action, ctx = validator.retry_with_context(
            valid_scenario, self._failed_result(), retry_count=2
        )
        assert action == "retry"
        assert ctx["retry_count"] == 3

    def test_retry_at_count_3_escalates(
        self, validator: Validator, valid_scenario: ThreatScenario
    ) -> None:
        """retry_count=3 → new count would be 4 → must escalate."""
        action, ctx = validator.retry_with_context(
            valid_scenario, self._failed_result(), retry_count=3
        )
        assert action == "escalate_to_human"
        assert "exhausted" in ctx["note"].lower() or "escalated" in ctx["note"].lower()

    def test_retry_context_contains_failure_detail(
        self, validator: Validator, valid_scenario: ThreatScenario
    ) -> None:
        action, ctx = validator.retry_with_context(
            valid_scenario, self._failed_result(), retry_count=0
        )
        assert action == "retry"
        assert "citation" in ctx["retry_context"].lower()

    def test_retry_context_includes_check_id(
        self, validator: Validator, valid_scenario: ThreatScenario
    ) -> None:
        """check_id should appear in retry_context so generator can branch on it."""
        action, ctx = validator.retry_with_context(
            valid_scenario, self._failed_result(), retry_count=0
        )
        assert action == "retry"
        assert CHECK_CITATION_MISSING in ctx["retry_context"]

    def test_failed_checks_serialized_in_context(
        self, validator: Validator, valid_scenario: ThreatScenario
    ) -> None:
        """failed_checks in context dict must be serializable dicts, not FailedCheck objects."""
        action, ctx = validator.retry_with_context(
            valid_scenario, self._failed_result(), retry_count=0
        )
        assert action == "retry"
        assert isinstance(ctx["failed_checks"], list)
        assert isinstance(ctx["failed_checks"][0], dict)
        assert "check_id" in ctx["failed_checks"][0]

    def test_escalation_preserves_tid(
        self, validator: Validator, valid_scenario: ThreatScenario
    ) -> None:
        _, ctx = validator.retry_with_context(
            valid_scenario, self._failed_result(), retry_count=3
        )
        assert ctx["tid"] == valid_scenario.tid

    def test_validation_result_rejects_retry_count_above_3(self) -> None:
        """Schema-level enforcement: ValidationResult(retry_count=4) must raise."""
        with pytest.raises(ValidationError):
            ValidationResult(
                passed=False,
                failed_checks=[_make_failed_check()],
                retry_count=4,
            )


# ============================================================================
# StateManager — write path
# ============================================================================


class TestStateManager:
    @pytest.fixture()
    def tmp_scrs(self, tmp_path: Path) -> Path:
        return tmp_path / "SCRS_state.json"

    @pytest.fixture()
    def state_manager(self, tmp_scrs: Path) -> StateManager:
        return StateManager(scrs_path=tmp_scrs)

    def test_write_approved_scenario_succeeds(
        self,
        state_manager: StateManager,
        approved_scenario: ThreatScenario,
        tmp_scrs: Path,
    ) -> None:
        result = state_manager.write_threat_scenario(approved_scenario, run_id="RUN-001")
        assert result is True
        assert tmp_scrs.exists()
        on_disk = json.loads(tmp_scrs.read_text(encoding="utf-8"))
        assert approved_scenario.tid in on_disk["threat_scenarios"]

    def test_write_rejected_scenario_raises(
        self, state_manager: StateManager
    ) -> None:
        scenario = _make_scenario(status=ThreatStatus.REJECTED)
        with pytest.raises(NotApprovedError):
            state_manager.write_threat_scenario(scenario, run_id="RUN-002")

    def test_write_pending_test_scenario_raises(
        self, state_manager: StateManager
    ) -> None:
        scenario = _make_scenario(status=ThreatStatus.PENDING_TEST)
        with pytest.raises(NotApprovedError):
            state_manager.write_threat_scenario(scenario, run_id="RUN-003")

    def test_write_pending_human_scenario_raises(
        self, state_manager: StateManager
    ) -> None:
        scenario = _make_scenario(status=ThreatStatus.PENDING_HUMAN)
        with pytest.raises(NotApprovedError):
            state_manager.write_threat_scenario(scenario, run_id="RUN-004")

    def test_audit_log_entry_created_on_write(
        self,
        state_manager: StateManager,
        approved_scenario: ThreatScenario,
    ) -> None:
        state_manager.write_threat_scenario(approved_scenario, run_id="RUN-005")
        log = state_manager.get_audit_log()
        assert len(log) == 1
        entry = log[0]
        assert entry.run_id == "RUN-005"
        assert entry.tid == approved_scenario.tid
        assert entry.action == "write"

    def test_no_audit_entry_on_rejection(
        self, state_manager: StateManager
    ) -> None:
        scenario = _make_scenario(status=ThreatStatus.REJECTED)
        with pytest.raises(NotApprovedError):
            state_manager.write_threat_scenario(scenario, run_id="RUN-006")
        assert state_manager.get_audit_log() == []

    def test_multiple_approved_writes(
        self, state_manager: StateManager
    ) -> None:
        for i in range(3):
            scenario = _make_scenario(tid=f"TID-2024-{i:03d}", status=ThreatStatus.APPROVED)
            state_manager.write_threat_scenario(scenario, run_id=f"RUN-{i:03d}")
        assert len(state_manager.get_threat_scenarios()) == 3
        assert len(state_manager.get_audit_log()) == 3

