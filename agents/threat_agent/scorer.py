"""
agents/threat_agent/scorer.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1: Threat Agent  |  Evidence & Confidence Scorer (Chetan)
──────────────────────────────────────────────────────────────────────────────
Pipeline position:
    generator.py → scorer.py → validator.py (Shriraj)

Responsibility:
    Calculates and assigns confidence scores for ThreatScenario instances.
    Extracted from inline logic in generator.py._make_scenario().

Current Scoring Logic (Preliminary Baseline):
    Computes confidence score from the mean retrieval_score of AttackPath steps:
        preliminary_score = mean(step.retrieval_score for step in path.steps)
    Clamped strictly to [0.0, 1.0].

Future Expansion (Section 2.6 Multi-Signal Formula):
    Once multi-pass consistency and validator signals are integrated:
        confidence = (
            0.4 * retrieval_match_strength
          + 0.4 * self_consistency
          + 0.2 * evidence_completeness
        )

Defensive Design & Invariants:
    - Guaranteed valid range: Always returns a float in [0.0, 1.0].
    - Missing/Empty Input Handling: Returns DEFAULT_FALLBACK_CONFIDENCE (0.0)
      if path is None, steps are empty, or no scores are available.
    - Defensive Parsing: Skips invalid/non-numeric retrieval scores safely
      rather than crashing or raising unhandled exceptions.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agents.threat_agent.schemas import AttackPath, KBCandidate, ThreatScenario

logger = logging.getLogger(__name__)

#: Default fallback confidence score when inputs are empty, missing, or invalid
DEFAULT_FALLBACK_CONFIDENCE: float = 0.0

#: Threshold below which a confidence score is considered low-confidence (Section 2.6)
LOW_CONFIDENCE_THRESHOLD: float = 0.4


def compute_confidence_score(
    path: AttackPath | None = None,
    *,
    steps: Sequence[KBCandidate | Any] | None = None,
) -> float:
    """Compute confidence score for an attack path or sequence of steps.

    Extracted from inline generator.py logic. Computes the arithmetic mean
    of step retrieval scores, clamped to [0.0, 1.0].

    Args:
        path: Optional AttackPath containing steps with retrieval scores.
        steps: Optional direct sequence of steps/candidates. If provided,
            takes precedence over path.steps.

    Returns:
        float: Clamped confidence score in [0.0, 1.0]. Returns 0.0 if no
        valid steps or scores are available.
    """
    candidate_steps: Sequence[Any] | None = None
    if steps is not None:
        candidate_steps = steps
    elif path is not None and hasattr(path, "steps"):
        candidate_steps = path.steps

    if not candidate_steps:
        return DEFAULT_FALLBACK_CONFIDENCE

    valid_scores: list[float] = []
    for step in candidate_steps:
        raw_score = getattr(step, "retrieval_score", None)
        if raw_score is None and isinstance(step, (int, float)):
            raw_score = step
        elif raw_score is None and isinstance(step, dict):
            raw_score = step.get("retrieval_score")

        if raw_score is not None:
            try:
                valid_scores.append(float(raw_score))
            except (ValueError, TypeError):
                logger.warning(
                    "scorer_invalid_retrieval_score",
                    extra={"raw_score": repr(raw_score)},
                )
                continue

    if not valid_scores:
        return DEFAULT_FALLBACK_CONFIDENCE

    raw_mean = sum(valid_scores) / len(valid_scores)
    # Clamp defensively to [0.0, 1.0]
    return max(0.0, min(1.0, float(raw_mean)))


def score_scenario(
    scenario: ThreatScenario,
    path: AttackPath | None = None,
) -> ThreatScenario:
    """Apply confidence score to a ThreatScenario, returning an updated copy.

    Args:
        scenario: The immutable ThreatScenario to score.
        path: Optional AttackPath originating this scenario.

    Returns:
        ThreatScenario: A new frozen model instance with updated confidence_score.
    """
    score = compute_confidence_score(path)
    return scenario.model_copy(update={"confidence_score": score})
