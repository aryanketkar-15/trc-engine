"""
tests/demo/test_cli_smoke.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1: Threat Agent Demonstration Smoke Test
──────────────────────────────────────────────────────────────────────────────
Smoke tests for scripts/demo_cli.py to ensure the live demonstration path runs
end-to-end without raising exceptions on both domain fixtures.
"""

from __future__ import annotations

from collections.abc import Callable
from unittest.mock import patch

import pytest

from agents.threat_agent.attack_chain import build_paths, build_single_step_path
from agents.threat_agent.generator import generate_scenarios
from agents.threat_agent.retrieval import build_retrieval_plan, fetch_candidates
from agents.threat_agent.schemas import (
    RetrievalPlan,
    ThreatAgentInput,
    ValidationResult,
)
from agents.threat_agent.validator import Validator
from scripts.demo_cli import (
    _mock_llm_fallback,
    load_infusion_pump_input,
    load_smart_door_lock_input,
)


@pytest.mark.parametrize(
    "loader, fixture_name",
    [
        (load_smart_door_lock_input, "smart_door_lock"),
        (load_infusion_pump_input, "infusion_pump"),
    ],
)
def test_demo_cli_pipeline_smoke(
    loader: Callable[[], ThreatAgentInput], fixture_name: str
) -> None:
    """Smoke test full CLI demonstration pipeline for both domain fixtures."""
    # 1. Load Fixture
    agent_input: ThreatAgentInput = loader()
    assert agent_input.run_id is not None
    assert len(agent_input.assets) > 0

    # 2. Stage 1: Build Retrieval Plan
    plan: RetrievalPlan = build_retrieval_plan(agent_input, top_k=5)
    assert plan.run_id == agent_input.run_id
    assert len(plan.queries) == len(agent_input.assets)

    # 3. Stage 2: FAISS Retrieval
    candidates = fetch_candidates(plan)
    assert len(candidates) > 0

    # 4. Stage 3: Attack Chaining
    try:
        paths = build_paths(candidates, agent_input)
    except NotImplementedError:
        paths = [build_single_step_path(c) for c in candidates]
    assert len(paths) > 0

    # 5. Stage 4: Scenario Generation (Deterministic Fixture)
    try:
        scenarios = generate_scenarios(paths, agent_input)
    except NotImplementedError:
        with patch(
            "agents.threat_agent.generator._call_llm",
            side_effect=_mock_llm_fallback,
        ):
            scenarios = generate_scenarios(paths, agent_input)
    assert len(scenarios) > 0

    # 6. Stage 5: Validation
    v_result: ValidationResult = Validator().validate(scenarios[0])
    assert isinstance(v_result, ValidationResult)
    assert isinstance(v_result.passed, bool)
