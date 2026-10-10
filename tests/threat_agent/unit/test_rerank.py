"""Domain tags, rerank scoring, and its wiring into retrieval.fetch_candidates."""

from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any, ClassVar

import numpy as np
import pytest

from agents.threat_agent import retrieval as rv
from agents.threat_agent.rerank import RerankParams, infer_asset_tags, rerank_score
from agents.threat_agent.schemas import AssetModel, DFDContext, ThreatAgentInput
from common.domain_tags import tags_for_text


def _asset(**over: Any) -> AssetModel:
    base: dict[str, Any] = {
        "asset_id": "AS-1", "name": "Telematics API", "asset_type": "REST API",
        "dfd_context": DFDContext(interfaces=["HTTPS", "MQTT"], trust_zone="external"),
        "device_config": {"auth": "api-key", "rate_limit": "none"},
    }
    base.update(over)
    return AssetModel(**base)


class TestTags:
    def test_text_tags(self) -> None:
        assert "hardware" in tags_for_text("Hardware Fault Injection on the chip")
        assert {"wireless", "firmware"} <= tags_for_text("BLE OTA firmware update")
        assert tags_for_text("") == frozenset()

    def test_asset_tags_from_interfaces_and_config(self) -> None:
        tags = infer_asset_tags(_asset())
        assert {"web", "credentials"} <= tags
        assert "hardware" not in tags

    def test_secure_element_asset_is_hardware(self) -> None:
        tags = infer_asset_tags(_asset(name="Secure Element", asset_type="key storage", device_config={}))
        assert "hardware" in tags


class TestRerankScore:
    def test_noop_params_return_similarity(self) -> None:
        p = RerankParams()
        assert p.is_noop
        assert rerank_score(0.5, {"web"}, {"web"}, p) == 0.5

    def test_boost_is_capped_at_two_overlaps(self) -> None:
        p = RerankParams(tag_boost=0.1)
        assert rerank_score(0.5, {"a", "b", "c"}, {"a", "b", "c"}, p) == pytest.approx(0.7)

    def test_hardware_penalty_only_for_non_hardware_assets(self) -> None:
        p = RerankParams(hardware_penalty=0.2)
        assert rerank_score(0.5, {"web"}, {"hardware"}, p) == pytest.approx(0.3)
        assert rerank_score(0.5, {"firmware"}, {"hardware"}, p) == 0.5


class _Cur:
    def __init__(self, rows: list[tuple[dict[str, Any], float]]) -> None:
        self._rows = rows

    def __enter__(self) -> _Cur:
        return self

    def __exit__(self, *a: object) -> bool:
        return False

    def execute(self, *a: object, **k: object) -> None:
        return None

    def fetchall(self) -> list[tuple[dict[str, Any], float]]:
        return self._rows


class _Conn:
    def __init__(self, rows: list[tuple[dict[str, Any], float]]) -> None:
        self._rows = rows

    def cursor(self, *a: object, **k: object) -> _Cur:
        return _Cur(self._rows)


def _meta(pid: str, tags: list[str] | None) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "pattern_id": pid, "source": "CWE", "title": pid, "description": "d",
        "stride_hint": None, "mitre_tactics": [],
    }
    if tags is not None:
        meta["domain_tags"] = tags
    return meta


def _run(monkeypatch: pytest.MonkeyPatch, rows: list[tuple[dict[str, Any], float]],
         boost: float, penalty: float) -> list[str]:
    @contextmanager
    def _fake_conn() -> Any:
        yield _Conn(rows)

    monkeypatch.setattr(rv, "get_db_connection", _fake_conn)
    monkeypatch.setattr("pgvector.psycopg.register_vector", lambda c: None)
    monkeypatch.setattr(rv, "_get_encoder", lambda *_: SimpleNamespace(
        encode=lambda texts, **k: np.zeros((len(texts), 384), dtype=np.float32)))
    monkeypatch.setattr(rv, "get_settings", lambda: SimpleNamespace(
        RETRIEVAL_RERANK=True, RETRIEVAL_RERANK_BOOST=boost,
        RETRIEVAL_RERANK_HW_PENALTY=penalty, RETRIEVAL_POOL_SIZE=60))
    plan = rv.build_retrieval_plan(
        ThreatAgentInput(run_id="R", use_case="Telematics API threat test run", system_model="{}",
                         assets=[_asset()]), top_k=2)
    return [c.pattern_id for c in rv.fetch_candidates(plan)]


class TestFetchCandidatesWiring:
    ROWS: ClassVar[list[tuple[dict[str, Any], float]]] = [(_meta("HW-ONLY", ["hardware"]), 0.60), (_meta("WEB-RELEVANT", ["web"]), 0.55),
            (_meta("OTHER", ["mobile"]), 0.50)]

    def test_rerank_demotes_hardware_pattern_for_software_asset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert _run(monkeypatch, self.ROWS, boost=0.02, penalty=0.10)[0] == "WEB-RELEVANT"

    def test_noop_params_keep_pure_similarity_order(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert _run(monkeypatch, self.ROWS, boost=0.0, penalty=0.0)[0] == "HW-ONLY"

    def test_untagged_kb_is_unaffected_even_with_rerank_on(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rows = [(_meta("A", None), 0.60), (_meta("B", None), 0.55)]
        assert _run(monkeypatch, rows, boost=0.1, penalty=0.5) == ["A", "B"]
