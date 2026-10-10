"""The application default must be the full knowledge base, not the 24-entry seed KB."""

from __future__ import annotations

import pytest

from config.settings import Settings


def test_default_database_is_the_full_knowledge_base(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("KB_DATA_DIR", "kb/data")
    assert Settings(_env_file=None).DATABASE_URL.endswith("/trc_engine_fullkb")


def test_test_suite_runs_on_the_seed_database() -> None:
    from config.settings import get_settings

    get_settings.cache_clear()
    assert get_settings().DATABASE_URL.rsplit("/", 1)[-1] == "trc_engine"
