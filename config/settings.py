"""
config/settings.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1  |  Application Configuration (Day-1 Scaffold)
──────────────────────────────────────────────────────────────────────────────
Loads all runtime configuration from environment variables (or a .env file)
using pydantic-settings.  No secret value is ever hardcoded here.

Usage
─────
    from config.settings import get_settings

    settings = get_settings()
    client = OpenAI(api_key=settings.OPENAI_API_KEY.get_secret_value())

Environment variable reference
───────────────────────────────
    OPENAI_API_KEY        — Required.  OpenAI API key (secret).
    ENVIRONMENT           — Optional.  "development" | "staging" | "production".
                            Defaults to "development".
    LOG_LEVEL             — Optional.  Python logging level string.
                            Defaults to "INFO".
    MAX_RETRY_COUNT       — Optional.  Max LLM retry attempts (capped at 3
                            by the ValidationResult schema).  Defaults to 3.

.env file
─────────
    Copy .env.example to .env and fill in real values.  The .env file is
    git-ignored — never commit it.

Ruff compliance
───────────────
    • Line length ≤ 88 chars.
    • Full annotations on all fields and functions (ANN rules).
    • No unused imports.
    • SecretStr used for OPENAI_API_KEY (S106 / no plaintext secrets).
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide configuration, sourced exclusively from environment.

    All fields map 1-to-1 to an environment variable of the same name
    (case-insensitive on most platforms).  pydantic-settings reads the .env
    file first, then real environment variables (env vars take precedence).

    Secrets policy (§2.10 of build plan):
        OPENAI_API_KEY is typed as SecretStr so it is never accidentally
        logged or serialised as plain text.  Access its value explicitly with
        ``.get_secret_value()`` only at the call site that needs it.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        # Extra fields in .env are ignored rather than raising an error,
        # so teammates can add convenience vars without breaking each other.
        extra="ignore",
        # Re-validate on assignment — ensures MAX_RETRY_COUNT stays ≤ 3
        # even if updated programmatically in tests.
        validate_default=True,
    )

    # ── Secrets ───────────────────────────────────────────────────────────────

    OPENAI_API_KEY: Annotated[
        SecretStr,
        Field(
            description=(
                "OpenAI API key.  Required — the application will not start "
                "if this variable is missing or empty.  Never log or print "
                "this value; use .get_secret_value() only at the call site."
            ),
        ),
    ]

    # ── Runtime environment ───────────────────────────────────────────────────

    ENVIRONMENT: Annotated[
        Literal["development", "staging", "production"],
        Field(
            default="development",
            description=(
                "Deployment environment.  Controls log verbosity defaults, "
                "debug middleware, and SCRS persistence behaviour.  "
                "Must be one of: development | staging | production."
            ),
        ),
    ]

    # ── Logging ───────────────────────────────────────────────────────────────

    LOG_LEVEL: Annotated[
        Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        Field(
            default="INFO",
            description=(
                "Python logging level for the application root logger.  "
                "In production, prefer INFO or WARNING.  DEBUG emits "
                "full prompt and KB-chunk logs — do not use in production."
            ),
        ),
    ]

    # ── Agent behaviour ───────────────────────────────────────────────────────

    MAX_RETRY_COUNT: Annotated[
        int,
        Field(
            default=3,
            ge=1,
            le=3,
            description=(
                "Maximum number of LLM retry attempts before the Threat Agent "
                "escalates to human review as a flagged failure.  "
                "Strictly capped at le=3 — mirrors the ValidationResult schema "
                "constraint so the two values are always consistent.  "
                "Reduce to 1 in CI to keep test runs fast."
            ),
        ),
    ]

    # TODO (Week 2): add further settings as new modules are wired up, e.g.:
    #   OPENAI_MODEL: str = "gpt-4o"
    #   OPENAI_TEMPERATURE: float = Field(default=0.1, ge=0.0, le=1.0)
    #   OPENAI_REQUEST_TIMEOUT_SECONDS: int = Field(default=30, ge=5, le=120)
    #   OPENAI_MAX_TOKENS_PER_RUN: int = 8000
    #   FAISS_INDEX_PATH: Path = Path("kb/data/faiss_index")
    #   SCRS_STATE_FILE: Path = Path("scrp/SCRS_state.json")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the singleton Settings instance, cached after the first call.

    Using lru_cache(maxsize=1) means the .env file is read exactly once
    per process lifetime.  In tests, call ``get_settings.cache_clear()``
    before patching environment variables to force a fresh load.

    Returns:
        The application-wide Settings instance.

    Raises:
        ValidationError: If a required field (e.g. OPENAI_API_KEY) is missing
            or any field fails its constraint — the application fails closed
            rather than starting with a broken configuration.
    """
    return Settings()
