"""
main.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1  |  FastAPI Application Entrypoint (Day-1 Scaffold)
──────────────────────────────────────────────────────────────────────────────
Mounts the Threat Agent router and configures app-level middleware and
startup/shutdown lifecycle hooks.

Run locally:
    uvicorn main:app --reload

The /docs (Swagger UI) and /redoc endpoints are available in development
and staging; disabled in production (security best practice).
"""

from __future__ import annotations

import logging
import logging.config
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from agents.threat_agent.router import router as threat_agent_router
from config.settings import get_settings

settings = get_settings()

# ──────────────────────────────────────────────────────────────────────────────
# Logging bootstrap
# ──────────────────────────────────────────────────────────────────────────────
# TODO (Week 2): replace with structured JSON logging from common/logging.py
# per §2.9 of the build plan.
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Lifespan (startup / shutdown hooks)
# ──────────────────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:  # noqa: ARG001
    """FastAPI lifespan context manager.

    Startup tasks run before ``yield``; shutdown tasks run after.

    TODO (Week 2): add:
        - FAISS index warm-up (retrieval.py)
        - SCRS state file validation (scrp/state_manager.py)
        - LLM client health check (common/llm_client.py)
    """
    logger.info(
        "TRC Engine starting up",
        extra={"environment": settings.ENVIRONMENT, "log_level": settings.LOG_LEVEL},
    )
    yield
    logger.info("TRC Engine shutting down")


# ──────────────────────────────────────────────────────────────────────────────
# Application factory
# ──────────────────────────────────────────────────────────────────────────────

_is_prod = settings.ENVIRONMENT == "production"

app = FastAPI(
    title="TRC Engine — Threat Agent API",
    description=(
        "Phase 1 of the TRC Engine (Threat–Risk–Compliance reasoning system).  "
        "Accepts a system model and asset list, runs the SCRP threat analysis "
        "loop, and writes validated, human-approved threat scenarios to the SCRS."
    ),
    version="0.1.0",
    lifespan=lifespan,
    # Disable interactive docs in production (§5 coding standards — no exposure
    # of internal API schema to untrusted networks).
    docs_url=None if _is_prod else "/docs",
    redoc_url=None if _is_prod else "/redoc",
    openapi_url=None if _is_prod else "/openapi.json",
)

# ──────────────────────────────────────────────────────────────────────────────
# Routers
# ──────────────────────────────────────────────────────────────────────────────

app.include_router(threat_agent_router, prefix="/api/v1")

# TODO (Week 2): mount additional routers as they are built:
#   from common.middleware import PiiRedactionMiddleware
#   app.add_middleware(PiiRedactionMiddleware)
