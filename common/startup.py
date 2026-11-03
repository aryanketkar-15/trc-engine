"""What a deployment needs around the agents: safe settings, health checks, limits, request IDs."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, Request, Response
from fastapi.responses import JSONResponse

from config.settings import get_settings

logger = logging.getLogger(__name__)

DEFAULT_API_KEY = "trc-dev-secret-key"
DEFAULT_DB_PASSWORD = "trc_password"  # noqa: S105

ops_router = APIRouter(tags=["operations"])


def production_problems(settings: Any) -> list[str]:  # noqa: ANN401
    """Reasons this configuration must not serve production."""
    problems = []
    users = getattr(settings, "TRC_USERS_FILE", None)
    if not users:
        problems.append("TRC_USERS_FILE is not set: decisions would not carry a verified identity")
    elif not Path(users).exists():
        problems.append(f"TRC_USERS_FILE points to a missing file: {users}")
    if settings.THREAT_AGENT_API_KEY.get_secret_value() == DEFAULT_API_KEY:
        problems.append("THREAT_AGENT_API_KEY still has the development default")
    if not getattr(settings, "AUDIT_HMAC_KEY", None):
        problems.append("AUDIT_HMAC_KEY is not set: the audit chain would not be keyed")
    if not getattr(settings, "REQUIRE_AUTH_FOR_READS", False):
        problems.append("REQUIRE_AUTH_FOR_READS is off: threat data would be readable by anyone")
    if DEFAULT_DB_PASSWORD in str(settings.DATABASE_URL):
        problems.append("DATABASE_URL uses the development database password")
    return problems


def check_production_settings(settings: Any) -> None:  # noqa: ANN401
    """Refuse to start in production with development settings."""
    if settings.ENVIRONMENT != "production":
        return
    problems = production_problems(settings)
    if problems:
        raise RuntimeError("Refusing to start in production: " + "; ".join(problems))


@ops_router.get("/health")
def health() -> dict[str, str]:
    """Liveness: the process is up."""
    return {"status": "ok"}


@ops_router.get("/ready")
def ready(response: Response) -> dict[str, Any]:
    """Readiness: everything a request depends on can be reached. Reveals no configuration."""
    from agents.compliance_agent.engine import Rules
    from agents.risk_agent.engine import Ratings
    from common.db import get_db_connection
    from common.kb_version import kb_fingerprint
    from scrp.state_manager import StateManager

    checks: dict[str, Any] = {}

    def attempt(name: str, action: Callable[[], Any]) -> None:
        try:
            checks[name] = action() or "ok"
        except Exception as exc:
            logger.warning("readiness check %s failed: %s", name, exc)
            checks[name] = "failed"

    def database() -> str:
        with get_db_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1;")
        return "ok"

    def audit() -> str:
        report = StateManager(Path(get_settings().SCRS_STATE_PATH)).verify_integrity()
        return "ok" if report["ok"] else "failed"

    attempt("database", database)
    attempt("knowledge_base", kb_fingerprint)
    attempt("rating_tables", lambda: Ratings.load().version)
    attempt("rule_base", lambda: Rules.load().version)
    attempt("audit_chain", audit)
    healthy = all(v not in ("failed", None) for v in checks.values())
    if not healthy:
        response.status_code = 503
    return {"status": "ready" if healthy else "not_ready", "checks": checks}


def install_handlers(app: FastAPI) -> None:
    """Request size limit, request IDs, and clear errors for shared-state problems."""
    from scrp.state_manager import ConcurrentWriteError, SCRSCorruptError

    limit = int(getattr(get_settings(), "MAX_REQUEST_BYTES", 2_000_000))

    @app.middleware("http")
    async def _request_guard(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            return JSONResponse(
                {"detail": f"Request body is larger than {limit} bytes."},
                status_code=413,
                headers={"X-Request-ID": request_id},
            )
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    @app.exception_handler(ConcurrentWriteError)
    async def _conflict(_request: Request, exc: ConcurrentWriteError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(SCRSCorruptError)
    async def _corrupt(_request: Request, exc: SCRSCorruptError) -> JSONResponse:
        logger.error("shared state is damaged: %s", exc)
        return JSONResponse(
            {"detail": "The shared state cannot be read. An operator must restore it."},
            status_code=503,
        )
