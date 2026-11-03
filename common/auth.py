"""Who is calling the API, and what they may do.

Named users live in a JSON file (``TRC_USERS_FILE``) that stores only key hashes; create them with
``scripts/manage_users.py``. Roles: viewer reads, analyst also runs the agents, approver also makes
the human decisions. Without a users file the single shared key works as before, and a name passed
in ``X-Reviewer`` is recorded as unverified. Production refuses to start in that mode (main.py).
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, Header, HTTPException, status

from config.settings import get_settings

ROLES = ("viewer", "analyst", "approver")


@dataclass(frozen=True)
class Principal:
    """The authenticated caller."""

    name: str | None
    role: str
    verified: bool

    @property
    def label(self) -> str:
        if self.verified:
            return f"{self.name}"
        return f"{self.name} (unverified)" if self.name else "shared-key (unverified)"


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def load_users(path: Path) -> list[dict[str, Any]]:
    return list(json.loads(path.read_text(encoding="utf-8")).get("users", []))


def authenticate(api_key: str | None, reviewer: str | None = None) -> Principal | None:
    """Return the caller for this key, or None when the key is missing or wrong."""
    if not api_key:
        return None
    settings = get_settings()
    users_file = getattr(settings, "TRC_USERS_FILE", None)
    if users_file:
        hashed = hash_key(api_key)
        for user in load_users(Path(users_file)):
            if secrets.compare_digest(str(user.get("key_sha256", "")), hashed):
                return Principal(name=str(user["name"]), role=str(user["role"]), verified=True)
        return None
    expected = settings.THREAT_AGENT_API_KEY.get_secret_value()
    if secrets.compare_digest(api_key, expected):
        return Principal(name=(reviewer or "").strip() or None, role="approver", verified=False)
    return None


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Missing or invalid API key.",
        headers={"WWW-Authenticate": "ApiKey"},
    )


def current_principal(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    x_reviewer: Annotated[str | None, Header(alias="X-Reviewer")] = None,
) -> Principal:
    principal = authenticate(x_api_key, x_reviewer)
    if principal is None:
        raise _unauthorized()
    return principal


def _require(principal: Principal, *roles: str) -> Principal:
    if principal.role not in roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{principal.role}' may not do this; needs one of {list(roles)}.",
        )
    return principal


def require_writer(principal: Annotated[Principal, Depends(current_principal)]) -> Principal:
    """May run the agents."""
    return _require(principal, "analyst", "approver")


def require_approver(principal: Annotated[Principal, Depends(current_principal)]) -> Principal:
    """May make the human decisions that reach the shared state."""
    return _require(principal, "approver")


def read_gate(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> None:
    """Protect read endpoints when ``REQUIRE_AUTH_FOR_READS`` is on."""
    if getattr(get_settings(), "REQUIRE_AUTH_FOR_READS", False) and authenticate(x_api_key) is None:
        raise _unauthorized()


def actor_label(
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    x_reviewer: Annotated[str | None, Header(alias="X-Reviewer")] = None,
) -> str | None:
    """Audit name for this request; never raises, because auth is enforced elsewhere."""
    principal = authenticate(x_api_key, x_reviewer)
    return principal.label if principal else None


def decided_by(principal: Principal, typed_name: str) -> str:
    """The name recorded on a decision: the logged-in user, never a name they typed."""
    return principal.label if principal.verified else typed_name
