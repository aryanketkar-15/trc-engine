"""A product with several use cases: one threat run per use case.

The company's feedback (12 Oct 2026): an application has many use cases (for a smart lock:
issue a credential, access the lock, delete a lost credential ...).  Each use case has its own
description and its own data-flow diagram, and the list of use cases must be visible.  We
therefore keep the assets of a product once and describe, per use case, which assets take part
and what its system model is.  :func:`expand_project` turns that into one
:class:`ThreatAgentInput` per use case, so every use case is analysed, reviewed and stored
separately (results are keyed by ``project_id`` + ``use_case_id``).
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Annotated, Any

from pydantic import BaseModel, Field, model_validator

from threat_schemas import AssetModel, ThreatAgentInput


class UseCaseSpec(BaseModel):
    """One use case of the product."""

    use_case_id: Annotated[str, Field(min_length=1, description="e.g. 'UC-01'")]
    title: Annotated[str, Field(min_length=3, description="e.g. 'Remote unlock by homeowner'")]
    description: Annotated[
        str, Field(min_length=10, description="What happens in this use case, in plain words.")
    ]
    system_model: Annotated[
        str,
        Field(
            min_length=1,
            description="This use case's data-flow description (trust boundaries, flows).",
        ),
    ]
    asset_ids: Annotated[
        list[str],
        Field(
            default_factory=list,
            description="Assets that take part in this use case. Empty means all assets.",
        ),
    ]


class ProjectInput(BaseModel):
    """A product: its assets, once, and the list of its use cases."""

    project_id: Annotated[str, Field(min_length=1)]
    product_name: Annotated[str, Field(min_length=1)]
    assets: Annotated[list[AssetModel], Field(min_length=1)]
    use_cases: Annotated[list[UseCaseSpec], Field(min_length=1)]
    kb_snapshot_version: str = "latest"

    @model_validator(mode="after")
    def _consistent(self) -> ProjectInput:
        ids = [u.use_case_id for u in self.use_cases]
        if len(set(ids)) != len(ids):
            raise ValueError("use_case_id values must be unique within a project")
        known = {a.asset_id for a in self.assets}
        if len(known) != len(self.assets):
            raise ValueError("asset_id values must be unique within a project")
        for u in self.use_cases:
            missing = [a for a in u.asset_ids if a not in known]
            if missing:
                raise ValueError(f"{u.use_case_id} refers to unknown assets: {missing}")
        return self


def is_project_payload(data: object) -> bool:
    """True when a JSON document is in the multi-use-case project format."""
    return isinstance(data, dict) and "use_cases" in data and "project_id" in data


def expand_project(project: ProjectInput, run_suffix: str | None = None) -> list[ThreatAgentInput]:
    """One ready-to-run input per use case (same order as ``project.use_cases``)."""
    suffix = run_suffix or uuid.uuid4().hex[:6].upper()
    by_id = {a.asset_id: a for a in project.assets}
    inputs: list[ThreatAgentInput] = []
    for u in project.use_cases:
        assets = [by_id[i] for i in u.asset_ids] if u.asset_ids else list(project.assets)
        inputs.append(
            ThreatAgentInput(
                run_id=f"{project.project_id}-{u.use_case_id}-{suffix}",
                project_id=project.project_id,
                use_case_id=u.use_case_id,
                use_case=f"{u.title}. {u.description}",
                system_model=u.system_model,
                assets=assets,
                kb_snapshot_version=project.kb_snapshot_version,
            )
        )
    return inputs


def load_inputs(path: Path, run_suffix: str | None = None) -> list[ThreatAgentInput]:
    """Read a project file. Accepts both formats and always returns a list of runs.

    * single-run format (``ThreatAgentInput``): returns one input
    * project format (``ProjectInput``): returns one input per use case
    """
    data: Any = json.loads(path.read_text(encoding="utf-8"))
    if is_project_payload(data):
        return expand_project(ProjectInput.model_validate(data), run_suffix)
    return [ThreatAgentInput.model_validate(data)]
