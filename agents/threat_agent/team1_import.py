# ruff: noqa: E501, ANN401
"""Read Team 1's approved results and turn them into Threat Agent inputs.

Team 1's pipeline (item definition, use case, modelling, asset) ends with an approved asset table per
use case. This module reads those artefacts, from an exported file or from their HTTP API, and builds
one ``ThreatAgentInput`` per use case. It uses plain dictionaries only: nothing of Team 1's code is
imported, so the two projects stay independent (they run on different Python and package versions).

Rules that follow from how both sides work:

* Only **approved** artefacts are used. An artefact must arrive with its approval status, because the
  content alone does not say whether anyone approved it.
* Team 1 hands over only when **every** use case has an approved asset table (their ``handoff_ready``).
* Their asset numbers (``AS-1`` ...) belong to one use case's table, so each use case keeps its own list.
* A property Team 1 has not decided is not turned into "No": it is recorded in ``device_config``.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agents.threat_agent.project import ProjectInput, UseCaseSpec
from agents.threat_agent.schemas import (
    AssetModel,
    DFDContext,
    SecurityAttributes,
    ThreatAgentInput,
)

APPROVED = "approved"
NO_MODEL = "No data-flow model was supplied for this use case."
#: Only real catalogue identifiers are passed on as hints; anything else is not evidence.
_CATALOGUE_ID = re.compile(r"CAPEC-\d+|CWE-\d+|T\d{4}(\.\d{3})?")
_PROPERTIES = (
    ("C", "confidentiality"),
    ("I", "integrity"),
    ("A", "availability"),
    ("Auth", "authenticity"),
)


class Team1ImportError(ValueError):
    """The Team 1 data cannot be used as it is. The message says what to fix."""


# ------------------------------------------------------------------ artefacts


@dataclass(frozen=True)
class Source:
    """Which Team 1 artefact a value came from (the backward trace)."""

    artefact_id: str | None
    version: int | None
    approved_by: str | None
    approved_at: str | None

    def label(self) -> str:
        return f"{self.artefact_id or 'unknown'}@v{self.version if self.version else '?'}"


def unwrap(
    payload: Any,
    label: str,
    *,
    allow_unapproved: bool = False,
) -> tuple[dict[str, Any], Source]:
    """Content and provenance of one artefact.

    Accepts the API answer (``{"step": ..., "artefact": {...}}``), the artefact itself, or, only with
    ``allow_unapproved``, bare content whose approval cannot be checked.
    """
    if not isinstance(payload, dict):
        raise Team1ImportError(f"{label}: expected an object, got {type(payload).__name__}")
    artefact = payload.get("artefact", payload)
    if isinstance(artefact, dict) and "content" in artefact and "approval_status" in artefact:
        status = str(artefact.get("approval_status")).lower()
        if status != APPROVED and not allow_unapproved:
            raise Team1ImportError(
                f"{label} is '{status}', not approved. Team 2 only works on approved artefacts."
            )
        content = artefact["content"]
        if not isinstance(content, dict):
            raise Team1ImportError(f"{label}: the artefact has no content")
        source = Source(
            artefact_id=artefact.get("artefact_id") or artefact.get("id"),
            version=artefact.get("version"),
            approved_by=artefact.get("approved_by"),
            approved_at=artefact.get("approved_at"),
        )
        return content, source
    if not allow_unapproved:
        raise Team1ImportError(
            f"{label} has no approval status, so approval cannot be checked. Export it with its "
            "artefact wrapper (the API's 'artefact' object), or pass allow_unapproved for test data."
        )
    return payload, Source(
        artefact_id=payload.get("id"),
        version=payload.get("version"),
        approved_by=None,
        approved_at=None,
    )


# ------------------------------------------------------------------ mapping helpers


def _text(value: Any) -> str:
    return str(getattr(value, "value", value) or "").strip()


def _boundary_names(diagrams: dict[str, Any]) -> dict[str, str]:
    return {
        str(b["id"]): str(b.get("name") or b["id"]) for b in diagrams.get("trust_boundaries", [])
    }


def _boundary_of(diagrams: dict[str, Any], element_id: str) -> str | None:
    for entity in diagrams.get("entities", []):
        if entity.get("id") == element_id and entity.get("trust_boundary"):
            return str(entity["trust_boundary"])
    for boundary in diagrams.get("trust_boundaries", []):
        if element_id in boundary.get("members", []):
            return str(boundary["id"])
    return None


def _distinct_flows(flows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop a flow when an earlier one has the same source, destination, protocol and payload.

    Team 1's modelling output can hold one message twice under two ids (for example a store
    "queries" and "returns" pair from separate answers). The first one's id and name are kept.
    """
    seen: set[tuple[Any, ...]] = set()
    kept: list[dict[str, Any]] = []
    for flow in flows:
        key = (
            flow.get("source"),
            flow.get("destination"),
            flow.get("protocol"),
            tuple(flow.get("payload_fields") or []),
        )
        if key not in seen:
            seen.add(key)
            kept.append(flow)
    return kept


def _touching(
    diagrams: dict[str, Any], elements: list[str]
) -> tuple[list[dict[str, Any]], list[str]]:
    """Flows an asset takes part in, and the trust zones around it."""
    flows = diagrams.get("data_flows", [])
    names = _boundary_names(diagrams)
    found: list[dict[str, Any]] = []
    zones: list[str] = []
    for element in elements:
        direct = [f for f in flows if f.get("id") == element]
        if direct:
            found += direct
        else:
            found += [f for f in flows if element in (f.get("source"), f.get("destination"))]
            zone = _boundary_of(diagrams, element)
            if zone:
                zones.append(names.get(zone, zone))
    for flow in found:
        start, end = flow.get("from_boundary"), flow.get("to_boundary")
        if start and end and start != end:
            zones.append(f"{names.get(start, start)} to {names.get(end, end)}")
        else:
            zones += [names.get(b, b) for b in (start, end) if b]
    unique_flows = _distinct_flows(list({f["id"]: f for f in found}.values()))
    return unique_flows, list(dict.fromkeys(zones))


def _verdicts(asset: dict[str, Any]) -> tuple[SecurityAttributes, list[str]]:
    """Four booleans, plus the properties Team 1 has not decided."""
    stated = asset.get("security_attributes") or {}
    accepted = {_text(a) for a in asset.get("attributes", [])}
    flags: dict[str, bool] = {}
    undecided: list[str] = []
    for code, field_name in _PROPERTIES:
        verdict = stated.get(field_name) if isinstance(stated, dict) else None
        if verdict is None:
            flags[field_name] = code in accepted
            applies = code != "Auth" or bool(asset.get("is_message"))
            if code not in accepted and applies:
                undecided.append(code)
        else:
            flags[field_name] = bool(verdict)
    return SecurityAttributes(**flags), undecided


def _damage(asset: dict[str, Any]) -> str:
    parts = []
    for item in asset.get("damage_scenarios", []):
        text = _text(item.get("scenario"))
        if not text:
            continue
        severity = _text(item.get("severity"))
        parts.append(f"{text} (stated severity: {severity})" if severity else text)
    return "; ".join(parts)


_KIND_LABEL = {
    "external_entity": "external entity",
    "process": "process",
    "data_store": "data store",
    "flow": "data flow",
    "payload": "data flow payload",
}


def asset_type_from_model(elements: list[str], diagrams: dict[str, Any], fallback: str) -> str:
    """Describe an asset by the model elements it is made of, in the model's own words.

    Our source selection reads this text (words such as cloud, backend, firmware, bootloader), so it
    comes from the data-flow model and not from a guess about the asset's name.
    """
    entities = {e["id"]: e for e in diagrams.get("entities", [])}
    flows = {f["id"]: f for f in diagrams.get("data_flows", [])}

    def name(entity_id: Any) -> str:
        return _text(entities.get(entity_id, {}).get("name")) or _text(entity_id)

    described: list[str] = []
    for element in elements:
        if element in flows:
            flow = flows[element]
            described.append(
                f"{_KIND_LABEL['flow']} {name(flow.get('source'))} to {name(flow.get('destination'))}"
            )
        elif element in entities:
            kind = _text(entities[element].get("entity_type"))
            described.append(f"{_KIND_LABEL.get(kind, kind)} {name(element)}")
    return "; ".join(described[:2]) or fallback


def asset_to_model(
    asset: dict[str, Any],
    diagrams: dict[str, Any],
    table: Source,
    notes: list[str],
    details: list[dict[str, Any]] | None = None,
) -> AssetModel:
    """One Team 1 asset as one of ours.

    ``device_config`` is part of our retrieval query, so it only carries what belongs there: the
    controls the data-flow model states and the validated attack references. Where the asset came
    from, who approved it and what is undecided go to ``details`` (the import report).
    """
    source = asset.get("source") or {}
    elements = [
        e for e in dict.fromkeys([source.get("element_id"), *source.get("elements", [])]) if e
    ]
    flows, zones = _touching(diagrams, [str(e) for e in elements])
    security, undecided = _verdicts(asset)
    interfaces = sorted({str(f["protocol"]) for f in flows if f.get("protocol")})
    asset_id = str(asset["id"])
    if not flows:
        notes.append(
            f"{asset_id} ({asset.get('name')}): not linked to any data flow, so no interface is known"
        )
    elif not interfaces:
        linked = ", ".join(sorted({str(f.get("id")) for f in flows}))
        notes.append(
            f"{asset_id} ({asset.get('name')}): linked to flow {linked}, "
            "but Team 1 recorded no protocol for it, so no interface is known"
        )
    kb = [
        c["reference_id"]
        for c in asset.get("kb_citations", [])
        if _CATALOGUE_ID.fullmatch(str(c.get("reference_id") or ""))
    ]
    controls = sorted({str(c) for f in flows for c in f.get("security_controls", [])})
    config = {
        "security_controls": ", ".join(controls),
        "known_attack_references": ", ".join(str(k) for k in kb),
    }
    kind = _text(source.get("kind"))
    fallback = "unspecified" if kind in ("", "knowledge_base", "engineer") else kind
    asset_type = asset_type_from_model([str(e) for e in elements], diagrams, fallback)
    if details is not None:
        details.append(
            {
                "asset_id": asset_id,
                "name": str(asset["name"]),
                "team1_asset_table": table.label(),
                "approved_by": table.approved_by,
                "source_kind": kind,
                "source_elements": [str(e) for e in elements],
                "asset_type_used": asset_type,
                "undecided_properties": undecided,
                "unresolved_facts": [str(u) for u in asset.get("unresolved", [])],
            }
        )
    return AssetModel(
        asset_id=asset_id,
        name=str(asset["name"]),
        asset_type=asset_type,
        location=_text(asset.get("location")) or "unspecified",
        security_attributes=security,
        damage_scenario=_damage(asset),
        dfd_context=DFDContext(
            interfaces=interfaces,
            trust_zone="; ".join(zones[:3]) if zones else "untrusted",
            data_flows=sorted({str(f.get("name") or f["id"]) for f in flows}),
        ),
        version=f"{table.version or 1}.0",
        device_config={k: v for k, v in config.items() if v},
    )


def system_model_text(diagrams: dict[str, Any]) -> str:
    """The structured data-flow model as plain sentences (never the Mermaid drawing)."""
    if not diagrams:
        return NO_MODEL
    entities = {e["id"]: e for e in diagrams.get("entities", [])}
    lines: list[str] = []
    for boundary in diagrams.get("trust_boundaries", []):
        members = ", ".join(
            f"{m} {entities[m]['name']}" if m in entities else str(m)
            for m in boundary.get("members", [])
        )
        lines.append(
            f"Trust boundary {boundary['id']} ({boundary.get('name', '')}) contains {members}."
        )
    for entity in entities.values():
        rating = entity.get("sensitivity") or {}
        needed = [
            code
            for code, name in (("C", "confidentiality"), ("I", "integrity"), ("A", "availability"))
            if _text(rating.get(name)).lower() == "yes"
        ]
        if needed:
            lines.append(f"{entity['id']} {entity['name']} must protect {', '.join(needed)}.")
    for flow in _distinct_flows(diagrams.get("data_flows", [])):
        crossing = (
            f" It crosses trust boundary {flow.get('from_boundary')} to {flow.get('to_boundary')}."
            if flow.get("crosses_trust_boundary")
            else ""
        )
        payload = ", ".join(flow.get("payload_fields", [])) or "unspecified data"
        lines.append(
            f"Flow {flow['id']} {flow.get('name', '')}: {flow.get('source')} to {flow.get('destination')} "
            f"over {flow.get('protocol') or 'an unspecified protocol'} carrying {payload}.{crossing}"
        )
    return "\n".join(lines) or NO_MODEL


def use_case_parts(usecase: dict[str, Any], item: dict[str, Any] | None) -> tuple[str, str]:
    """Title, and the description (use case plus the product it belongs to)."""
    title = _text(usecase.get("title")) or _text(usecase.get("id"))
    steps = "; ".join(
        f"{s.get('step_number')}. {s.get('action')}"
        + (f" ({s['actor']})" if s.get("actor") else "")
        for s in usecase.get("main_flow", [])
    )
    parts: list[str] = []
    if item and (item.get("item_name") or item.get("description")):
        parts.append(
            f"Product: {_text(item.get('item_name'))}. {_text(item.get('description'))}".strip()
        )
    if usecase.get("actor"):
        parts.append(f"Actor: {usecase['actor']}.")
    if usecase.get("preconditions"):
        parts.append(f"Preconditions: {'; '.join(usecase['preconditions'])}.")
    if steps:
        parts.append(f"Flow: {steps}.")
    if usecase.get("postconditions"):
        parts.append(f"Postconditions: {'; '.join(usecase['postconditions'])}.")
    if usecase.get("alternate_flows"):
        parts.append(f"Alternate flows: {'; '.join(usecase['alternate_flows'])}.")
    if item and item.get("assumptions"):
        parts.append(f"Assumptions: {'; '.join(item['assumptions'])}.")
    return title, " ".join(parts) or f"Use case {title}."


def derive_project_id(item: dict[str, Any] | None, session_id: str | None) -> str:
    name = _text((item or {}).get("item_name"))
    code = re.search(r"\(([A-Za-z0-9][A-Za-z0-9-]{2,})\)", name)
    if code:
        return code.group(1)
    slug = re.sub(r"[^A-Za-z0-9]+", "-", name).strip("-")
    return slug or session_id or "PROJECT"


# ------------------------------------------------------------------ the bundle


@dataclass
class ImportResult:
    """Everything an import produced."""

    inputs: list[ThreatAgentInput]
    project: ProjectInput | None = None
    notes: list[str] = field(default_factory=list)
    provenance: list[dict[str, Any]] = field(default_factory=list)
    asset_details: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


def _entries(bundle: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    raw = bundle.get("usecases")
    if isinstance(raw, dict):
        return [(str(k), v) for k, v in raw.items()]
    if isinstance(raw, list):
        out = []
        for index, entry in enumerate(raw, 1):
            key = entry.get("usecase_id") or entry.get("id") or f"entry {index}"
            out.append((str(key), entry))
        return out
    raise Team1ImportError("The bundle has no 'usecases'.")


def build_inputs(
    bundle: dict[str, Any],
    *,
    allow_unapproved: bool = False,
    partial: bool = False,
    project_id: str | None = None,
    run_suffix: str | None = None,
    kb_snapshot_version: str = "latest",
) -> ImportResult:
    """One ``ThreatAgentInput`` per use case of a Team 1 bundle.

    Bundle: ``{"session_id", "item_definition", "usecases": {"UC-01": {"usecase", "diagrams", "assets"}}}``
    where every part is an artefact (see :func:`unwrap`). A use case with ``"status": "dropped"`` is
    skipped. Without ``partial`` the import refuses unless every use case has an approved asset table.
    """
    session_id = _text(bundle.get("session_id")) or None
    item: dict[str, Any] | None = None
    item_source: Source | None = None
    if bundle.get("item_definition"):
        item, item_source = unwrap(
            bundle["item_definition"], "item definition", allow_unapproved=allow_unapproved
        )
    project = project_id or _text(bundle.get("project_id")) or derive_project_id(item, session_id)
    suffix = run_suffix or uuid.uuid4().hex[:6].upper()

    result = ImportResult(inputs=[])
    specs: list[UseCaseSpec] = []
    problems: list[str] = []
    for key, entry in _entries(bundle):
        if _text(entry.get("status")).lower() == "dropped":
            result.skipped.append(f"{key}: dropped by the engineer")
            continue
        try:
            assets_content, assets_src = unwrap(
                entry.get("assets"), f"{key} asset table", allow_unapproved=allow_unapproved
            )
            usecase, usecase_src = unwrap(
                entry.get("usecase"), f"{key} use case", allow_unapproved=allow_unapproved
            )
            diagrams: dict[str, Any] = {}
            diagrams_src: Source | None = None
            if entry.get("diagrams"):
                diagrams, diagrams_src = unwrap(
                    entry["diagrams"], f"{key} system model", allow_unapproved=allow_unapproved
                )
            else:
                result.notes.append(
                    f"{key}: no system model supplied; interfaces and trust zones are unknown"
                )
        except Team1ImportError as exc:
            problems.append(str(exc))
            continue

        use_case_id = _text(usecase.get("id")) or key
        rows = assets_content.get("assets", [])
        if not rows:
            problems.append(f"{use_case_id}: the approved asset table has no assets")
            continue
        notes: list[str] = []
        details: list[dict[str, Any]] = []
        models = [asset_to_model(a, diagrams, assets_src, notes, details) for a in rows]
        result.notes += [f"{use_case_id}: {n}" for n in notes]
        result.asset_details += [{"use_case_id": use_case_id, **d} for d in details]
        title, description = use_case_parts(usecase, item)
        model_text = system_model_text(diagrams)
        result.inputs.append(
            ThreatAgentInput(
                run_id=f"{project}-{use_case_id}-{suffix}",
                project_id=project,
                use_case_id=use_case_id,
                use_case=f"{title}. {description}",
                system_model=model_text,
                assets=models,
                kb_snapshot_version=kb_snapshot_version,
            )
        )
        specs.append(
            UseCaseSpec(
                use_case_id=use_case_id,
                title=title if len(title) >= 3 else f"Use case {title}",
                description=description,
                system_model=model_text,
                assets=models,
            )
        )
        result.provenance.append(
            {
                "use_case_id": use_case_id,
                "assets": assets_src.label(),
                "assets_approved_by": assets_src.approved_by,
                "assets_approved_at": assets_src.approved_at,
                "use_case": usecase_src.label(),
                "system_model": diagrams_src.label() if diagrams_src else None,
                "item_definition": item_source.label() if item_source else None,
            }
        )

    if problems and not (partial and result.inputs):
        raise Team1ImportError(
            "Team 1's handoff is not ready: "
            + "; ".join(problems)
            + (". Use partial to import the use cases that are ready." if result.inputs else "")
        )
    result.skipped += problems
    if not result.inputs:
        raise Team1ImportError("There is no use case to import.")
    result.project = ProjectInput(
        project_id=project,
        product_name=_text((item or {}).get("item_name")) or project,
        use_cases=specs,
        kb_snapshot_version=kb_snapshot_version,
    )
    return result


def load_bundle(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Team1ImportError(f"Cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise Team1ImportError(f"{path} is not a bundle (expected a JSON object)")
    return data


# ------------------------------------------------------------------ Team 1's HTTP API


def _get(base: str, path: str, token: str | None, timeout: float) -> Any:
    request = urllib.request.Request(base.rstrip("/") + path)  # noqa: S310  (operator-given URL)
    request.add_header("Accept", "application/json")
    if token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        if exc.code in (401, 403):
            raise Team1ImportError(
                f"Team 1's API refused the request ({exc.code}); check the token"
            ) from exc
        raise Team1ImportError(f"Team 1's API answered {exc.code} for {path}") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise Team1ImportError(f"Cannot reach Team 1's API at {base}: {exc}") from exc


def fetch_bundle(
    base_url: str, session_id: str, token: str | None = None, timeout: float = 30.0
) -> dict[str, Any]:
    """Read a session from Team 1's API into a bundle. Nothing is written to their system."""
    quoted = urllib.parse.quote(session_id, safe="")
    root = f"/api/v1/sessions/{quoted}"
    listing = _get(base_url, f"{root}/usecases", token, timeout)
    if listing is None:
        raise Team1ImportError(f"Session {session_id} was not found")
    bundle: dict[str, Any] = {
        "session_id": session_id,
        "handoff_ready": bool(listing.get("handoff_ready")),
        "item_definition": _get(base_url, f"{root}/artefacts/item_definition", token, timeout),
        "usecases": {},
    }
    for track in listing.get("usecases", []):
        uc = str(track.get("usecase_id"))
        query = f"?usecase_id={urllib.parse.quote(uc, safe='')}"
        bundle["usecases"][uc] = {
            "status": track.get("status"),
            "usecase": _get(base_url, f"{root}/artefacts/usecase{query}", token, timeout),
            "diagrams": _get(base_url, f"{root}/artefacts/modelling{query}", token, timeout),
            "assets": _get(base_url, f"{root}/artefacts/asset{query}", token, timeout),
        }
    return bundle
