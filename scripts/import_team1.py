# ruff: noqa: E501
"""Import Team 1's approved results as Threat Agent inputs.

    python scripts/import_team1.py --file team1_export.json --out projects/imported
    python scripts/import_team1.py --api http://localhost:8000 --session <id> --token <bearer>

Reads only: nothing is written to Team 1's system. Only approved artefacts are accepted, and every use
case must have an approved asset table (add --partial to take the ones that are ready).

The result is one input file per use case, plus ``import_report.json`` listing which Team 1 artefact
and version each use case came from. Load a use case with ``scripts/scrp_demo.py --input <file>``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agents.threat_agent.team1_import import (
    Team1ImportError,
    build_inputs,
    fetch_bundle,
    load_bundle,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", help="a bundle exported from Team 1 (JSON)")
    source.add_argument("--api", help="base URL of Team 1's API, e.g. http://localhost:8000")
    parser.add_argument("--session", help="Team 1 session id (with --api)")
    parser.add_argument("--token", help="bearer token for Team 1's API, if it needs one")
    parser.add_argument("--out", default=str(_ROOT / "projects" / "imported"))
    parser.add_argument("--project-id", help="override the project id")
    parser.add_argument("--partial", action="store_true", help="import only the ready use cases")
    parser.add_argument(
        "--allow-unapproved",
        action="store_true",
        help="TEST DATA ONLY: accept artefacts whose approval cannot be checked",
    )
    args = parser.parse_args()

    try:
        if args.api:
            if not args.session:
                parser.error("--session is required with --api")
            bundle = fetch_bundle(args.api, args.session, args.token)
        else:
            bundle = load_bundle(Path(args.file))
        result = build_inputs(
            bundle,
            allow_unapproved=args.allow_unapproved,
            partial=args.partial,
            project_id=args.project_id,
        )
    except Team1ImportError as exc:
        print(f"NOT IMPORTED: {exc}")
        return 1

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for item in result.inputs:
        path = out / f"{item.project_id}_{item.use_case_id}.json".replace(" ", "_")
        path.write_text(item.model_dump_json(indent=2), encoding="utf-8")
        print(f"{item.use_case_id}: {len(item.assets)} assets -> {path}")
    if result.project is not None:
        combined = out / f"{result.project.project_id}_project.json".replace(" ", "_")
        combined.write_text(result.project.model_dump_json(indent=2), encoding="utf-8")
        print(f"All use cases together -> {combined}")
    report = {
        "provenance": result.provenance,
        "assets": result.asset_details,
        "notes": result.notes,
        "skipped": result.skipped,
    }
    (out / "import_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    for note in result.notes:
        print(f"  note: {note}")
    for skipped in result.skipped:
        print(f"  skipped: {skipped}")
    print(f"Report: {out / 'import_report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
