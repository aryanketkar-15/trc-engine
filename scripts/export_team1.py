# ruff: noqa: E501
"""Export our approved threats, risks and resistance levels for Team 1 and Team 3.

    python scripts/export_team1.py                           # every use case in demo_output/SCRS_demo.json
    python scripts/export_team1.py --use-case UC-01 --session-id <Team 1 session id>
    python scripts/export_team1.py --scrs SCRS_state.json --out exports --import-report projects/imported/import_report.json

One folder per use case with threats.json, risks.json, compliance.json, versions.json and
audit_trail.json, in the field names Team 1's hand-over kit uses. Only approved results are exported.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scrp.state_manager import SCRSCorruptError, StateManager
from scrp.team_export import build_export, use_cases_in, write_export


def upstream_versions(report_path: str | None, use_case_id: str) -> dict[str, int]:
    """Team 1's artefact versions for this use case, from the import report (labels like 'X@v2')."""
    if not report_path:
        return {}
    data = json.loads(Path(report_path).read_text(encoding="utf-8"))
    row = next((p for p in data.get("provenance", []) if p.get("use_case_id") == use_case_id), None)
    if row is None:
        return {}
    out: dict[str, int] = {}
    for ours, theirs in (
        ("assets", "asset"),
        ("use_case", "usecase"),
        ("system_model", "diagram"),
        ("item_definition", "item_definition"),
    ):
        match = re.search(r"@v(\d+)$", str(row.get(ours) or ""))
        if match:
            out[theirs] = int(match.group(1))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scrs", default=str(_ROOT / "demo_output" / "SCRS_demo.json"))
    parser.add_argument("--use-case", help="one use case, e.g. UC-01 (default: all)")
    parser.add_argument("--project-id")
    parser.add_argument("--session-id", help="Team 1's session id, copied into the files")
    parser.add_argument(
        "--import-report", help="import_report.json, to carry Team 1's artefact versions"
    )
    parser.add_argument(
        "--out", help="output folder (default: 'team_export' next to the SCRS file)"
    )
    args = parser.parse_args()

    scrs = Path(args.scrs)
    if not scrs.exists():
        print(f"No shared state at {scrs}.")
        return 1
    try:
        state = StateManager(scrs)
    except SCRSCorruptError as exc:
        print(f"NOT EXPORTED: {exc}")
        return 1
    targets = [
        (project, uc)
        for project, uc in use_cases_in(state)
        if (not args.use_case or uc == args.use_case)
        and (not args.project_id or project == args.project_id)
    ]
    if not targets:
        print("No approved threats match this selection.")
        return 1

    out = Path(args.out) if args.out else scrs.parent / "team_export"
    for project, uc in targets:
        bundle = build_export(
            state,
            uc,
            project_id=project,
            session_id=args.session_id,
            upstream_versions=upstream_versions(args.import_report, uc),
        )
        folder = out / (f"{project}_{uc}" if project else uc)
        write_export(bundle, folder)
        t, r, m = (
            len(bundle["threats"]["threats"]),
            len(bundle["risks"]["risks"]),
            len(bundle["compliance"]["mappings"]),
        )
        print(f"{uc}: {t} threats, {r} risks, {m} resistance mappings -> {folder}")
        print(f"  versions {bundle['versions']} | {bundle['audit_trail']['audit_chain']}")
        for problem in bundle["problems"]:
            print(f"  note: {problem}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
