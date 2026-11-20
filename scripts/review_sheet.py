# ruff: noqa: E501
"""Expert review sheet: have a person judge the approved threats, then measure what they said.

    # 1. make a workbook for one use case (one row per approved threat, one row per asset)
    python scripts/review_sheet.py export --use-case UC-01 \
        --input projects/smart_door_lock_multi_use_case.json --out review_UC-01.xlsx

    # 2. the reviewer fills the yellow columns (drop-down answers) and saves the file

    # 3. count the answers
    python scripts/review_sheet.py summarise review_UC-01.xlsx --out review_UC-01_results

The sheet is an evaluation instrument. It does not change the shared state and it does not approve
anything: it records what a named reviewer thinks of each threat, the cited pattern, the impact
and the feasibility, and of the assets that have no threat. The summary reports the shares as
counted, with the number of rows behind each, so that "how many are right" has a source.

Needs the optional ``openpyxl`` package (``pip install openpyxl``).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

REALISTIC = ("Yes", "Partly", "No")
FITS = ("Yes", "Loosely", "No")
IMPACT = ("About right", "Too low", "Too high")
FEASIBILITY = ("About right", "Too easy", "Too hard")
MISSING = ("No", "Yes")

THREAT_HEAD = [
    "Threat",
    "Asset",
    "Attack",
    "STRIDE",
    "Cited pattern",
    "Pattern title",
    "Pattern description",
    "Why the model says it applies",
    "Overall impact",
    "Attack feasibility",
    "Risk",
    "Treatment",
]
REVIEW_HEAD = [
    "Is the threat realistic for this asset?",
    "Does the cited pattern fit?",
    "Impact rating",
    "Feasibility rating",
    "Comment",
]
ASSET_HEAD = ["Asset", "Name", "Approved threats", "Note", "Is a threat missing for this asset?", "Missing threat (in your words)"]

INSTRUCTIONS = [
    "How to review",
    "",
    "Sheet 'Threats': one row per approved threat. Read the attack, the asset and the cited pattern, then answer the yellow columns using the drop-down lists.",
    "- Is the threat realistic for this asset?  Yes = a real attacker could do this to this asset; Partly = plausible but the details are wrong; No = not realistic.",
    "- Does the cited pattern fit?  Yes = the pattern describes this attack; Loosely = related but a stretch; No = unrelated to this attack or asset.",
    "- Impact / Feasibility rating: is the value shown about right, or too low / too high (too easy / too hard)?",
    "Sheet 'Assets': for each asset say whether an important threat is missing, and describe it.",
    "Sheet 'Reviewer': write your name, role and the date. Without a name the answers are not counted as a review.",
    "",
    "Please answer from your own knowledge. If you cannot tell, leave the cell empty; empty answers are counted as 'not answered', not as 'Yes'.",
]


def _need_openpyxl() -> Any:  # noqa: ANN401
    try:
        import openpyxl
    except ImportError:  # pragma: no cover
        raise SystemExit("This script needs openpyxl: pip install openpyxl") from None
    return openpyxl


def pattern_texts(ids: list[str]) -> dict[str, tuple[str, str]]:
    """Title and description of each cited pattern from the knowledge base; empty if unreachable."""
    out: dict[str, tuple[str, str]] = {}
    try:
        from common.db import get_db_connection

        with get_db_connection() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT pattern_id, title, description FROM threat_patterns "
                "WHERE pattern_id = ANY(%s);",
                (ids,),
            )
            for pid, title, description in cur.fetchall():
                out[str(pid)] = (str(title or ""), str(description or ""))
    except Exception as exc:  # the sheet is still useful without the pattern text
        print(f"Note: pattern text not added ({type(exc).__name__}).")
    return out


def threat_rows(scrs: Path, use_case: str, project_id: str | None) -> list[dict[str, Any]]:
    """One dict per approved threat of the use case, with its risk and treatment."""
    from scrp.state_manager import StateManager

    state = StateManager(scrs)
    risks = {
        str(t): v for t, v in state.get_risk_assessments().items() if isinstance(v, dict)
    }
    rows = []
    for tid, t in state.get_threat_scenarios().items():
        if not isinstance(t, dict) or t.get("use_case_id") != use_case:
            continue
        if project_id and t.get("project_id") not in (None, project_id):
            continue
        risk = risks.get(str(tid), {})
        evidence = t.get("evidence_chain") or {}
        adjusted = risk.get("adjusted_risk")
        rows.append(
            {
                "tid": str(tid),
                "asset_id": str(t.get("asset_id", "")),
                "attack": str(t.get("attack_vector", "")),
                "stride": str(t.get("stride_category", "")),
                "kb_reference": str(t.get("kb_reference", "")),
                "why": str(evidence.get("applicability_reason", "")),
                "impact": str(risk.get("overall_impact", "")),
                "feasibility": str(risk.get("attack_feasibility", "")),
                "risk": str(adjusted or risk.get("risk", "")),
                "treatment": str(risk.get("treatment", "") or ""),
            }
        )
    return sorted(rows, key=lambda r: (r["asset_id"], r["tid"]))


def _validation(ws: Any, column: int, first: int, last: int, options: tuple[str, ...]) -> None:  # noqa: ANN401
    from openpyxl.utils import get_column_letter
    from openpyxl.worksheet.datavalidation import DataValidation

    dv = DataValidation(type="list", formula1='"' + ",".join(options) + '"', allow_blank=True)
    ws.add_data_validation(dv)
    letter = get_column_letter(column)
    dv.add(f"{letter}{first}:{letter}{last}")


def export(
    scrs: Path,
    use_case: str,
    out: Path,
    project_id: str | None = None,
    assets: list[Any] | None = None,
) -> Path:
    """Write the review workbook and return its path."""
    openpyxl = _need_openpyxl()
    from openpyxl.styles import Alignment, Font, PatternFill

    from agents.risk_agent import report
    from scrp.state_manager import StateManager

    rows = threat_rows(scrs, use_case, project_id)
    texts = pattern_texts(sorted({r["kb_reference"] for r in rows if r["kb_reference"]}))
    wb = openpyxl.Workbook()
    yellow = PatternFill("solid", fgColor="FFF2CC")
    bold = Font(bold=True)
    wrap = Alignment(wrap_text=True, vertical="top")

    info = wb.active
    info.title = "Instructions"
    for i, line in enumerate(INSTRUCTIONS, 1):
        info.cell(row=i, column=1, value=line).alignment = Alignment(wrap_text=True)
    info.cell(row=1, column=1).font = Font(bold=True, size=14)
    info.column_dimensions["A"].width = 120

    ws = wb.create_sheet("Threats")
    ws.append([*THREAT_HEAD, *REVIEW_HEAD])
    for r in rows:
        title, description = texts.get(r["kb_reference"], ("", ""))
        ws.append(
            [
                r["tid"], r["asset_id"], r["attack"], r["stride"], r["kb_reference"], title,
                description[:600], r["why"], r["impact"], r["feasibility"], r["risk"],
                r["treatment"], None, None, None, None, None,
            ]
        )
    first, last = 2, max(len(rows) + 1, 2)
    for col, options in ((13, REALISTIC), (14, FITS), (15, IMPACT), (16, FEASIBILITY)):
        _validation(ws, col, first, last, options)
    n = len(THREAT_HEAD)
    for c in range(1, n + len(REVIEW_HEAD) + 1):
        cell = ws.cell(row=1, column=c)
        cell.font = bold
        cell.alignment = wrap
        if c > n:
            cell.fill = yellow
    for row in ws.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = wrap
            if cell.column > n:
                cell.fill = yellow
    for letter, width in zip("ABCDEFGHIJKLMNOPQ", (22, 8, 40, 14, 14, 28, 55, 45, 11, 11, 9, 11, 20, 20, 16, 16, 40), strict=True):
        ws.column_dimensions[letter].width = width
    ws.freeze_panes = "C2"

    wa = wb.create_sheet("Assets")
    wa.append(ASSET_HEAD)
    coverage: list[dict[str, Any]] = []
    if assets:
        data = report.build_report(StateManager(scrs), project_id, use_case, None, assets)
        coverage = data["coverage"]
    for c in coverage:
        wa.append([c["asset_id"], c["name"], c["approved_threats"], c["note"], None, None])
    _validation(wa, 5, 2, max(len(coverage) + 1, 2), MISSING)
    for c in range(1, len(ASSET_HEAD) + 1):
        wa.cell(row=1, column=c).font = bold
        if c > 4:
            wa.cell(row=1, column=c).fill = yellow
    for row in wa.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = wrap
            if cell.column > 4:
                cell.fill = yellow
    for letter, width in zip("ABCDEF", (10, 28, 12, 60, 24, 50), strict=True):
        wa.column_dimensions[letter].width = width

    wr = wb.create_sheet("Reviewer")
    for i, label in enumerate(("Name", "Role / organisation", "Date", "Use case reviewed"), 1):
        wr.cell(row=i, column=1, value=label).font = bold
        wr.cell(row=i, column=2).fill = yellow
    wr.cell(row=4, column=2, value=use_case)
    wr.column_dimensions["A"].width = 24
    wr.column_dimensions["B"].width = 50

    out.parent.mkdir(parents=True, exist_ok=True)
    wb.save(out)
    return out


def _share(counter: Counter[str], total: int, key: str) -> str:
    return f"{counter.get(key, 0)} of {total}" if total else "0 of 0"


def summarise(path: Path) -> dict[str, Any]:
    """Count the reviewer's answers. Empty cells are 'not answered', never a default."""
    openpyxl = _need_openpyxl()
    wb = openpyxl.load_workbook(path, data_only=True)
    reviewer = {
        str(wb["Reviewer"].cell(row=i, column=1).value): wb["Reviewer"].cell(row=i, column=2).value
        for i in range(1, 5)
    }
    named = bool(str(reviewer.get("Name") or "").strip())

    ws = wb["Threats"]
    columns = {
        "realistic": (13, REALISTIC),
        "pattern_fits": (14, FITS),
        "impact": (15, IMPACT),
        "feasibility": (16, FEASIBILITY),
    }
    counts: dict[str, Counter[str]] = {k: Counter() for k in columns}
    answered_rows = 0
    threats = 0
    comments: list[dict[str, str]] = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        if not row or not row[0]:
            continue
        threats += 1
        any_answer = False
        for key, (col, allowed) in columns.items():
            value = str(row[col - 1] or "").strip()
            if value in allowed:
                counts[key][value] += 1
                any_answer = True
        if any_answer:
            answered_rows += 1
        if row[16]:
            comments.append({"threat": str(row[0]), "comment": str(row[16])})

    wa = wb["Assets"]
    missing: Counter[str] = Counter()
    missing_text: list[dict[str, str]] = []
    assets = 0
    for row in wa.iter_rows(min_row=2, values_only=True):
        if not row or not row[0]:
            continue
        assets += 1
        value = str(row[4] or "").strip()
        if value in MISSING:
            missing[value] += 1
        if value == "Yes" and row[5]:
            missing_text.append({"asset": str(row[0]), "missing": str(row[5])})

    def block(key: str) -> dict[str, Any]:
        c = counts[key]
        answered = sum(c.values())
        return {"answered": answered, "of": threats, "counts": dict(c)}

    return {
        "file": path.name,
        "reviewer": reviewer,
        "reviewer_named": named,
        "counted_as_review": named and answered_rows > 0,
        "threats": threats,
        "threats_answered": answered_rows,
        "realistic": block("realistic"),
        "pattern_fits": block("pattern_fits"),
        "impact": block("impact"),
        "feasibility": block("feasibility"),
        "assets": assets,
        "assets_with_missing_threat": missing.get("Yes", 0),
        "assets_answered": sum(missing.values()),
        "missing_threats": missing_text,
        "comments": comments,
    }


def to_markdown(result: dict[str, Any]) -> str:
    r = result
    who = r["reviewer"]
    lines = [
        f"# Expert review result: {r['file']}",
        "",
        f"Reviewer: {who.get('Name') or '(no name)'}, {who.get('Role / organisation') or '(no role)'}, "
        f"{who.get('Date') or '(no date)'}. Use case: {who.get('Use case reviewed') or ''}.",
        "",
    ]
    if not r["counted_as_review"]:
        lines += ["**This file is not counted as a review: it has no reviewer name or no answers.**", ""]
    lines += [f"Threats in the sheet: {r['threats']}; with at least one answer: {r['threats_answered']}.", ""]
    labels = (
        ("realistic", "Is the threat realistic for the asset?", REALISTIC),
        ("pattern_fits", "Does the cited pattern fit?", FITS),
        ("impact", "Impact rating", IMPACT),
        ("feasibility", "Feasibility rating", FEASIBILITY),
    )
    for key, title, allowed in labels:
        b = r[key]
        parts = ", ".join(f"{v}: {b['counts'].get(v, 0)}" for v in allowed)
        lines.append(f"* **{title}** answered {b['answered']} of {b['of']}. {parts}.")
    lines += [
        "",
        f"Assets: {r['assets']}; answered: {r['assets_answered']}; "
        f"assets where a threat is missing: {r['assets_with_missing_threat']}.",
    ]
    for m in r["missing_threats"]:
        lines.append(f"* {m['asset']}: {m['missing']}")
    if r["comments"]:
        lines += ["", "Comments:"]
        lines += [f"* {c['threat']}: {c['comment']}" for c in r["comments"]]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    ex = sub.add_parser("export", help="write the review workbook")
    ex.add_argument("--scrs", default=str(_ROOT / "demo_output" / "SCRS_demo.json"))
    ex.add_argument("--use-case", required=True)
    ex.add_argument("--project-id")
    ex.add_argument("--input", help="project JSON, to list the assets of the use case")
    ex.add_argument("--out", required=True)
    sm = sub.add_parser("summarise", help="count the answers in a filled workbook")
    sm.add_argument("file")
    sm.add_argument("--out", help="write <out>.md and <out>.json")
    args = parser.parse_args()

    if args.command == "export":
        assets: list[Any] = []
        if args.input:
            from agents.threat_agent.project import load_inputs

            for run in load_inputs(Path(args.input), "REVIEW"):
                if run.use_case_id == args.use_case:
                    assets = list(run.assets)
        scrs = Path(args.scrs)
        if not scrs.exists():
            print(f"No shared state at {scrs}.")
            return 1
        path = export(scrs, args.use_case, Path(args.out), args.project_id, assets)
        print(f"Wrote {path}. Give it to the reviewer; the yellow cells are theirs.")
        return 0

    result = summarise(Path(args.file))
    text = to_markdown(result)
    print(text)
    if args.out:
        Path(args.out).with_suffix(".md").write_text(text, encoding="utf-8")
        Path(args.out).with_suffix(".json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"Wrote {args.out}.md and {args.out}.json")
    return 0


if __name__ == "__main__":
    code = 2
    try:
        code = main()
    finally:
        sys.stdout.flush()
    # the database pool keeps a thread alive; leave without waiting for it
    os._exit(code)
