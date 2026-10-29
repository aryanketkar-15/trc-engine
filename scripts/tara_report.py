"""Write the consolidated TARA report (Markdown + CSV + JSON) from the shared state.

python scripts/tara_report.py                       # all use cases in demo_output/SCRS_demo.json
python scripts/tara_report.py --use-case UC-01
python scripts/tara_report.py --scrs SCRS_state.json --out reports
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agents.risk_agent import report
from scrp.state_manager import StateManager


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scrs", default=str(_ROOT / "demo_output" / "SCRS_demo.json"))
    parser.add_argument("--project-id")
    parser.add_argument("--use-case")
    parser.add_argument(
        "--out", help="folder for the report files (default: next to the SCRS file)"
    )
    args = parser.parse_args()

    scrs = Path(args.scrs)
    if not scrs.exists():
        print(f"No shared state at {scrs}. Run scripts/scrp_demo.py first.")
        return 1
    data = report.build_report(StateManager(scrs), args.project_id, args.use_case)
    if not data["summary"]["approved_threats"]:
        print("No approved threats found for this selection.")
        return 1
    out = Path(args.out) if args.out else scrs.parent
    out.mkdir(parents=True, exist_ok=True)
    stem = "tara_report" + (f"_{args.use_case}" if args.use_case else "")
    title = "TARA report" + (f" - {args.use_case}" if args.use_case else "")
    (out / f"{stem}.md").write_text(report.to_markdown(data, title), encoding="utf-8")
    (out / f"{stem}.csv").write_text(report.to_csv(data), encoding="utf-8")
    (out / f"{stem}.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    s = data["summary"]
    print(
        f"{s['scored']} of {s['approved_threats']} approved threats scored; "
        f"{s['to_reduce_requirements']} need requirements, {s['residual_items']} residual."
    )
    print(f"Written: {out / (stem + '.md')} (+ .csv, .json)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
