"""Check the audit chain and that approved content still matches what was approved.

    python scripts/verify_audit.py
    python scripts/verify_audit.py --scrs SCRS_state.json

Exit code 0 means intact, 1 means tampering or damage was found.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from scrp.state_manager import SCRSCorruptError, StateManager


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scrs", default=str(_ROOT / "demo_output" / "SCRS_demo.json"))
    args = parser.parse_args()
    if not Path(args.scrs).exists():
        print(f"No shared state at {args.scrs}.")
        return 1
    try:
        report = StateManager(Path(args.scrs)).verify_integrity()
    except SCRSCorruptError as exc:
        print(f"DAMAGED: {exc}")
        return 1
    print(
        f"Audit entries     : {report['chain']['entries']} ({report['chain']['unsealed']} unsealed)"
    )
    print(f"State version     : {report['state_version']}")
    print(f"Hash mode         : {'keyed (HMAC)' if report['keyed'] else 'unkeyed SHA-256'}")
    print(f"Records checked   : {report['records_checked']}")
    print(f"No digest (legacy): {len(report['records_unverifiable'])}")
    if not report["chain"]["ok"]:
        print(f"CHAIN BROKEN at entry {report['chain']['broken_at']} ({report['chain']['tid']})")
    for item in report["records_changed"]:
        print(f"CONTENT CHANGED   : {item}")
    print("RESULT: " + ("intact" if report["ok"] else "PROBLEMS FOUND"))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
