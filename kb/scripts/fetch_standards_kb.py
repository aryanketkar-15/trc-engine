"""Download the freely available standards documents into kb/data/standards/.

    Common Criteria CC:2022 R1 Parts 1-5 + CEM   commoncriteriaportal.org
    JIL Application of Attack Potential to Smartcards v3.2.1   sogis.eu (JIL)
    EU Cyber Resilience Act, Regulation (EU) 2024/2847   publications.europa.eu

NOT fetched (see kb/NOTICE_STANDARDS.md): ISO/SAE 21434 (paid), SESIP (free but no
stable direct link / reuse terms not stated), IEC 62443 (paid).

Usage:
    python -m kb.scripts.fetch_standards_kb
"""

from __future__ import annotations

import sys
import urllib.request
from pathlib import Path

OUT_DIR = Path("kb/data/standards")
_CC = "https://www.commoncriteriaportal.org/files/ccfiles/"

_SOURCES: dict[str, tuple[str, dict[str, str]]] = {
    "CC2022PART1R1.pdf": (_CC + "CC2022PART1R1.pdf", {}),
    "CC2022PART2R1.pdf": (_CC + "CC2022PART2R1.pdf", {}),
    "CC2022PART3R1.pdf": (_CC + "CC2022PART3R1.pdf", {}),
    "CC2022PART4R1.pdf": (_CC + "CC2022PART4R1.pdf", {}),
    "CC2022PART5R1.pdf": (_CC + "CC2022PART5R1.pdf", {}),
    "CEM2022R1.pdf": (_CC + "CEM2022R1.pdf", {}),
    "JIL-Attack-Potential-Smartcards-v3.2.1.pdf": (
        "https://sogis.eu/documents/cc/domains/sc/"
        "JIL-Application-of-Attack-Potential-to-Smartcards-v3.2.1.pdf",
        {},
    ),
    "CRA-2024-2847.xhtml": (
        "http://publications.europa.eu/resource/celex/32024R2847",
        {"Accept": "application/xhtml+xml", "Accept-Language": "en"},
    ),
}


def fetch(out_dir: Path = OUT_DIR) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, (url, headers) in _SOURCES.items():
        target = out_dir / name
        if target.exists() and target.stat().st_size > 0:
            print(f"[SKIP] {name} already present", file=sys.stderr)
            continue
        print(f"[GET ] {url}", file=sys.stderr)
        req = urllib.request.Request(url, headers=headers)  # noqa: S310 - fixed URLs
        with urllib.request.urlopen(req, timeout=120) as resp:  # noqa: S310
            target.write_bytes(resp.read())
        print(f"[OK  ] {name} ({target.stat().st_size / 1e6:.1f} MB)", file=sys.stderr)


if __name__ == "__main__":
    fetch()
