"""Download the full public MITRE knowledge bases into kb/data/full/.

Sources (free, royalty-free incl. commercial use; MITRE copyright notice must
be kept -- see kb/NOTICE_MITRE.md):
    CAPEC            https://capec.mitre.org/data/xml/capec_latest.xml
    CWE              https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
    ATT&CK Enterprise / ICS   github.com/mitre-attack/attack-stix-data

Usage:
    python -m kb.scripts.fetch_full_kb
"""

from __future__ import annotations

import sys
import urllib.request
import zipfile
from pathlib import Path

OUT_DIR = Path("kb/data/full")

_SOURCES: dict[str, str] = {
    "capec_latest.xml": "https://capec.mitre.org/data/xml/capec_latest.xml",
    "cwec_latest.xml.zip": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
    "enterprise-attack.json": (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/enterprise-attack/enterprise-attack.json"
    ),
    "ics-attack.json": (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "master/ics-attack/ics-attack.json"
    ),
}


def fetch(out_dir: Path = OUT_DIR) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, url in _SOURCES.items():
        target = out_dir / name
        if target.exists() and target.stat().st_size > 0:
            print(f"[SKIP] {name} already present", file=sys.stderr)
            continue
        print(f"[GET ] {url}", file=sys.stderr)
        urllib.request.urlretrieve(url, target)  # noqa: S310 - fixed https URLs
        print(f"[OK  ] {name} ({target.stat().st_size / 1e6:.1f} MB)", file=sys.stderr)
    cwe_zip = out_dir / "cwec_latest.xml.zip"
    with zipfile.ZipFile(cwe_zip) as zf:
        xml_names = [n for n in zf.namelist() if n.endswith(".xml")]
        zf.extract(xml_names[0], out_dir)
        (out_dir / xml_names[0]).replace(out_dir / "cwec_latest.xml")
    print("[DONE] full KB source files ready in", out_dir, file=sys.stderr)


if __name__ == "__main__":
    fetch()
