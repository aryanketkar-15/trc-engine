"""Loaders for the full public MITRE catalogues (CAPEC XML, CWE XML, ATT&CK STIX).

These complement the 24-entry seed loaders.  Pattern-ID formats match the seed
data so existing labels keep working: ``CAPEC-94``, ``CWE-306``,
``ATT&CK-T1078``.  Deprecated / revoked / obsolete entries are skipped.

STRIDE hints are *inferred* with transparent keyword rules (``infer_stride``);
they are a heuristic, not part of the MITRE data, and are left ``None`` when
no rule fires.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from agents.threat_agent.schemas import KBSource, STRIDECategory
from kb.loaders.base_loader import BaseLoader, KBEntry

MAX_DESC_CHARS = 1200

_S = STRIDECategory
_STRIDE_RULES: list[tuple[STRIDECategory, tuple[str, ...]]] = [
    (_S.SPOOFING, ("spoof", "impersonat", "forg", "masquerad", "replay", "session hijack",
                   "phishing", "stolen credential", "valid account", "authentication bypass",
                   "brute force", "credential")),
    (_S.TAMPERING, ("tamper", "modif", "inject", "overflow", "corrupt", "manipulat",
                    "malicious update", "firmware", "integrity", "fault injection")),
    (_S.REPUDIATION, ("repudiat", "audit log", "clear log", "indicator removal",
                      "log tamper", "disable logging")),
    (_S.INFORMATION_DISCLOSURE, ("eavesdrop", "sniff", "intercept", "disclos", "leak",
                                 "side channel", "side-channel", "exfiltrat", "cleartext",
                                 "reverse engineer", "sensitive information", "extract")),
    (_S.DENIAL_OF_SERVICE, ("denial of service", "flood", "exhaust", "resource consumption",
                            "crash", "jam", "dos ")),
    (_S.ELEVATION_OF_PRIVILEGE, ("privilege escalation", "escalat", "elevat",
                                 "bypass authorization", "improper authorization",
                                 "root access", "sudo")),
]


def infer_stride(title: str, description: str) -> STRIDECategory | None:
    """Heuristic STRIDE category from keywords; title hits count double."""
    t, d = title.lower(), description.lower()
    best: tuple[int, STRIDECategory | None] = (0, None)
    for cat, kws in _STRIDE_RULES:
        score = sum(2 for k in kws if k in t) + sum(1 for k in kws if k in d)
        if score > best[0]:
            best = (score, cat)
    return best[1] if best[0] >= 2 else None


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _text(el: ET.Element | None) -> str:
    return _clean("".join(el.itertext())) if el is not None else ""


def _truncate(text: str) -> str:
    return text if len(text) <= MAX_DESC_CHARS else text[: MAX_DESC_CHARS - 1].rstrip() + "…"


def _ns(root: ET.Element) -> dict[str, str]:
    return {"n": root.tag.split("}")[0][1:]}


class CAPECXMLLoader(BaseLoader):
    """Full CAPEC catalogue from ``capec_latest.xml``."""

    def __init__(self) -> None:
        super().__init__(source=KBSource.CAPEC)

    def load(self, data_path: Path) -> list[KBEntry]:
        root = ET.parse(data_path).getroot()  # noqa: S314
        ns = _ns(root)
        out: list[KBEntry] = []
        for ap in root.findall(".//n:Attack_Pattern", ns):
            if ap.get("Status") in {"Deprecated", "Obsolete"}:
                continue
            title = _clean(ap.get("Name", ""))
            desc = _text(ap.find("n:Description", ns))
            ext = _text(ap.find("n:Extended_Description", ns))
            full = _truncate(f"{desc} {ext}".strip())
            if not (ap.get("ID") and title and full):
                continue
            out.append(KBEntry(f"CAPEC-{ap.get('ID')}", self._source, title, full,
                               infer_stride(title, full), []))
        return out


class CWEXMLLoader(BaseLoader):
    """Full CWE catalogue from ``cwec_latest.xml``; hardware weaknesses flagged.

    Weaknesses reachable from the Hardware Design view (CWE-1194) get a
    ``[Hardware design]`` marker in their description so hardware assets
    retrieve them more readily.
    """

    def __init__(self) -> None:
        super().__init__(source=KBSource.CWE)

    @staticmethod
    def _hardware_ids(root: ET.Element, ns: dict[str, str]) -> set[str]:
        view = next((v for v in root.findall(".//n:View", ns) if v.get("ID") == "1194"), None)
        if view is None:
            return set()
        member_ids = {m.get("CWE_ID") for m in view.findall(".//n:Has_Member", ns)}
        hw: set[str] = set(member_ids)
        for cat in root.findall(".//n:Category", ns):
            if cat.get("ID") in member_ids:
                hw.update(m.get("CWE_ID") for m in cat.findall(".//n:Has_Member", ns))
        return {i for i in hw if i}

    def load(self, data_path: Path) -> list[KBEntry]:
        root = ET.parse(data_path).getroot()  # noqa: S314
        ns = _ns(root)
        hw = self._hardware_ids(root, ns)
        out: list[KBEntry] = []
        for w in root.findall(".//n:Weakness", ns):
            if w.get("Status") == "Deprecated":
                continue
            title = _clean(w.get("Name", ""))
            desc = _text(w.find("n:Description", ns))
            ext = _text(w.find("n:Extended_Description", ns))
            full = f"{desc} {ext}".strip()
            if w.get("ID") in hw:
                full = f"[Hardware design weakness] {full}"
            full = _truncate(full)
            if not (w.get("ID") and title and full):
                continue
            out.append(KBEntry(f"CWE-{w.get('ID')}", self._source, title, full,
                               infer_stride(title, full), []))
        return out


class ATTCKSTIXLoader(BaseLoader):
    """ATT&CK techniques/sub-techniques from a STIX 2.x bundle (Enterprise or ICS)."""

    def __init__(self) -> None:
        super().__init__(source=KBSource.ATT_AND_CK)

    def load(self, data_path: Path) -> list[KBEntry]:
        objs = json.loads(Path(data_path).read_text(encoding="utf-8"))["objects"]
        tactic_code = {
            o["x_mitre_shortname"]: next(
                (r["external_id"] for r in o.get("external_references", [])
                 if r.get("external_id", "").startswith("TA")), "")
            for o in objs if o.get("type") == "x-mitre-tactic"
        }
        out: list[KBEntry] = []
        for o in objs:
            if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
                continue
            ext_id = next((r["external_id"] for r in o.get("external_references", [])
                           if r.get("source_name") in {"mitre-attack", "mitre-ics-attack"}
                           and r.get("external_id")), None)
            title, desc = _clean(o.get("name", "")), _clean(o.get("description", ""))
            if not (ext_id and title and desc):
                continue
            platforms = o.get("x_mitre_platforms") or []
            if platforms:
                desc = f"{desc} Platforms: {', '.join(platforms)}."
            tactics = [tactic_code.get(p["phase_name"], "") for p in o.get("kill_chain_phases", [])]
            out.append(KBEntry(f"ATT&CK-{ext_id}", self._source, title, _truncate(desc),
                               infer_stride(title, desc), [t for t in tactics if t]))
        return out
