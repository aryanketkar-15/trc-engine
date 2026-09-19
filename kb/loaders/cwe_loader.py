"""
kb/loaders/cwe_loader.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1  |  CWE Loader  (Aryan)
──────────────────────────────────────────────────────────────────────────────
Loads CWE (Common Weakness Enumeration) entries from a JSON seed file and
produces ``KBEntry`` objects.

Seed format (``kb/data/cwe_seed.json``):
    JSON array of objects, each with:
      - pattern_id:    str  e.g. "CWE-306"
      - title:         str  Weakness name
      - description:   str  Full description
      - stride_hint:   str | null  STRIDE mapping for this weakness
      - mitre_tactics: list[str]  Usually empty for CWE (no direct mapping)

CWE entries have no MITRE tactic IDs by default — they describe weaknesses,
not adversary tactics.  The STRIDE hint is inferred from CWE category
(e.g. CWE-311 Missing Encryption → InformationDisclosure).

Week 3 extension:
    This loader will parse the full NVD CWE XML catalog downloaded from
    https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
    STRIDE hints will be inferred from CWE Research Concept View (800)
    category membership.
"""

from __future__ import annotations

from pathlib import Path

from agents.threat_agent.schemas import KBSource
from kb.loaders.base_loader import BaseLoader, KBEntry

_REQUIRED_FIELDS = ["pattern_id", "title", "description"]


class CWELoader(BaseLoader):
    """Loads CWE weakness entries from JSON seed data."""

    def __init__(self) -> None:
        super().__init__(source=KBSource.CWE)

    def load(self, data_path: Path) -> list[KBEntry]:
        """Load CWE entries from a JSON seed file.

        Args:
            data_path: Path to ``cwe_seed.json`` (or full CWE XML in
                       Week 3).

        Returns:
            List of ``KBEntry`` objects, one per valid CWE entry.

        Raises:
            FileNotFoundError:     If ``data_path`` does not exist.
            MalformedKBEntryError: If any entry fails schema validation.
        """
        raw_entries = self._load_json(data_path)
        entries: list[KBEntry] = []

        for raw in raw_entries:
            self._validate_entry(raw, _REQUIRED_FIELDS)
            stride_hint = self._parse_stride_hint(
                raw.get("stride_hint"),
                pattern_id=str(raw["pattern_id"]),
            )
            entries.append(
                KBEntry(
                    pattern_id=str(raw["pattern_id"]),
                    source=self._source,
                    title=str(raw["title"]),
                    description=str(raw["description"]),
                    stride_hint=stride_hint,
                    mitre_tactics=list(raw.get("mitre_tactics") or []),
                )
            )

        return entries
