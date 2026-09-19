"""
kb/loaders/capec_loader.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1  |  CAPEC Loader  (Aryan)
──────────────────────────────────────────────────────────────────────────────
Loads CAPEC (Common Attack Pattern Enumeration and Classification) entries
from a JSON seed file and produces ``KBEntry`` objects.

Seed format (``kb/data/capec_seed.json``):
    JSON array of objects, each with:
      - pattern_id:    str  e.g. "CAPEC-62"
      - title:         str  Human-readable name
      - description:   str  Full technical description
      - stride_hint:   str | null  STRIDE category
      - mitre_tactics: list[str]  ATT&CK tactic IDs (may be empty)

Week 3 extension:
    This loader will also handle the full CAPEC XML download from
    https://capec.mitre.org/data/xml/capec_latest.xml
    The ``load()`` method will detect the file extension and dispatch
    to ``_load_json()`` or ``_load_xml()`` accordingly.
"""

from __future__ import annotations

from pathlib import Path

from agents.threat_agent.schemas import KBSource
from kb.loaders.base_loader import BaseLoader, KBEntry

_REQUIRED_FIELDS = ["pattern_id", "title", "description"]


class CAPECLoader(BaseLoader):
    """Loads CAPEC attack pattern entries from JSON seed data."""

    def __init__(self) -> None:
        super().__init__(source=KBSource.CAPEC)

    def load(self, data_path: Path) -> list[KBEntry]:
        """Load CAPEC entries from a JSON seed file.

        Args:
            data_path: Path to ``capec_seed.json`` (or full CAPEC JSON in
                       Week 3).

        Returns:
            List of ``KBEntry`` objects, one per valid CAPEC entry.

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
