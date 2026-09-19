"""
kb/loaders/attck_loader.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1  |  MITRE ATT&CK Loader  (Aryan)
──────────────────────────────────────────────────────────────────────────────
Loads MITRE ATT&CK Enterprise technique entries from a JSON seed file and
produces ``KBEntry`` objects.

Seed format (``kb/data/attck_seed.json``):
    JSON array of objects, each with:
      - pattern_id:    str  e.g. "ATT&CK-T1190"
      - title:         str  Technique name
      - description:   str  Full technical description
      - stride_hint:   str | null  Inferred STRIDE mapping
      - mitre_tactics: list[str]  Tactic IDs (e.g. ["TA0001", "TA0003"])

ATT&CK tactic IDs map directly to ``MITRE_TACTIC_ORDER`` in attack_chain.py,
enabling topological kill-chain ordering of retrieved candidates.

Week 3 extension:
    This loader will parse full MITRE ATT&CK STIX 2.x JSON bundles
    downloaded from https://github.com/mitre/cti
    The ``_load_stix()`` method will extract attack-pattern objects,
    map kill_chain_phases to tactic IDs, and infer STRIDE hints from
    technique category keywords.
"""

from __future__ import annotations

from pathlib import Path

from agents.threat_agent.schemas import KBSource
from kb.loaders.base_loader import BaseLoader, KBEntry

_REQUIRED_FIELDS = ["pattern_id", "title", "description"]


class ATTCKLoader(BaseLoader):
    """Loads MITRE ATT&CK Enterprise technique entries from JSON seed data."""

    def __init__(self) -> None:
        super().__init__(source=KBSource.ATT_AND_CK)

    def load(self, data_path: Path) -> list[KBEntry]:
        """Load ATT&CK entries from a JSON seed file.

        Args:
            data_path: Path to ``attck_seed.json`` (or full STIX bundle
                       in Week 3).

        Returns:
            List of ``KBEntry`` objects, one per valid ATT&CK technique.
            Each entry carries the MITRE tactic IDs for kill-chain ordering.

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
