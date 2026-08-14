"""
kb/loaders/stride_loader.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1  |  STRIDE Loader  (Aryan)
──────────────────────────────────────────────────────────────────────────────
Loads STRIDE threat-category entries from a JSON seed file and produces
``KBEntry`` objects.

Unlike CAPEC/ATT&CK/CWE loaders, the STRIDE loader works from our own
curated vocabulary (``kb/data/stride_seed.json``) — there is no external
download.  Each entry encapsulates a domain-neutral threat description for
one of the six STRIDE categories.

Seed format (``kb/data/stride_seed.json``):
    JSON array of objects, each with:
      - pattern_id:    str  e.g. "STRIDE-S-001"
      - title:         str  Threat name
      - description:   str  Full technical description
      - stride_hint:   str  STRIDE category (always present for STRIDE entries)
      - mitre_tactics: list[str]  Optional ATT&CK tactic IDs

The STRIDE_VECTOR_VOCABULARY in retrieval.py provides the keyword sets used
at plan() time to generate FAISS query text.  The STRIDE loader provides the
actual pattern entries that back those queries in the KB.

Note on ``stride_hint``:
    For STRIDE entries, ``stride_hint`` is REQUIRED (not optional) since the
    category is the primary classification.  The loader enforces this by
    treating a missing hint as a ``MalformedKBEntryError``.
"""

from __future__ import annotations

from pathlib import Path

from agents.threat_agent.exceptions import MalformedKBEntryError
from agents.threat_agent.schemas import KBSource
from kb.loaders.base_loader import BaseLoader, KBEntry

_REQUIRED_FIELDS = ["pattern_id", "title", "description", "stride_hint"]


class STRIDELoader(BaseLoader):
    """Loads STRIDE threat-category entries from JSON seed data."""

    def __init__(self) -> None:
        super().__init__(source=KBSource.STRIDE)

    def load(self, data_path: Path) -> list[KBEntry]:
        """Load STRIDE entries from the curated JSON seed file.

        Unlike other loaders, ``stride_hint`` is mandatory for every STRIDE
        entry — a missing hint raises ``MalformedKBEntryError`` immediately.

        Args:
            data_path: Path to ``stride_seed.json``.

        Returns:
            List of ``KBEntry`` objects, one per STRIDE entry.
            Typically 6 entries (one per STRIDE category), but the seed
            may contain multiple entries per category for richer retrieval.

        Raises:
            FileNotFoundError:     If ``data_path`` does not exist.
            MalformedKBEntryError: If any entry is missing ``stride_hint``
                                   or fails other validation.
        """
        raw_entries = self._load_json(data_path)
        entries: list[KBEntry] = []

        for raw in raw_entries:
            self._validate_entry(raw, _REQUIRED_FIELDS)

            pattern_id = str(raw["pattern_id"])
            stride_hint = self._parse_stride_hint(
                raw.get("stride_hint"),
                pattern_id=pattern_id,
            )

            # For STRIDE entries, stride_hint is mandatory
            if stride_hint is None:
                raise MalformedKBEntryError(
                    pattern_id=pattern_id,
                    source=str(self._source),
                    validation_error=(
                        "STRIDE entries must have a non-null 'stride_hint'. "
                        "The STRIDE category is the primary classification."
                    ),
                )

            entries.append(
                KBEntry(
                    pattern_id=pattern_id,
                    source=self._source,
                    title=str(raw["title"]),
                    description=str(raw["description"]),
                    stride_hint=stride_hint,
                    mitre_tactics=list(raw.get("mitre_tactics") or []),
                )
            )

        return entries
