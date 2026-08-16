"""
kb/loaders/base_loader.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1  |  KB Loader Abstract Base  (Aryan)
──────────────────────────────────────────────────────────────────────────────
Every KB loader (CAPEC, ATT&CK, CWE, STRIDE) inherits from BaseLoader and
must implement exactly one method: ``load(data_path)``.

Design rationale
────────────────
• **No duplicate code** (build plan §5): shared validation, logging, and
  STRIDE-hint inference live here.  Concrete loaders only parse the format.
• **Typed intermediate representation**: loaders produce ``KBEntry`` objects
  (a frozen dataclass without asset_id or retrieval_score — those are
  assigned at retrieval time).  ``KBEntry`` → ``KBCandidate`` conversion
  happens in retrieval.py, not here.
• **Fail-loud**: a malformed KB entry raises ``MalformedKBEntryError``
  immediately.  Silent skips are prohibited (build plan §5).
• **Source-stamped**: every ``KBEntry`` carries its ``KBSource`` enum value
  so the FAISS metadata store is self-describing.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agents.threat_agent.exceptions import (
    MalformedKBEntryError,
)
from agents.threat_agent.schemas import KBSource, STRIDECategory

# ── STRIDE hint string → enum map ─────────────────────────────────────────


_STRIDE_STR_MAP: dict[str, STRIDECategory] = {
    "Spoofing": STRIDECategory.SPOOFING,
    "Tampering": STRIDECategory.TAMPERING,
    "Repudiation": STRIDECategory.REPUDIATION,
    "InformationDisclosure": STRIDECategory.INFORMATION_DISCLOSURE,
    "DenialOfService": STRIDECategory.DENIAL_OF_SERVICE,
    "ElevationOfPrivilege": STRIDECategory.ELEVATION_OF_PRIVILEGE,
    # tolerate alternate spacing from seed data authors
    "Information Disclosure": STRIDECategory.INFORMATION_DISCLOSURE,
    "Denial of Service": STRIDECategory.DENIAL_OF_SERVICE,
    "Elevation of Privilege": STRIDECategory.ELEVATION_OF_PRIVILEGE,
}

# ── Internal KB entry representation ──────────────────────────────────────


@dataclass(frozen=True)
class KBEntry:
    """Intermediate representation produced by KB loaders.

    This is NOT a ``KBCandidate`` — it has no ``asset_id`` or
    ``retrieval_score`` because those are assigned at retrieval time when a
    specific asset query is matched against the FAISS index.

    Serialised to ``kb_metadata.json`` alongside the FAISS index binary.
    Deserialised by retrieval.py to reconstruct ``KBCandidate`` objects.

    Attributes:
        pattern_id:    Canonical KB identifier (e.g. 'CAPEC-62').
        source:        KB provenance enum.
        title:         Human-readable pattern name.
        description:   Full text used to generate the embedding vector.
        stride_hint:   Optional STRIDE classification from the KB entry.
        mitre_tactics: ATT&CK tactic IDs (empty list for CAPEC/CWE/STRIDE).
    """

    pattern_id: str
    source: KBSource
    title: str
    description: str
    stride_hint: STRIDECategory | None
    mitre_tactics: list[str] = field(default_factory=list)

    def embedding_text(self) -> str:
        """Return the text that will be embedded into a FAISS vector.

        Concatenates title + description for richer semantic signal.
        STRIDE hint is appended as a keyword when present so the embedding
        captures the threat-category context.
        """
        parts = [self.title, self.description]
        if self.stride_hint is not None:
            parts.append(self.stride_hint.value)
        if self.mitre_tactics:
            parts.append(" ".join(self.mitre_tactics))
        return " ".join(parts)

    def to_metadata_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict for storage in ``kb_metadata.json``."""
        return {
            "pattern_id": self.pattern_id,
            "source": str(self.source),
            "title": self.title,
            "description": self.description,
            "stride_hint": (
                self.stride_hint.value if self.stride_hint is not None else None
            ),
            "mitre_tactics": list(self.mitre_tactics),
        }

    @staticmethod
    def from_metadata_dict(data: dict[str, Any]) -> KBEntry:
        """Deserialise from a ``kb_metadata.json`` record."""
        stride_raw = data.get("stride_hint")
        stride_hint = _STRIDE_STR_MAP.get(stride_raw) if stride_raw else None
        return KBEntry(
            pattern_id=data["pattern_id"],
            source=KBSource(data["source"]),
            title=data["title"],
            description=data["description"],
            stride_hint=stride_hint,
            mitre_tactics=list(data.get("mitre_tactics", [])),
        )


# ── Abstract base loader ───────────────────────────────────────────────────


class BaseLoader(ABC):
    """Abstract base class for all KB loaders.

    Subclasses implement ``load()`` to parse a format-specific data file
    (JSON seed, XML, STIX) into a list of ``KBEntry`` objects.  All shared
    concerns (validation, STRIDE-hint parsing, logging) are handled here.

    Usage::

        loader = CAPECLoader()
        entries = loader.load(Path("kb/data/capec_seed.json"))

    The ``build_index.py`` script calls ``load()`` on all loaders, merges
    the results, embeds them, and writes the FAISS index + metadata.
    """

    def __init__(self, source: KBSource) -> None:
        self._source = source

    @property
    def source(self) -> KBSource:
        return self._source

    @abstractmethod
    def load(self, data_path: Path) -> list[KBEntry]:
        """Parse ``data_path`` and return a list of validated ``KBEntry`` objects.

        Args:
            data_path: Path to the source data file. The format is
                       loader-specific (JSON for seed files, XML for full
                       CAPEC/CWE, STIX JSON for ATT&CK).

        Returns:
            Non-empty list of ``KBEntry`` objects.

        Raises:
            FileNotFoundError:     If ``data_path`` does not exist.
            MalformedKBEntryError: If any entry fails validation.
        """

    # ── Shared helpers ────────────────────────────────────────────────────

    def _load_json(self, data_path: Path) -> list[dict[str, Any]]:
        """Read and parse a JSON file, returning a list of dicts.

        Args:
            data_path: Path to a JSON file containing a top-level array.

        Returns:
            List of raw dicts from the JSON file.

        Raises:
            FileNotFoundError:  If the file does not exist.
            ValueError:         If the file is not valid JSON or not a list.
        """
        if not data_path.exists():
            raise FileNotFoundError(
                f"KB data file not found: {data_path}.  "
                f"Run kb/scripts/build_index.py after placing seed data in kb/data/."
            )
        raw = json.loads(data_path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError(
                f"Expected a JSON array in {data_path}, got {type(raw).__name__}."
            )
        return raw

    def _parse_stride_hint(
        self,
        raw_hint: str | None,
        pattern_id: str,
    ) -> STRIDECategory | None:
        """Parse a raw STRIDE hint string into a ``STRIDECategory`` enum.

        Args:
            raw_hint:   Raw string from KB data (e.g. 'Spoofing').
            pattern_id: Pattern ID for error context.

        Returns:
            ``STRIDECategory`` if the hint is valid, ``None`` if absent.

        Raises:
            MalformedKBEntryError: If hint is present but not a known category.
        """
        if not raw_hint:
            return None
        result = _STRIDE_STR_MAP.get(raw_hint)
        if result is None:
            raise MalformedKBEntryError(
                pattern_id=pattern_id,
                source=str(self._source),
                validation_error=(
                    f"Unknown stride_hint '{raw_hint}'.  "
                    f"Valid values: {list(_STRIDE_STR_MAP.keys())}"
                ),
            )
        return result

    def _validate_entry(
        self,
        entry: dict[str, Any],
        required_fields: list[str],
    ) -> None:
        """Assert that all required fields are present and non-empty strings.

        Args:
            entry:          Raw dict from the KB data file.
            required_fields: Field names that must be non-empty strings.

        Raises:
            MalformedKBEntryError: On the first violation found.
        """
        pattern_id = str(entry.get("pattern_id", "<unknown>"))
        for f in required_fields:
            val = entry.get(f)
            if not val or not str(val).strip():
                raise MalformedKBEntryError(
                    pattern_id=pattern_id,
                    source=str(self._source),
                    validation_error=(f"Required field '{f}' is missing or empty."),
                )
