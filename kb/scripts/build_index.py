"""
kb/scripts/build_index.py
══════════════════════════════════════════════════════════════════════════════
TRC Engine — Phase 1  |  FAISS Index Builder  (Aryan)
──────────────────────────────────────────────────────────────────────────────
CLI script that loads all KB seed data, embeds entries with
sentence-transformers, and writes a FAISS IndexFlatIP binary + a
kb_metadata.json sidecar.

Usage::

    python -m kb.scripts.build_index

    # Or with explicit paths (overrides config):
    python -m kb.scripts.build_index \\
        --data-dir kb/data \\
        --index-path kb/data/threat_agent.faiss \\
        --metadata-path kb/data/kb_metadata.json \\
        --model all-MiniLM-L6-v2

Output files:
    ``<FAISS_INDEX_PATH>``  — FAISS IndexFlatIP binary (cosine similarity)
    ``<KB_DATA_DIR>/kb_metadata.json``  — FAISS ID → KBEntry dict

Index type: ``faiss.IndexFlatIP``
    Inner-product (cosine similarity) after L2-normalisation.
    No training required.  Exact nearest-neighbour search.
    Sufficient for < 5,000 KB entries (Week 3: upgrade to IndexIVFFlat).

Embedding model: ``all-MiniLM-L6-v2`` (384-dim, CPU-only)
    Sentence transformer; weights downloaded on first run.
    Model name is overridable via ``EMBEDDING_MODEL_NAME`` in settings.py.

Re-run this script whenever:
    1. New entries are added to a seed JSON file.
    2. A new seed file is added.
    3. The embedding model is changed.
    4. Full CAPEC/ATT&CK/CWE XML files are added (Week 3).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# ── Dependency guards with helpful error messages ─────────────────────────

try:
    import faiss  # type: ignore[import-untyped]
except ImportError as e:
    print(
        "[ERROR] faiss-cpu is not installed.\n"
        "Run: pip install faiss-cpu\n"
        f"Original error: {e}",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    import numpy as np
    from sentence_transformers import SentenceTransformer
except ImportError as e:
    print(
        "[ERROR] sentence-transformers or numpy is not installed.\n"
        "Run: pip install sentence-transformers numpy\n"
        f"Original error: {e}",
        file=sys.stderr,
    )
    sys.exit(1)

from kb.loaders.attck_loader import ATTCKLoader
from kb.loaders.base_loader import KBEntry
from kb.loaders.capec_loader import CAPECLoader
from kb.loaders.cwe_loader import CWELoader
from kb.loaders.stride_loader import STRIDELoader

# ── Loader registry — add new loaders here in Week 3 ──────────────────────

_LOADER_MAP: list[tuple[object, str]] = [
    (CAPECLoader(), "capec_seed.json"),
    (ATTCKLoader(), "attck_seed.json"),
    (CWELoader(), "cwe_seed.json"),
    (STRIDELoader(), "stride_seed.json"),
]


# ── Core build functions ───────────────────────────────────────────────────


def _load_all_entries(data_dir: Path) -> list[KBEntry]:
    """Run all loaders and return the merged entry list.

    Args:
        data_dir: Directory containing the seed JSON files.

    Returns:
        Merged, deduplicated list of ``KBEntry`` objects.
    """
    all_entries: list[KBEntry] = []
    seen: set[str] = set()

    for loader, filename in _LOADER_MAP:
        data_path = data_dir / filename
        if not data_path.exists():
            print(f"  [SKIP] {filename} not found in {data_dir}", file=sys.stderr)
            continue

        entries = loader.load(data_path)  # type: ignore[union-attr]
        added = 0
        for entry in entries:
            key = f"{entry.source}::{entry.pattern_id}"
            if key not in seen:
                seen.add(key)
                all_entries.append(entry)
                added += 1
            else:
                print(
                    f"  [DEDUP] Skipping duplicate {key}",
                    file=sys.stderr,
                )

        print(
            f"  [LOAD] {loader.source}: {added} entries loaded from {filename}",  # type: ignore[union-attr]
            file=sys.stderr,
        )

    return all_entries


def _embed_entries(
    entries: list[KBEntry],
    model_name: str,
) -> np.ndarray:  # type: ignore[type-arg]
    """Embed all KB entries using the sentence transformer model.

    Each entry's ``embedding_text()`` (title + description + stride_hint +
    tactic IDs) is embedded into a 384-dim vector and L2-normalised so that
    inner-product search equals cosine similarity.

    Args:
        entries:    List of ``KBEntry`` objects to embed.
        model_name: Sentence transformer model name / HuggingFace model ID.

    Returns:
        float32 numpy array of shape (len(entries), embedding_dim),
        L2-normalised.
    """
    print(f"  [EMBED] Loading model '{model_name}'…", file=sys.stderr)
    model = SentenceTransformer(model_name)

    texts = [e.embedding_text() for e in entries]
    print(
        f"  [EMBED] Encoding {len(texts)} entries…",
        file=sys.stderr,
    )
    embeddings: np.ndarray = model.encode(  # type: ignore[assignment]
        texts,
        normalize_embeddings=True,
        show_progress_bar=True,
        batch_size=32,
    )
    return embeddings.astype(np.float32)


def _build_faiss_index(
    embeddings: np.ndarray,  # type: ignore[type-arg]
) -> faiss.IndexFlatIP:
    """Build a FAISS IndexFlatIP from L2-normalised embeddings.

    ``IndexFlatIP`` performs exact inner-product (cosine) search.
    No training step required.

    Args:
        embeddings: float32 array of shape (n_entries, embedding_dim).

    Returns:
        A populated ``faiss.IndexFlatIP`` ready for ``search()``.
    """
    dim = embeddings.shape[1]
    index = faiss.IndexFlatIP(dim)
    index.add(embeddings)
    print(
        f"  [FAISS] Built IndexFlatIP: {index.ntotal} vectors, dim={dim}",
        file=sys.stderr,
    )
    return index


def _save_outputs(
    index: faiss.IndexFlatIP,
    entries: list[KBEntry],
    index_path: Path,
    metadata_path: Path,
) -> None:
    """Persist the FAISS index binary and the metadata JSON sidecar.

    The metadata JSON maps FAISS integer ID (as string) → KBEntry dict.
    FAISS assigns IDs 0, 1, 2, … in the order entries were added, so
    metadata[str(i)] corresponds to entries[i].

    Args:
        index:         Populated FAISS index.
        entries:       KBEntry list in the same order as index vectors.
        index_path:    Destination path for the FAISS binary.
        metadata_path: Destination path for the JSON metadata sidecar.
    """
    # Write FAISS binary
    index_path.parent.mkdir(parents=True, exist_ok=True)
    faiss.write_index(index, str(index_path))
    print(f"  [SAVE] FAISS index written to {index_path}", file=sys.stderr)

    # Write metadata sidecar
    metadata: dict[str, object] = {
        str(i): entry.to_metadata_dict() for i, entry in enumerate(entries)
    }
    metadata_path.write_text(
        json.dumps(metadata, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"  [SAVE] KB metadata written to {metadata_path}", file=sys.stderr)


# ── CLI entry point ────────────────────────────────────────────────────────


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build FAISS index from KB seed data.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("kb/data"),
        help="Directory containing seed JSON files.",
    )
    parser.add_argument(
        "--index-path",
        type=Path,
        default=Path("kb/data/threat_agent.faiss"),
        help="Output path for the FAISS binary.",
    )
    parser.add_argument(
        "--metadata-path",
        type=Path,
        default=Path("kb/data/kb_metadata.json"),
        help="Output path for the KB metadata JSON sidecar.",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="all-MiniLM-L6-v2",
        help="Sentence transformer model name.",
    )
    return parser.parse_args()


def build(
    data_dir: Path = Path("kb/data"),
    index_path: Path = Path("kb/data/threat_agent.faiss"),
    metadata_path: Path = Path("kb/data/kb_metadata.json"),
    model_name: str = "all-MiniLM-L6-v2",
) -> None:
    """Programmatic entry point for build_index (usable from tests / CI).

    Args:
        data_dir:      Directory containing seed JSON files.
        index_path:    Output FAISS binary path.
        metadata_path: Output metadata JSON path.
        model_name:    Sentence transformer model name.
    """
    print("[BUILD] Starting KB index build…", file=sys.stderr)
    entries = _load_all_entries(data_dir)

    if not entries:
        print("[ERROR] No KB entries loaded. Check seed files.", file=sys.stderr)
        sys.exit(1)

    print(
        f"[BUILD] Total entries to embed: {len(entries)}",
        file=sys.stderr,
    )
    embeddings = _embed_entries(entries, model_name)
    index = _build_faiss_index(embeddings)
    _save_outputs(index, entries, index_path, metadata_path)
    print(
        f"[BUILD] Done. Index contains {index.ntotal} vectors.",
        file=sys.stderr,
    )


if __name__ == "__main__":
    args = _parse_args()
    build(
        data_dir=args.data_dir,
        index_path=args.index_path,
        metadata_path=args.metadata_path,
        model_name=args.model,
    )
