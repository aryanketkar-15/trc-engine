"""Build the FULL-KB pgvector index into a SEPARATE database.

The Phase 1 baseline KB (24 seed entries in database ``trc_engine``) is left
untouched.  This script writes CAPEC + CWE + ATT&CK (Enterprise + ICS) plus the
STRIDE seed entries into ``--database-name`` (default ``trc_engine_fullkb``).

Usage:
    python -m kb.scripts.fetch_full_kb
    python -m kb.scripts.build_full_index
Then run anything against the full KB with:
    DATABASE_URL=<url ending /trc_engine_fullkb> ...
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path


def _db_name(url: str) -> str:
    return re.search(r"/([^/?]+)(\?.*)?$", url).group(1)  # type: ignore[union-attr]


def _full_db_url(database_name: str) -> str:
    # Settings() (not the cached get_settings()) so the override applied below
    # is what every later get_settings() call sees.
    from config.settings import Settings

    base = Settings().DATABASE_URL
    return re.sub(r"/[^/?]+(\?.*)?$", rf"/{database_name}\1", base)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-name", default="trc_engine_fullkb")
    parser.add_argument("--full-dir", type=Path, default=Path("kb/data/full"))
    parser.add_argument("--seed-dir", type=Path, default=Path("kb/data"))
    parser.add_argument("--model", default="all-MiniLM-L6-v2")
    args = parser.parse_args()

    from config.settings import Settings

    baseline_db = _db_name(Settings().DATABASE_URL)
    if args.database_name == baseline_db:
        sys.exit(f"[ABORT] refusing to write the full KB into baseline DB '{baseline_db}'.")
    os.environ["DATABASE_URL"] = _full_db_url(args.database_name)
    from config.settings import get_settings

    get_settings.cache_clear()
    effective = _db_name(get_settings().DATABASE_URL)
    if effective != args.database_name:
        sys.exit(f"[ABORT] effective DB is '{effective}', expected '{args.database_name}'.")
    print(f"[BUILD] target database: {effective}", file=sys.stderr)

    from kb.loaders.full_loaders import ATTCKSTIXLoader, CAPECXMLLoader, CWEXMLLoader
    from kb.loaders.stride_loader import STRIDELoader
    from kb.scripts import build_index as bi

    entries = []
    ics_entries: list = []
    for loader, path in [
        (CAPECXMLLoader(), args.full_dir / "capec_latest.xml"),
        (CWEXMLLoader(), args.full_dir / "cwec_latest.xml"),
        (ATTCKSTIXLoader(), args.full_dir / "enterprise-attack.json"),
        (ATTCKSTIXLoader(), args.full_dir / "ics-attack.json"),
        (STRIDELoader(), args.seed_dir / "stride_seed.json"),
    ]:
        loaded = loader.load(path)
        if path.name == "ics-attack.json":
            ics_entries.extend(loaded)
        print(f"  [LOAD] {loader.source}: {len(loaded)} from {path.name}", file=sys.stderr)
        entries.extend(loaded)

    # Domain tags (deterministic keyword rules shared with query-time reranking).
    from dataclasses import replace

    from common.domain_tags import tags_for_text

    ics_ids = {e.pattern_id for e in ics_entries}
    tagged = []
    for e in entries:
        tags = set(tags_for_text(f"{e.title} {e.description}"))
        if e.pattern_id in ics_ids:
            tags.add("ics")
        tagged.append(replace(e, domain_tags=sorted(tags)))
    entries = tagged

    seen: set[tuple[str, str]] = set()
    unique = []
    for e in entries:
        key = (str(e.source), e.pattern_id)
        if key not in seen:
            seen.add(key)
            unique.append(e)
    with_hint = sum(1 for e in unique if e.stride_hint is not None)
    print(f"[BUILD] {len(unique)} unique entries; inferred/seed STRIDE hint on {with_hint}",
          file=sys.stderr)

    bi._init_schema()
    embeddings = bi._embed_entries(unique, args.model)
    bi._upsert_entries(unique, embeddings)
    print("[BUILD] Done.", file=sys.stderr)


if __name__ == "__main__":
    main()
