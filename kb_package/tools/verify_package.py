"""Check that the data files in this package are complete and unchanged.

    pip install numpy
    python tools/verify_package.py
"""

import hashlib
import json
from pathlib import Path

import numpy as np

PKG = Path(__file__).resolve().parent.parent
man = json.loads((PKG / "data/MANIFEST.json").read_text(encoding="utf-8"))
ok = True
for name, expected in man["data_file_sha256"].items():
    actual = hashlib.sha256((PKG / "data" / name).read_bytes()).hexdigest()
    status = "ok" if actual == expected else "MISMATCH"
    ok &= actual == expected
    print(f"[{status}] {name}")

pats = [json.loads(x) for x in (PKG / "data/threat_patterns.jsonl").read_text("utf-8").splitlines()]
chunks = [json.loads(x) for x in (PKG / "data/standards_chunks.jsonl").read_text("utf-8").splitlines()]
ep = np.load(PKG / "data/threat_patterns_embeddings.npy")
ec = np.load(PKG / "data/standards_chunks_embeddings.npy")
checks = {
    "patterns rows == embeddings rows": len(pats) == ep.shape[0] == man["patterns"]["count"],
    "chunks rows == embeddings rows": len(chunks) == ec.shape[0] == man["standards_chunks"]["count"],
    "embedding size is 384": ep.shape[1] == ec.shape[1] == 384,
    "vectors are unit length": bool(np.allclose(np.linalg.norm(ep, axis=1), 1, atol=1e-3)),
    "pattern ids unique per source": len({(p["source"], p["pattern_id"]) for p in pats}) == len(pats),
}
for k, v in checks.items():
    print(f"[{'ok' if v else 'FAIL'}] {k}")
    ok &= v
print("patterns by source:", man["patterns"]["by_source"])
print("RESULT:", "package is intact" if ok else "PROBLEM FOUND")
raise SystemExit(0 if ok else 1)
