"""Build the full-KB retrieval evaluation set (labels fixed BEFORE any tuning).

Relevance is graded:
    2 = expert-cited pattern ("seed"): from the company document (section 2.5),
        our earlier hand labels, or engineer-authored seeds for held-out systems.
    1 = MITRE cross-reference neighbour of a seed (CAPEC related patterns,
        CAPEC<->CWE related weaknesses, CAPEC->ATT&CK taxonomy mappings,
        CWE parent/child/peer links, ATT&CK technique<->sub-technique).

Neighbour links come from MITRE's own data, never from our embeddings, so the
labels do not depend on the system being measured.  A seed with more than
``HUB_LIMIT`` links is treated as a hub and contributes no grade-1 neighbours
(otherwise broad parents such as CWE-287 would label hundreds of patterns).

Splits:
    dev      - the 6 queries of the original benchmark (used to choose weights)
    company  - the company document's smart-door-lock threats T1-T6 (not tuned on)
    heldout  - two systems never used in development: vehicle gateway ECU and
               industrial PLC (not tuned on)

LIMITATION: heldout seeds are engineer-authored and need expert review.

    python tests/threat_agent/research/build_fullkb_eval_dataset.py
"""

from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET  # noqa: S405
from collections import defaultdict
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_ROOT))

from kb.loaders.full_loaders import ATTCKSTIXLoader, CAPECXMLLoader, CWEXMLLoader  # noqa: E402

FULL = _ROOT / "kb" / "data" / "full"
OUT = Path(__file__).resolve().parent / "retrieval_eval_fullkb.json"
HUB_LIMIT = 30

_CAPEC_NATURES = {"ChildOf", "ParentOf", "PeerOf", "CanPrecede", "CanFollow", "CanAlsoBe"}
_CWE_NATURES = {"ChildOf", "ParentOf", "PeerOf", "CanPrecede", "CanFollow", "CanAlsoBe"}


def _ns(root: ET.Element) -> dict[str, str]:
    return {"n": root.tag.split("}")[0][1:]}


def build_graph(known: set[str]) -> dict[str, set[str]]:
    g: dict[str, set[str]] = defaultdict(set)

    def link(a: str, b: str) -> None:
        if a in known and b in known and a != b:
            g[a].add(b)
            g[b].add(a)

    capec = ET.parse(FULL / "capec_latest.xml").getroot()  # noqa: S314
    ns = _ns(capec)
    for ap in capec.findall(".//n:Attack_Pattern", ns):
        cid = f"CAPEC-{ap.get('ID')}"
        for r in ap.findall("n:Related_Attack_Patterns/n:Related_Attack_Pattern", ns):
            if r.get("Nature") in _CAPEC_NATURES:
                link(cid, f"CAPEC-{r.get('CAPEC_ID')}")
        for r in ap.findall("n:Related_Weaknesses/n:Related_Weakness", ns):
            link(cid, f"CWE-{r.get('CWE_ID')}")
        for tm in ap.findall("n:Taxonomy_Mappings/n:Taxonomy_Mapping", ns):
            if tm.get("Taxonomy_Name") == "ATTACK":
                eid = (tm.findtext("n:Entry_ID", default="", namespaces=ns) or "").strip()
                if eid:
                    link(cid, f"ATT&CK-T{eid.lstrip('T')}")

    cwe = ET.parse(FULL / "cwec_latest.xml").getroot()  # noqa: S314
    ns = _ns(cwe)
    for w in cwe.findall(".//n:Weakness", ns):
        wid = f"CWE-{w.get('ID')}"
        for r in w.findall("n:Related_Weaknesses/n:Related_Weakness", ns):
            if r.get("Nature") in _CWE_NATURES:
                link(wid, f"CWE-{r.get('CWE_ID')}")
        for r in w.findall("n:Related_Attack_Patterns/n:Related_Attack_Pattern", ns):
            link(wid, f"CAPEC-{r.get('CAPEC_ID')}")

    for k in list(known):
        if k.startswith("ATT&CK-T") and "." in k:
            link(k, k.split(".")[0])
    return g


def expand(seeds: list[str], graph: dict[str, set[str]]) -> dict[str, int]:
    rel = {s: 2 for s in seeds}
    for s in seeds:
        nbrs = graph.get(s, set())
        if len(nbrs) > HUB_LIMIT:
            continue
        for n in nbrs:
            rel.setdefault(n, 1)
    return rel


_ATTR_NAMES = {"C": "confidentiality", "I": "integrity", "A": "availability", "Auth": "authenticity"}


def _attrs(*keys: str) -> dict[str, bool]:
    return {name: key in keys for key, name in _ATTR_NAMES.items()}


# Security attributes per dev query (inputs only; authored from the asset's role, not from labels).
_DEV_ATTRS = {
    "SDL-Q1": _attrs("I", "A", "Auth"), "SDL-Q2": _attrs("C", "I"),
    "SDL-Q3": _attrs("C", "I", "A", "Auth"), "SDL-Q4": _attrs("C", "I", "Auth"),
    "INF-Q1": _attrs("I", "A", "Auth"), "INF-Q2": _attrs("C", "I", "A", "Auth"),
}


def _asset(aid: str, name: str, typ: str, ifaces: list[str], zone: str, cfg: dict[str, str],
           attrs: dict[str, bool] | None = None) -> dict:
    return {"asset_id": aid, "name": name, "asset_type": typ, "interfaces": ifaces,
            "trust_zone": zone, "device_config": cfg, "security_attributes": attrs or {}}


def queries() -> list[dict]:
    q: list[dict] = []

    # ---- dev: original 6 benchmark queries, their hand labels are the seeds
    old = json.loads((Path(__file__).resolve().parent / "retrieval_eval_dataset.json")
                     .read_text(encoding="utf-8"))
    for item in old["labeled_queries"]:
        q.append({
            "query_id": item["query_id"], "split": "dev", "fixture": item["fixture"],
            "asset": _asset(item["asset_id"], item["asset_name"], item["asset_type"],
                            item["interfaces"], item["trust_zone"], item.get("device_config", {}),
                            _DEV_ATTRS[item["query_id"]]),
            "seeds": list(item["relevant_patterns"]),
        })

    # ---- company: smart door lock, threats T1-T6 of the company document (section 2.5)
    sdl = json.loads((_ROOT / "tests/threat_agent/e2e/fixtures/smart_door_lock/input.json")
                     .read_text(encoding="utf-8"))
    by_id = {a["asset_id"]: a for a in sdl["assets"]}
    company = {  # asset -> (threat ids, strict company references, accepted alternates)
        "AS-1": ("T1,T5", ["CAPEC-94", "CAPEC-125"], []),
        "AS-2": ("T2", ["ATT&CK-T1078", "ATT&CK-T1566"], []),
        "AS-3": ("T3", ["CAPEC-186"], []),
        "AS-5": ("T4", ["CAPEC-117"], []),
        # The document cites CAPEC-189 for "side-channel"; in CAPEC v3.9 that ID is
        # "Black Box Reverse Engineering".  CAPEC-622 (EM side-channel) is accepted too.
        "AS-6": ("T6", ["CAPEC-189"], ["CAPEC-622"]),
    }
    for aid, (tids, strict, alt) in company.items():
        a = by_id[aid]
        q.append({
            "query_id": f"CO-{aid}", "split": "company", "fixture": "Smart Door Lock (company doc)",
            "threat_ids": tids,
            "asset": _asset(aid, a["name"], a["asset_type"], a["dfd_context"]["interfaces"],
                            a["dfd_context"]["trust_zone"], a["device_config"],
                            a["security_attributes"]),
            "seeds": strict + alt, "strict_seeds": strict,
        })

    # ---- heldout: two systems not used in development
    held = [
        ("VE-AS1", "Vehicle gateway ECU", _asset("AS-1", "Gateway ECU Firmware", "embedded firmware",
            ["CAN bus", "OBD-II", "LTE"], "untrusted", {"secure_boot": "none", "can_authentication": "none"},
            _attrs("I", "A", "Auth")),
         ["CAPEC-186", "CWE-347", "CWE-345", "CWE-1277", "ATT&CK-T1693", "ATT&CK-T0800"]),
        ("VE-AS2", "Vehicle gateway ECU", _asset("AS-2", "Diagnostic Session", "diagnostic service",
            ["UDS over CAN", "OBD-II"], "external", {"seed_key": "static", "session_timeout": "none"},
            _attrs("C", "I", "Auth")),
         ["CWE-798", "CWE-294", "CAPEC-60", "CAPEC-112", "CWE-306", "CWE-307"]),
        ("VE-AS3", "Vehicle gateway ECU", _asset("AS-3", "Telematics Backend API", "REST API",
            ["HTTPS", "MQTT"], "external", {"auth": "api-key", "rate_limit": "none"},
            _attrs("C", "A", "Auth")),
         ["CWE-306", "CWE-770", "CWE-799", "CAPEC-125", "CWE-287", "ATT&CK-T1078"]),
        ("PLC-AS1", "Industrial PLC", _asset("AS-1", "Modbus/TCP Control Channel", "control protocol",
            ["Modbus/TCP", "Ethernet"], "internal", {"authentication": "none", "encryption": "none"},
            _attrs("I", "A", "Auth")),
         ["CWE-306", "CWE-319", "CAPEC-94", "CAPEC-117", "CWE-294", "ATT&CK-T0836"]),
        ("PLC-AS2", "Industrial PLC", _asset("AS-2", "PLC Logic Program", "controller firmware program",
            ["Engineering port", "Ethernet"], "trusted", {"program_signing": "none", "change_audit": "none"},
            _attrs("I", "Auth")),
         ["CWE-345", "CWE-494", "ATT&CK-T0889", "ATT&CK-T0821", "CWE-306"]),
        ("PLC-AS3", "Industrial PLC", _asset("AS-3", "Engineering Workstation Credentials", "access credential",
            ["RDP", "SMB"], "internal", {"password_policy": "weak", "mfa": "none"},
            _attrs("C", "Auth")),
         ["ATT&CK-T1078", "ATT&CK-T1110", "CWE-798", "CWE-521", "CAPEC-112"]),
    ]
    for qid, fixture, asset, seeds in held:
        q.append({"query_id": qid, "split": "heldout", "fixture": fixture, "asset": asset, "seeds": seeds})
    return q


def main() -> None:
    known: set[str] = set()
    for loader, name in [(CAPECXMLLoader(), "capec_latest.xml"), (CWEXMLLoader(), "cwec_latest.xml"),
                         (ATTCKSTIXLoader(), "enterprise-attack.json"), (ATTCKSTIXLoader(), "ics-attack.json")]:
        known |= {e.pattern_id for e in loader.load(FULL / name)}
    graph = build_graph(known)

    qs = queries()
    for item in qs:
        # STRIDE-* seed patterns (our own entries) have no MITRE links; they stay as seeds.
        missing = [s for s in item["seeds"] if s not in known and not s.startswith("STRIDE-")]
        assert not missing, f"{item['query_id']}: seeds not in the full KB: {missing}"
        item["relevant"] = expand(item["seeds"], graph)

    OUT.write_text(json.dumps({
        "name": "retrieval_eval_fullkb",
        "kb_source": "MITRE CAPEC v3.9, CWE v4.20, ATT&CK (Enterprise+ICS) + STRIDE seeds",
        "hub_limit": HUB_LIMIT,
        "grades": {"2": "expert-cited seed", "1": "MITRE cross-reference neighbour"},
        "queries": qs,
    }, indent=1, ensure_ascii=False), encoding="utf-8")
    for item in qs:
        g2 = sum(1 for v in item["relevant"].values() if v == 2)
        g1 = sum(1 for v in item["relevant"].values() if v == 1)
        print(f"{item['query_id']:9s} {item['split']:8s} seeds={g2:2d} neighbours={g1:3d}")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
