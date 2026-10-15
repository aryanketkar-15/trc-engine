# 01 · The knowledge base explained: sources, contents, fields

## 1. What a "knowledge base" means here

A library of **known ways to attack a system** plus **security-standard text**. The Threat Agent reads an asset
(for example "firmware image, updated over Bluetooth"), searches this library for the closest matching attacks, and
the AI then writes a threat scenario that **cites** one of them. The library is why a scenario can say
"this is based on CAPEC-186", not just "an attacker might do something".

## 2. Where each part came from

All files were downloaded from the official publishers on the dates shown and are **not modified**, except that we
skipped deprecated and revoked entries.

### 2.1 Attack patterns (`threat_patterns`, 2,300 rows)

| Source | What it is | Official URL we downloaded | Version | Rows | What we kept |
|---|---|---|---|---:|---|
| **CAPEC** | Catalogue of common **attack patterns** (how attackers typically do something) | `https://capec.mitre.org/data/xml/capec_latest.xml` | 3.9 (2023-01-24) | 556 | Attack patterns; deprecated/obsolete skipped |
| **CWE** | Catalogue of software and hardware **weaknesses** (the mistakes attacks exploit) | `https://cwe.mitre.org/data/xml/cwec_latest.xml.zip` | 4.20 (2026-04-30) | 944 | Weaknesses; deprecated skipped. 101 reachable from the CWE *Hardware Design* view carry the marker `[Hardware design weakness]` in the text |
| **MITRE ATT&CK, Enterprise** | **Techniques** that real attackers use (IT systems) | `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json` | 19.2 (2026-08-05) | 697 | Techniques and sub-techniques; revoked/deprecated skipped |
| **MITRE ATT&CK, ICS** | Techniques for **industrial control systems** | `.../master/ics-attack/ics-attack.json` | 19.2 (2026-08-05) | 97 | Same filters; these rows get the tag `ics` |
| **STRIDE** (ours) | Six rules, one per STRIDE type (our own seed entries) | `kb/data/stride_seed.json` in our repo | – | 6 | Written by us; kept so older labels still resolve |

**Not included on purpose:** ATT&CK *Mobile*, ATT&CK mitigations and tactics as separate entries, MITRE EMB3D (licence terms
not checked), anything from the company.

### 2.2 Standards text (`standards_chunks`, 5,097 rows)

Reference text only: **no rules or mappings are encoded.** Cut into pieces (about 900 characters each).

| Document | Official source | Pieces |
|---|---|---:|
| Common Criteria CC:2022 R1, Part 1 | commoncriteriaportal.org | 551 |
| CC:2022 R1, Part 2 | commoncriteriaportal.org | 1,017 |
| CC:2022 R1, Part 3 | commoncriteriaportal.org | 735 |
| CC:2022 R1, Part 4 | commoncriteriaportal.org | 93 |
| CC:2022 R1, Part 5 | commoncriteriaportal.org | 104 |
| CEM:2022 R1 (evaluation methodology) | commoncriteriaportal.org | 1,907 |
| JIL "Application of Attack Potential to Smartcards" v3.2.1 | sogis.eu | 221 |
| Regulation (EU) 2024/2847, the **Cyber Resilience Act** | publications.europa.eu (CELEX 32024R2847) | 469 |

**Why these:** your TARA workflow ends with "map required resistance to JIL / SESIP / CC EAL" and the EU law is the
reason for the whole exercise. These are the **free** parts.

### 2.3 What is deliberately NOT in the library

| Item | Reason |
|---|---|
| ISO/SAE 21434 | Paid standard; we have no licence |
| GlobalPlatform SESIP | Free to download but no stable link and reuse terms are not stated ("all rights reserved") |
| IEC 62443, ISO 27001/27002 | Paid |
| The company's own internal patterns | We do not have them (we asked) |

## 3. Reuse and licensing (important)

* MITRE's CAPEC, CWE and ATT&CK are used under MITRE's royalty-free licence for research, development and commercial
  use. **You must keep the copyright notice** (`legal/NOTICE_MITRE.md`). The data is provided "as is".
* Common Criteria Parts 1–5: the portal states usage rights are granted, including re-use of text.
* CEM, JIL: freely downloadable, **reuse terms not confirmed**. Do not republish them outside the project.
* CRA: EU legislation; reuse is generally permitted (not separately verified).
* See `legal/NOTICE_STANDARDS.md` for the exact wording we recorded.

## 4. The two tables

### `threat_patterns`

| Column | Meaning | Example |
|---|---|---|
| `id` | Row number in the database (not stable across rebuilds; do not use as a key) | 1034 |
| `source` | Which catalogue: `CAPEC`, `ATT&CK`, `CWE`, `STRIDE` | `CAPEC` |
| `pattern_id` | The ID you cite (see formats below). **Unique together with `source`** | `CAPEC-622` |
| `title` | Official name | `Electromagnetic Side-Channel Attack` |
| `description` | Official description text | "…the attacker passively monitors electromagnetic emanations…" |
| `embedding` | 384 numbers that represent the meaning of title + description (+ STRIDE hint + tactics) | – |
| `metadata` | JSON with extra fields (below) | – |

`pattern_id` formats: `CAPEC-<n>`, `CWE-<n>`, `ATT&CK-T<nnnn>` or `ATT&CK-T<nnnn>.<nnn>` for sub-techniques
(ICS ones look like `ATT&CK-T0800`), `STRIDE-<S|T|R|I|D|E>-001`.

`metadata` keys:

| Key | Meaning | Reliability |
|---|---|---|
| `stride_hint` | Which STRIDE type this pattern most resembles (`Spoofing`, `Tampering`, …) | **Heuristic**: inferred by keyword rules for 714 of 2,300 rows; not MITRE data |
| `mitre_tactics` | ATT&CK tactic IDs (for example `TA0005`) | From ATT&CK |
| `domain_tags` | Topic tags: wireless, web, credentials, network, cloud, crypto, hardware, ics, firmware, physical, mobile, automotive | **Heuristic**: keyword rules; used only to help ranking |

Domain-tag counts: wireless 1,257 · web 927 · credentials 510 · network 497 · cloud 465 · crypto 333 · hardware 281 · ics 117 ·
firmware 80 · physical 69 · mobile 35 · automotive 1. (A pattern can have several tags.)

### `standards_chunks`

| Column | Meaning | Example |
|---|---|---|
| `standard` | `Common Criteria`, `JIL` or `EU CRA` | `JIL` |
| `doc` | The document | `JIL Application of Attack Potential to Smartcards v3.2.1` |
| `locator` | Where in the document. PDFs: `p. <PDF page index>.<piece>` (this is the **PDF page index, not the printed page number**). CRA: `Art. 13.2` (article 13, piece 2) or `Recital 51.4` (annexes are not separate) | `p. 31.1` |
| `title` | Often empty | |
| `text` | The text of the piece | |
| `embedding`, `metadata` | as above | |

## 4a. Numbers at a glance

| | Count |
|---|---:|
| Attack patterns | 2,300 (CWE 944 · ATT&CK 794 · CAPEC 556 · STRIDE 6) |
| Standards pieces | 5,097 |
| Embedding size | 384 numbers per row, unit length |

## 5. Quality: what to expect (honest)

* It finds **sensible** matches for typical questions (for example "firmware update over Bluetooth" returns
  *System Firmware*, *Bluetooth Impersonation Attacks*, *Firmware Not Updateable*).
* Search is **by meaning**, so similarity scores are modest (0.4–0.8 is normal). A score is **not** a probability.
* It is a **general** library. On the company's six reference threats we match 1 of 6 at our threshold, because their
  hardware/internal knowledge is not in public catalogues in the same wording.
* Heuristic fields (`stride_hint`, `domain_tags`) are helpers. Do not present them as MITRE facts.
* Hardware weaknesses can appear for non-hardware assets. We reduce this with a small ranking penalty (see file 02).
* CAPEC is v3.9 (2023): newer catalogue entries may be missing.

## 6. How to refresh it yourself

We include the exact downloads in `data/MANIFEST.json` (SHA-256 of each source file we used). To rebuild from the
publishers, use the scripts in our repository (`kb/scripts/fetch_full_kb.py`, `build_full_index.py`,
`fetch_standards_kb.py`, `build_standards_index.py`). A rebuild with newer files will produce different counts and
vectors, so **do not mix** a rebuilt library with scenarios or labels created against this version.
