# Standards documents notice

Loaded by `kb/scripts/build_standards_index.py` into the separate
`standards_chunks` table (reference text only; no mapping rules are encoded).

| Document | Source | Reuse status |
|---|---|---|
| Common Criteria CC:2022 R1 Parts 1-5 | commoncriteriaportal.org | The CC portal states that usage rights for Parts 1-5 are granted to private, commercial and other users, including re-use of text sections. |
| CEM:2022 R1 | commoncriteriaportal.org | Freely downloadable; the portal statement I verified names CC Parts 1-5, so CEM reuse terms are **not confirmed**. |
| JIL Application of Attack Potential to Smartcards v3.2.1 | sogis.eu (JIL, listed by ENISA) | Publicly downloadable; **reuse terms not verified**. |
| Regulation (EU) 2024/2847 (Cyber Resilience Act) | publications.europa.eu | EU legislation; reuse of EU legal text is generally permitted (not verified in this session). |

## Deliberately NOT loaded

- **ISO/SAE 21434** - paid standard; obtain a licence or written permission from the company.
- **GlobalPlatform SESIP** - free to download via GlobalPlatform, but no stable direct
  link, and reuse terms are not stated ("All rights reserved"). Obtain it manually / ask the company.
- **IEC 62443, ISO 27001/27002** - paid.

Chunks are located by PDF page index (not the printed page number) or CRA article/annex/recital.
Downloaded files are not stored in the repository; run `python -m kb.scripts.fetch_standards_kb`.
