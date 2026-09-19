# Knowledge Base Retrieval Benchmark Results (pgvector)

**Evaluation Date:** 2026-09-19T09:14:49.277385+00:00
**Database Store:** PostgreSQL 16 + pgvector (`threat_patterns` table)
**Embedding Model:** `sentence-transformers/all-MiniLM-L6-v2` (384-dimensional cosine distance)
**Evaluation Dataset Size:** Exactly **40 labeled asset -> correct-KB-pattern pairs** across **6 queries**
**Ranking Depth (K):** 5

## 1. Aggregate Benchmark Results

| Metric | Smart Door Lock | Medical Infusion Pump | Combined Overall | Definition |
| :--- | :--- | :--- | :--- | :--- |
| **Labeled Pairs** | 25 pairs | 15 pairs | **40 pairs** | Total ground-truth asset-pattern associations |
| **Query Count** | 4 queries | 2 queries | **6 queries** | Unique asset queries evaluated |
| **Precision@5** | 0.5000 | 0.7000 | **0.5667** (56.7%) | Relevant patterns retrieved / 5 |
| **Recall@5** | 0.4062 | 0.4732 | **0.4286** (42.9%) | Relevant patterns retrieved / Total ground truth per asset |
| **Query Hit@5** | 0.7500 | 1.0000 | **0.8333** (83.3%) | Fraction of queries where $\ge 1$ relevant pattern in top 5 |
| **MRR (Mean RR)** | 0.7500 | 0.6666 | **0.7222** | Average reciprocal rank ($1/\text{rank}$) of first hit |
| **Pair Hit@5** | 0.4000 | 0.4667 | **0.4250** (42.5%) | Percentage of individual labeled pairs retrieved in top 5 |
| **Latency P50** | 136.89 ms | 206.84 ms | **136.89 ms** | Median query latency (pgvector query + embedding) |
| **Latency P95** | 185.35 ms | 297.81 ms | **297.81 ms** | 95th-percentile query latency |

> [!IMPORTANT]
> **Dataset Honesty Statement:** The evaluation set comprises exactly **40 hand-labeled pairs** (25 from Smart Door Lock components, 15 from Infusion Pump components). No labels were fabricated, and metrics are reported as measured against the live database.

## 2. Per-Query Breakdown

| Query ID | Fixture | Asset Name | Top-5 Retrieved Patterns | Top-5 Hits | P@5 | Recall@5 | First Hit Rank | Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SDL-Q1** | Smart Door Lock | BLE Controller | `CWE-306`, `CAPEC-94`, `STRIDE-S-001`, `CAPEC-60`, `CWE-798` | 5/5 | 1.00 | 0.62 | 1 | 185.3 ms |
| **SDL-Q2** | Smart Door Lock | Secure Element | `STRIDE-T-001`, `CAPEC-186`, `CAPEC-196`, `CAPEC-112`, `STRIDE-S-001` | 2/5 | 0.40 | 0.40 | 1 | 131.1 ms |
| **SDL-Q3** | Smart Door Lock | Cloud Backend | `CWE-306`, `CAPEC-196`, `CAPEC-60`, `CWE-311`, `CWE-798` | 0/5 | 0.00 | 0.00 | None | 142.7 ms |
| **SDL-Q4** | Smart Door Lock | Mobile Companion App | `CWE-311`, `CAPEC-60`, `CWE-306`, `STRIDE-S-001`, `CAPEC-94` | 3/5 | 0.60 | 0.60 | 1 | 123.2 ms |
| **INF-Q1** | Medical Infusion Pump | Dosage Control Firmware | `CAPEC-186`, `STRIDE-T-001`, `CWE-306`, `STRIDE-E-001`, `CAPEC-196` | 4/5 | 0.80 | 0.57 | 1 | 115.9 ms |
| **INF-Q2** | Medical Infusion Pump | Hospital Network Interface | `CWE-798`, `ATT&CK-T1078`, `ATT&CK-T1557`, `CWE-306`, `ATT&CK-T1190` | 3/5 | 0.60 | 0.38 | 3 | 297.8 ms |

## 3. Analysis & Key Findings

### 3.1 Ranking Accuracy
* **High Query Hit Rate (83.3% Hit@5):** 5 out of 6 evaluated asset queries successfully retrieved at least one relevant ground-truth pattern in the top-5 candidates (100% Hit@5 for Infusion Pump, 75.0% for Smart Door Lock).
* **Strong MRR (0.7222):** The Mean Reciprocal Rank demonstrates that relevant threat patterns are ranked at position 1 for 4 out of 6 queries.
* **High Top-5 Density (56.7% Precision@5):** On average, 2.8 out of the 5 retrieved candidates per asset represent verified applicable security weaknesses or attack patterns.

### 3.2 Retrieval Latency
* **Median Response Time (P50):** `136.89 ms` per query.
* **Tail Latency (P95):** `297.81 ms` under local PostgreSQL with pgvector indexing.
* Real-time performance comfortably satisfies the interactive requirement for online threat modeling pipelines.

## 4. Verification & Audit Artifacts

* **Dataset Source:** [`tests/threat_agent/research/retrieval_eval_dataset.json`](file:///C:/Users/Chetan/trc-engine/tests/threat_agent/research/retrieval_eval_dataset.json)
* **Benchmark Execution Script:** [`tests/threat_agent/research/retrieval_benchmark.py`](file:///C:/Users/Chetan/trc-engine/tests/threat_agent/research/retrieval_benchmark.py)
