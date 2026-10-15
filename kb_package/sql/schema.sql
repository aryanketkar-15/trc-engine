-- Schema of the TRC knowledge base (PostgreSQL 14+ with the pgvector extension).
-- Use this only if you load the data from the JSONL/NPY files (tools/import_from_files.py does it for you).
-- If you restore db/trc_kb_tables.sql.gz you do NOT need this file: the dump already creates the tables.

CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS threat_patterns (
    id          SERIAL PRIMARY KEY,
    source      TEXT NOT NULL,          -- 'CAPEC' | 'ATT&CK' | 'CWE' | 'STRIDE'
    pattern_id  TEXT NOT NULL,          -- e.g. 'CAPEC-94', 'ATT&CK-T1078', 'CWE-306', 'STRIDE-S-001'
    title       TEXT NOT NULL,
    description TEXT NOT NULL,
    embedding   vector(384) NOT NULL,   -- all-MiniLM-L6-v2, unit length
    metadata    JSONB DEFAULT '{}',     -- stride_hint, mitre_tactics, domain_tags, ...
    created_at  TIMESTAMPTZ DEFAULT now(),
    UNIQUE (source, pattern_id)
);
CREATE INDEX IF NOT EXISTS idx_threat_patterns_source ON threat_patterns (source);

CREATE TABLE IF NOT EXISTS standards_chunks (
    id         SERIAL PRIMARY KEY,
    standard   TEXT NOT NULL,           -- 'Common Criteria' | 'JIL' | 'EU CRA'
    doc        TEXT NOT NULL,           -- e.g. 'CC:2022 R1 Part 2'
    locator    TEXT NOT NULL,           -- page index or article/annex/recital
    title      TEXT NOT NULL DEFAULT '',
    text       TEXT NOT NULL,
    embedding  vector(384) NOT NULL,
    metadata   JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE (doc, locator)
);
