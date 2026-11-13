-- S1: DFIR feedback loop — verified case knowledge. Idempotent.
-- All per-finding verdicts + confirmed facts. Keyed by case_key (logical per-case).

CREATE TABLE IF NOT EXISTS case_feedback (
    id          BIGSERIAL PRIMARY KEY,
    case_key    TEXT        NOT NULL,
    job_id      TEXT,
    claim_id    TEXT        NOT NULL,               -- stable hash of claim text
    claim_type  TEXT,                               -- signature|timeline|ioc|mitre|verdict|qa
    claim_text  TEXT        NOT NULL,
    verdict     TEXT        NOT NULL CHECK (verdict IN ('correct','incorrect','unknown')),
    source      TEXT        NOT NULL DEFAULT 'report',  -- report|qa
    question    TEXT,                               -- for source=qa: the user's question
    user_id     BIGINT,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_key, claim_id, user_id)            -- one verdict per claim per user (upsert)
);
CREATE INDEX IF NOT EXISTS idx_case_feedback_case    ON case_feedback (case_key);
CREATE INDEX IF NOT EXISTS idx_case_feedback_verdict ON case_feedback (verdict);

CREATE TABLE IF NOT EXISTS case_verified_facts (
    id           BIGSERIAL PRIMARY KEY,
    case_key     TEXT        NOT NULL,
    claim_id     TEXT,
    claim_type   TEXT,
    claim_text   TEXT        NOT NULL,
    question     TEXT,                              -- the "trigger": what to reuse this on
    embed_id     TEXT,                              -- Qdrant point id (verified=true)
    confirmed_by BIGINT,
    ts           TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (case_key, claim_id)
);
CREATE INDEX IF NOT EXISTS idx_verified_case ON case_verified_facts (case_key);
