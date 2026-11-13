-- raw_fallback_v2.event_ts: one normalised timestamp per row, derived from the family's payload key
-- (keys drift between ingest versions: visited_at | last_visit_time, started_at | start_time …).
-- Filled by a BEFORE INSERT trigger (version-proof, no parser edits) and backfilled once here.
ALTER TABLE raw_fallback_v2 ADD COLUMN IF NOT EXISTS event_ts timestamptz;

CREATE OR REPLACE FUNCTION raw_fallback_event_ts(p jsonb) RETURNS timestamptz LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
  k text; v text;
BEGIN
  IF p IS NULL THEN RETURN NULL; END IF;
  FOREACH k IN ARRAY ARRAY['visited_at','last_visit_time','visit_time','started_at','start_time','finished_at','end_time',
                           'date','searched_at','last_used','first_used','DeletedOn','RunTime','LastRun','TargetCreated',
                           'SourceCreated','LastWriteTime','LastWriteTimestamp','FirstInteracted','StartTime','Timestamp',
                           'timestamp','EndTime','DateTime','when','ts','time','event_ts','CreationTime','LastModified',
                           'DriverLastWriteTime','KeyLastWriteTimestamp','Modified','LastModifiedTime'] LOOP
    v := p ->> k;
    IF v IS NOT NULL AND v ~ '^20[0-9]{2}-[01][0-9]-[0-3][0-9]([ T][0-2][0-9]:[0-5][0-9](:[0-5][0-9](\.[0-9]+)?)?)?' THEN
      BEGIN
        RETURN substring(v from '(^20[0-9]{2}-[01][0-9]-[0-3][0-9]([ T][0-2][0-9]:[0-5][0-9](:[0-5][0-9](\.[0-9]{1,6})?)?)?(Z|[+-][0-9]{2}:?[0-9]{2})?)')::timestamptz;
      EXCEPTION WHEN others THEN
        NULL;
      END;
    END IF;
  END LOOP;
  RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION raw_fallback_set_event_ts() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.event_ts IS NULL THEN
    NEW.event_ts := raw_fallback_event_ts(NEW.payload::jsonb);
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_raw_fallback_event_ts ON raw_fallback_v2;
CREATE TRIGGER trg_raw_fallback_event_ts BEFORE INSERT ON raw_fallback_v2
  FOR EACH ROW EXECUTE FUNCTION raw_fallback_set_event_ts();

-- backfill (idempotent)
UPDATE raw_fallback_v2 SET event_ts = raw_fallback_event_ts(payload::jsonb) WHERE event_ts IS NULL;

CREATE INDEX IF NOT EXISTS ix_rf2_ck_fam_ts ON raw_fallback_v2 (case_key, parser_family, event_ts);
ANALYZE raw_fallback_v2;

SELECT parser_family, count(*) AS rows, count(event_ts) AS with_ts
FROM raw_fallback_v2 GROUP BY 1 ORDER BY 2 DESC LIMIT 25;
