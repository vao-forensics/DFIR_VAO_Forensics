-- Database schema for a NEW install (structure only, no data): generated with pg_dump --schema-only
-- from a working DFIR_VAO_Forensics database. Runs once, when PostgreSQL starts on an empty data folder.
--
-- PostgreSQL database dump
--

\restrict IJwPaWyQOq6y7Vn2VLSTaZ4jAhWj4SyQeMSHIgj9TdKdU67hxpFSgsUEEZDuOIP

-- Dumped from database version 16.13
-- Dumped by pg_dump version 16.13

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: amcheck; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS amcheck WITH SCHEMA public;


--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: raw_fallback_event_ts(jsonb); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.raw_fallback_event_ts(p jsonb) RETURNS timestamp with time zone
    LANGUAGE plpgsql IMMUTABLE
    AS $$
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


--
-- Name: raw_fallback_set_event_ts(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.raw_fallback_set_event_ts() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
  IF NEW.event_ts IS NULL THEN
    NEW.event_ts := raw_fallback_event_ts(NEW.payload::jsonb);
  END IF;
  RETURN NEW;
END $$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: access_audit_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.access_audit_v1 (
    id bigint NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    actor text,
    action text NOT NULL,
    user_id text,
    detail text
);


--
-- Name: access_audit_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.access_audit_v1_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: access_audit_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.access_audit_v1_id_seq OWNED BY public.access_audit_v1.id;


--
-- Name: access_requests_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.access_requests_v1 (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    action text NOT NULL,
    user_id text NOT NULL,
    label text,
    requested_by text,
    status text DEFAULT 'pending'::text NOT NULL,
    result text,
    handled_at timestamp with time zone
);


--
-- Name: access_requests_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.access_requests_v1_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: access_requests_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.access_requests_v1_id_seq OWNED BY public.access_requests_v1.id;


--
-- Name: agent_case_notes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_case_notes (
    note_id bigint NOT NULL,
    case_key text NOT NULL,
    note_type text,
    confidence text,
    summary text NOT NULL,
    sources text[],
    detail jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: agent_case_notes_note_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agent_case_notes_note_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_case_notes_note_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agent_case_notes_note_id_seq OWNED BY public.agent_case_notes.note_id;


--
-- Name: agent_kb; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_kb (
    kb_id bigint NOT NULL,
    attack_family text,
    technique text,
    lesson text NOT NULL,
    example_case text,
    keywords text[],
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: agent_kb_kb_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agent_kb_kb_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_kb_kb_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agent_kb_kb_id_seq OWNED BY public.agent_kb.kb_id;


--
-- Name: assistant_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.assistant_log (
    id bigint NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    session text,
    action text NOT NULL,
    details text,
    status text DEFAULT 'ok'::text
);


--
-- Name: assistant_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.assistant_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: assistant_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.assistant_log_id_seq OWNED BY public.assistant_log.id;


--
-- Name: autonomous_dfir_batches_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.autonomous_dfir_batches_v1 (
    batch_id text NOT NULL,
    case_key text NOT NULL,
    goal_text text,
    status text DEFAULT 'queued'::text NOT NULL,
    max_iterations integer DEFAULT 2 NOT NULL,
    time_budget_sec integer DEFAULT 7200 NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    last_error text,
    current_step_idx integer DEFAULT 0 NOT NULL,
    state_json jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_by_user_id text,
    created_by_chat_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    failure_stage text,
    stop_reason text,
    resume_count integer DEFAULT 0 NOT NULL,
    last_resume_at timestamp with time zone,
    heartbeat_at timestamp with time zone,
    last_verified_job_status jsonb
);


--
-- Name: benign_allowlist_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.benign_allowlist_v1 (
    id integer NOT NULL,
    pattern text NOT NULL,
    is_regex boolean DEFAULT false,
    note text,
    added_by text,
    approved boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: benign_allowlist_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.benign_allowlist_v1_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: benign_allowlist_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.benign_allowlist_v1_id_seq OWNED BY public.benign_allowlist_v1.id;


--
-- Name: bot_audit_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bot_audit_events (
    id bigint NOT NULL,
    event_type text NOT NULL,
    user_id bigint,
    chat_id bigint,
    username text,
    first_name text,
    last_name text,
    lang text,
    query_short text,
    status text,
    ts timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: bot_audit_events_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.bot_audit_events_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: bot_audit_events_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.bot_audit_events_id_seq OWNED BY public.bot_audit_events.id;


--
-- Name: bot_free_chat_acl; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bot_free_chat_acl (
    tg_id bigint NOT NULL,
    display_name text,
    webui_user_id text,
    active boolean DEFAULT true,
    granted_by bigint,
    granted_at timestamp with time zone DEFAULT now()
);


--
-- Name: bot_free_chat_log; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bot_free_chat_log (
    id bigint NOT NULL,
    tg_id bigint,
    display_name text,
    question text,
    answer text,
    ts timestamp with time zone DEFAULT now()
);


--
-- Name: bot_free_chat_log_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.bot_free_chat_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: bot_free_chat_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.bot_free_chat_log_id_seq OWNED BY public.bot_free_chat_log.id;


--
-- Name: bot_free_chat_mirror; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bot_free_chat_mirror (
    chat_id text NOT NULL,
    tg_id bigint NOT NULL,
    mirrored_at timestamp with time zone DEFAULT now()
);


--
-- Name: bot_free_chat_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bot_free_chat_sessions (
    tg_id bigint NOT NULL,
    history jsonb DEFAULT '[]'::jsonb,
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: bot_users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bot_users (
    user_id bigint NOT NULL,
    username text,
    first_name text,
    last_name text,
    lang text,
    role text DEFAULT 'blocked'::text NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone,
    notes text
);


--
-- Name: event_logs_v2; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.event_logs_v2 (
    row_id bigint NOT NULL,
    case_key text NOT NULL,
    file_id bigint,
    event_id integer,
    event_ts timestamp with time zone,
    channel text,
    provider text,
    computer text,
    remote_host text,
    target_user text,
    logon_type text,
    process_name text,
    command_line text,
    payload jsonb NOT NULL,
    source_file text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: filesystem_v2; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.filesystem_v2 (
    row_id bigint NOT NULL,
    case_key text NOT NULL,
    file_id bigint,
    event_ts timestamp with time zone,
    file_name text,
    extension text,
    parent_path text,
    action text,
    source_file text,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: browser_provenance_v1; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.browser_provenance_v1 AS
 WITH fs AS (
         SELECT f.case_key,
            f.event_ts,
                CASE
                    WHEN (lower(COALESCE(f.parent_path, ''::text)) ~~ '%edge%'::text) THEN 'edge'::text
                    WHEN (lower(COALESCE(f.parent_path, ''::text)) ~~ '%chrome%'::text) THEN 'chrome'::text
                    WHEN (lower(COALESCE(f.parent_path, ''::text)) ~~ '%internet explorer%'::text) THEN 'ie'::text
                    ELSE NULL::text
                END AS browser,
            NULL::text AS profile_name,
            NULL::text AS user_name,
                CASE
                    WHEN (lower(COALESCE(f.parent_path, ''::text)) ~~ 'internet explorer (homepage)/http%'::text) THEN split_part(f.parent_path, 'Internet Explorer (Homepage)/'::text, 2)
                    ELSE NULL::text
                END AS url,
            NULL::text AS domain,
            NULL::text AS remote_ip,
            NULL::text AS referrer_url,
                CASE
                    WHEN (lower(COALESCE(f.parent_path, ''::text)) ~~ '%downloads%'::text) THEN f.parent_path
                    ELSE NULL::text
                END AS download_path,
                CASE
                    WHEN (COALESCE(f.parent_path, ''::text) <> ''::text) THEN ((f.parent_path || '/'::text) || COALESCE(f.file_name, ''::text))
                    ELSE COALESCE(f.file_name, ''::text)
                END AS local_path,
            (regexp_match((f.payload ->> 'zone_id'::text), 'HostUrl=([^
]+)'::text))[1] AS zone_identifier_host_url,
            (regexp_match((f.payload ->> 'zone_id'::text), 'ReferrerUrl=([^
]+)'::text))[1] AS zone_identifier_referrer_url,
            f.source_file,
            'filesystem_lnk_or_path'::text AS source_type,
            'filesystem_v2'::text AS source_table,
            NULL::text AS container_path,
            NULL::text AS archive_origin,
            'native'::text AS evidence_kind
           FROM public.filesystem_v2 f
          WHERE ((f.parent_path ~~* '%downloads%'::text) OR (f.parent_path ~~* 'internet explorer (homepage)/%'::text) OR (f.parent_path ~~* '%edge%'::text) OR (f.parent_path ~~* '%chrome%'::text) OR (((f.payload)::text ~~* '%HostUrl%'::text) AND ((f.payload ->> 'zone_id'::text) ~~* '%HostUrl%'::text)))
        ), ev AS (
         SELECT e.case_key,
            e.event_ts,
                CASE
                    WHEN (lower(COALESCE((e.payload)::text, ''::text)) ~~ '%edge%'::text) THEN 'edge'::text
                    WHEN (lower(COALESCE((e.payload)::text, ''::text)) ~~ '%chrome%'::text) THEN 'chrome'::text
                    ELSE NULL::text
                END AS browser,
            NULL::text AS profile_name,
            NULL::text AS user_name,
            (regexp_match(COALESCE((e.payload)::text, ''::text), '(https?://[^"\\s]+)'::text))[1] AS url,
            NULL::text AS domain,
            (regexp_match(COALESCE((e.payload)::text, ''::text), '((?:\d{1,3}\.){3}\d{1,3})'::text))[1] AS remote_ip,
            NULL::text AS referrer_url,
            NULL::text AS download_path,
            NULL::text AS local_path,
            NULL::text AS zone_identifier_host_url,
            NULL::text AS zone_identifier_referrer_url,
            e.source_file,
            'event_payload_text'::text AS source_type,
            'event_logs_v2'::text AS source_table,
            NULL::text AS container_path,
            NULL::text AS archive_origin,
            'text_fallback'::text AS evidence_kind
           FROM public.event_logs_v2 e
          WHERE (((e.payload)::text ~~* '%http://%'::text) OR ((e.payload)::text ~~* '%https://%'::text) OR ((e.payload)::text ~~* '%download%'::text) OR ((e.payload)::text ~~* '%browser%'::text) OR ((e.payload)::text ~~* '%edge%'::text) OR ((e.payload)::text ~~* '%chrome%'::text))
        )
 SELECT fs.case_key,
    fs.event_ts,
    fs.browser,
    fs.profile_name,
    fs.user_name,
    fs.url,
    fs.domain,
    fs.remote_ip,
    fs.referrer_url,
    fs.download_path,
    fs.local_path,
    fs.zone_identifier_host_url,
    fs.zone_identifier_referrer_url,
    fs.source_file,
    fs.source_type,
    fs.source_table,
    fs.container_path,
    fs.archive_origin,
    fs.evidence_kind
   FROM fs
UNION ALL
 SELECT ev.case_key,
    ev.event_ts,
    ev.browser,
    ev.profile_name,
    ev.user_name,
    ev.url,
    ev.domain,
    ev.remote_ip,
    ev.referrer_url,
    ev.download_path,
    ev.local_path,
    ev.zone_identifier_host_url,
    ev.zone_identifier_referrer_url,
    ev.source_file,
    ev.source_type,
    ev.source_table,
    ev.container_path,
    ev.archive_origin,
    ev.evidence_kind
   FROM ev;


--
-- Name: case_evidence; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_evidence (
    seq bigint NOT NULL,
    case_key text NOT NULL,
    file_name text NOT NULL,
    stored_path text,
    size_bytes bigint DEFAULT 0 NOT NULL,
    md5 text NOT NULL,
    sha1 text NOT NULL,
    sha256 text NOT NULL,
    uploader_chat text,
    source text,
    ingested_at timestamp with time zone DEFAULT now() NOT NULL,
    prev_row_hash text NOT NULL,
    row_hash text NOT NULL
);


--
-- Name: case_evidence_seq_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_evidence_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_evidence_seq_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_evidence_seq_seq OWNED BY public.case_evidence.seq;


--
-- Name: case_feedback; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_feedback (
    id bigint NOT NULL,
    case_key text NOT NULL,
    job_id text,
    claim_id text NOT NULL,
    claim_type text,
    claim_text text NOT NULL,
    verdict text NOT NULL,
    source text DEFAULT 'report'::text NOT NULL,
    question text,
    user_id bigint,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    reflected_at timestamp with time zone,
    CONSTRAINT case_feedback_verdict_check CHECK ((verdict = ANY (ARRAY['correct'::text, 'incorrect'::text, 'unknown'::text])))
);


--
-- Name: case_feedback_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_feedback_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_feedback_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_feedback_id_seq OWNED BY public.case_feedback.id;


--
-- Name: case_iocs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_iocs (
    ioc_id bigint NOT NULL,
    case_key text NOT NULL,
    ioc_type text NOT NULL,
    ioc_value text NOT NULL,
    ioc_norm text NOT NULL,
    source_table text,
    source_ref text,
    event_ts timestamp with time zone,
    confidence numeric,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: case_iocs_ioc_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_iocs_ioc_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_iocs_ioc_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_iocs_ioc_id_seq OWNED BY public.case_iocs.ioc_id;


--
-- Name: case_learnings_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_learnings_v1 (
    id bigint NOT NULL,
    case_key text NOT NULL,
    topic text NOT NULL,
    finding text NOT NULL,
    artifacts text,
    timestamps text,
    confidence text DEFAULT 'medium'::text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: case_learnings_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_learnings_v1_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_learnings_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_learnings_v1_id_seq OWNED BY public.case_learnings_v1.id;


--
-- Name: case_trigger_hits_v2; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_trigger_hits_v2 (
    hit_id bigint NOT NULL,
    run_id text NOT NULL,
    case_key text NOT NULL,
    trigger text NOT NULL,
    source_table text NOT NULL,
    source_ref text,
    event_ts timestamp with time zone,
    artifact_family text,
    snippet text,
    score numeric(8,3) DEFAULT 1.0,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: case_trigger_hits_v2_hit_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_trigger_hits_v2_hit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_trigger_hits_v2_hit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_trigger_hits_v2_hit_id_seq OWNED BY public.case_trigger_hits_v2.hit_id;


--
-- Name: case_verified_facts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.case_verified_facts (
    id bigint NOT NULL,
    case_key text NOT NULL,
    claim_id text,
    claim_type text,
    claim_text text NOT NULL,
    question text,
    embed_id text,
    confirmed_by bigint,
    ts timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: case_verified_facts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.case_verified_facts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: case_verified_facts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.case_verified_facts_id_seq OWNED BY public.case_verified_facts.id;


--
-- Name: cases; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cases (
    case_key text NOT NULL,
    case_name text,
    created_at timestamp with time zone DEFAULT now(),
    owner_id text,
    created_by text,
    status text DEFAULT 'active'::text
);


--
-- Name: communications_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.communications_v1 (
    row_id bigint NOT NULL,
    case_key text NOT NULL,
    platform text,
    source_kind text,
    self_account text,
    contact_id text,
    contact_name text,
    direction text,
    msg_ts timestamp with time zone,
    message_text text,
    thread_id text,
    attachment text,
    source_artifact text,
    confidence text,
    payload jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: communications_v1_row_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.communications_v1_row_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: communications_v1_row_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.communications_v1_row_id_seq OWNED BY public.communications_v1.row_id;


--
-- Name: dfir_actor_profiles_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_actor_profiles_v1 (
    scope_key text NOT NULL,
    facts_hash text,
    n_cases integer,
    portrait_text text,
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_actors_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_actors_v1 (
    actor_uid text NOT NULL,
    label text,
    case_keys text[],
    confidence text,
    weight integer,
    n_cases integer,
    first_seen timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_agent_learnings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_agent_learnings (
    id integer NOT NULL,
    case_key text,
    job_id text,
    attack_family text,
    tool_sequence text[],
    effective_keywords text[],
    report_quality_score double precision DEFAULT 0,
    report_len integer DEFAULT 0,
    summary text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_agent_learnings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_agent_learnings_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_agent_learnings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_agent_learnings_id_seq OWNED BY public.dfir_agent_learnings.id;


--
-- Name: dfir_benchmark_gaps_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_benchmark_gaps_v1 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    run_id uuid NOT NULL,
    case_key text NOT NULL,
    gap_type text,
    expected text,
    bot_found text,
    severity text DEFAULT 'medium'::text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_benchmark_runs_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_benchmark_runs_v1 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_key text NOT NULL,
    status text DEFAULT 'running'::text NOT NULL,
    quality_score integer,
    pass_count integer DEFAULT 0,
    fail_count integer DEFAULT 0,
    notes text,
    started_at timestamp with time zone DEFAULT now(),
    finished_at timestamp with time zone
);


--
-- Name: dfir_case_classification; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_case_classification (
    case_key text NOT NULL,
    attack_types text,
    initial_vector text,
    one_line_verdict text,
    is_phishing boolean,
    confidence text,
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_case_facts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_case_facts (
    id bigint NOT NULL,
    case_key text NOT NULL,
    fact_type text NOT NULL,
    event_ts timestamp with time zone,
    title text NOT NULL,
    description text,
    source_table text,
    source_file text,
    source_ref text,
    event_id integer,
    artifact_type text,
    path text,
    username text,
    src_ip text,
    hash text,
    confidence real DEFAULT 1.0,
    status text DEFAULT 'active'::text NOT NULL,
    validation_status text DEFAULT 'not_checked'::text NOT NULL,
    validation_reason text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: dfir_case_facts_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_case_facts_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_case_facts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_case_facts_id_seq OWNED BY public.dfir_case_facts.id;


--
-- Name: dfir_case_qa_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_case_qa_v1 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_key text NOT NULL,
    intent text,
    question text NOT NULL,
    answer text,
    status text NOT NULL,
    confidence double precision DEFAULT 0,
    reviewed boolean DEFAULT false,
    review_verdict text,
    run_id uuid,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    fastpath_ver text
);


--
-- Name: dfir_case_reports_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_case_reports_v1 (
    case_key text NOT NULL,
    job_id text NOT NULL,
    report_md text,
    kind text DEFAULT 'full_with_qa'::text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_case_timeline_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_case_timeline_cache (
    id bigint NOT NULL,
    case_key text NOT NULL,
    timeline_version integer DEFAULT 1 NOT NULL,
    status text DEFAULT 'building'::text NOT NULL,
    generated_from text DEFAULT 'logs'::text NOT NULL,
    events_json jsonb,
    sources_json jsonb,
    report_validation_json jsonb,
    model_used text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: dfir_case_timeline_cache_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_case_timeline_cache_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_case_timeline_cache_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_case_timeline_cache_id_seq OWNED BY public.dfir_case_timeline_cache.id;


--
-- Name: dfir_case_verified_findings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_case_verified_findings (
    id bigint NOT NULL,
    case_key text NOT NULL,
    finding_key text NOT NULL,
    finding_type text DEFAULT 'fact'::text NOT NULL,
    title text NOT NULL,
    value text,
    event_ts timestamp with time zone,
    evidence_json jsonb,
    source_kind text DEFAULT 'analyst'::text NOT NULL,
    approval_status text DEFAULT 'approved'::text NOT NULL,
    approved_by text,
    approved_at timestamp with time zone,
    rejected_at timestamp with time zone,
    confidence real DEFAULT 1.0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: dfir_case_verified_findings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_case_verified_findings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_case_verified_findings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_case_verified_findings_id_seq OWNED BY public.dfir_case_verified_findings.id;


--
-- Name: dfir_claim_evidence_links_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_claim_evidence_links_v1 (
    link_id text NOT NULL,
    claim_id text NOT NULL,
    job_id text NOT NULL,
    case_key text NOT NULL,
    source_table text,
    source_row_ref text,
    source_file text,
    event_ts timestamp with time zone,
    evidence_role text,
    snippet text,
    weight numeric,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_claims_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_claims_v1 (
    claim_id text NOT NULL,
    job_id text NOT NULL,
    case_key text NOT NULL,
    step_code text,
    claim_type text NOT NULL,
    claim_text text NOT NULL,
    time_bound_start timestamp with time zone,
    time_bound_end timestamp with time zone,
    confidence text,
    status text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_eval_answers_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_eval_answers_v1 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    question_id uuid NOT NULL,
    case_key text NOT NULL,
    bot_answer text,
    tools_used jsonb DEFAULT '[]'::jsonb,
    sql_used jsonb DEFAULT '[]'::jsonb,
    sources_used jsonb DEFAULT '[]'::jsonb,
    logs_first boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_eval_failures_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_eval_failures_v1 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    question_id uuid NOT NULL,
    answer_id uuid,
    case_key text NOT NULL,
    category text,
    failure_type text NOT NULL,
    expected_fact text,
    actual_answer text,
    root_cause text,
    suggested_fix text,
    severity text DEFAULT 'medium'::text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_eval_questions_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_eval_questions_v1 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_key text NOT NULL,
    source_report text,
    question text NOT NULL,
    expected_answer text,
    expected_facts jsonb DEFAULT '[]'::jsonb,
    expected_sources jsonb DEFAULT '[]'::jsonb,
    category text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_finetune_dataset_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_finetune_dataset_v1 (
    id bigint NOT NULL,
    case_key text NOT NULL,
    instruction text NOT NULL,
    input_text text NOT NULL,
    output_text text NOT NULL,
    n_input integer,
    n_output integer,
    source text DEFAULT 'expert_report'::text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_finetune_dataset_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_finetune_dataset_v1_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_finetune_dataset_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_finetune_dataset_v1_id_seq OWNED BY public.dfir_finetune_dataset_v1.id;


--
-- Name: dfir_fix_candidates_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_fix_candidates_v1 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_key text,
    failure_type text,
    fix_area text,
    fix_prompt text,
    affected_questions jsonb DEFAULT '[]'::jsonb,
    priority integer DEFAULT 5,
    status text DEFAULT 'proposed'::text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_global_artifact_playbooks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_global_artifact_playbooks (
    id bigint NOT NULL,
    intent_name text NOT NULL,
    question_examples text[],
    artifact_type text,
    preferred_tables text[],
    preferred_event_ids integer[],
    preferred_registry_paths text[],
    preferred_source_file_patterns text[],
    sql_templates jsonb,
    evidence_requirements jsonb,
    output_template text,
    success_count integer DEFAULT 0 NOT NULL,
    fail_count integer DEFAULT 0 NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: dfir_global_artifact_playbooks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_global_artifact_playbooks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_global_artifact_playbooks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_global_artifact_playbooks_id_seq OWNED BY public.dfir_global_artifact_playbooks.id;


--
-- Name: dfir_golden_facts_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_golden_facts_v1 (
    id integer NOT NULL,
    case_key text NOT NULL,
    category text NOT NULL,
    fact_key text NOT NULL,
    fact_value text NOT NULL,
    severity text DEFAULT 'high'::text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_golden_facts_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_golden_facts_v1_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_golden_facts_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_golden_facts_v1_id_seq OWNED BY public.dfir_golden_facts_v1.id;


--
-- Name: dfir_ingest_coverage_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_ingest_coverage_v1 (
    id bigint NOT NULL,
    case_key text NOT NULL,
    job_id bigint,
    rel_path text NOT NULL,
    family text,
    rows integer,
    status text NOT NULL,
    note text,
    size_bytes bigint,
    ingested_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_ingest_coverage_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_ingest_coverage_v1_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_ingest_coverage_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_ingest_coverage_v1_id_seq OWNED BY public.dfir_ingest_coverage_v1.id;


--
-- Name: dfir_investigation_journal_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_investigation_journal_v1 (
    id bigint NOT NULL,
    case_key text NOT NULL,
    job_id text,
    round_no integer,
    kind text NOT NULL,
    tool text,
    args jsonb,
    reasoning text,
    result_head text,
    result_len integer,
    ok boolean,
    detail text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: dfir_investigation_journal_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_investigation_journal_v1_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_investigation_journal_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_investigation_journal_v1_id_seq OWNED BY public.dfir_investigation_journal_v1.id;


--
-- Name: dfir_investigation_snapshot_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_investigation_snapshot_v1 (
    case_key text NOT NULL,
    job_id text NOT NULL,
    phase text NOT NULL,
    collected jsonb,
    trace text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: dfir_ioc_pending_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_ioc_pending_v1 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    chat_id text,
    case_key text,
    iocs jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_learning_qa_eval; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_learning_qa_eval (
    id integer NOT NULL,
    learning_run_id integer,
    case_key text NOT NULL,
    question text NOT NULL,
    expected_answer text,
    bot_answer text,
    score integer,
    verdict text,
    missing_evidence text[] DEFAULT '{}'::text[],
    wrong_assumption text[] DEFAULT '{}'::text[],
    evidence_tables_checked text[] DEFAULT '{}'::text[],
    evidence_refs text[] DEFAULT '{}'::text[],
    recommended_tables text[] DEFAULT '{}'::text[],
    lesson_learned text,
    suggested_playbook_update text,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT dfir_learning_qa_eval_score_check CHECK (((score >= 1) AND (score <= 5)))
);


--
-- Name: dfir_learning_qa_eval_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_learning_qa_eval_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_learning_qa_eval_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_learning_qa_eval_id_seq OWNED BY public.dfir_learning_qa_eval.id;


--
-- Name: dfir_learning_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_learning_runs (
    id integer NOT NULL,
    run_id uuid DEFAULT gen_random_uuid(),
    case_key text NOT NULL,
    status text DEFAULT 'running'::text NOT NULL,
    started_at timestamp with time zone DEFAULT now(),
    finished_at timestamp with time zone,
    dry_run boolean DEFAULT true,
    model text,
    questions_total integer DEFAULT 0,
    questions_answered integer DEFAULT 0,
    avg_score double precision,
    error text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_learning_runs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_learning_runs_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_learning_runs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_learning_runs_id_seq OWNED BY public.dfir_learning_runs.id;


--
-- Name: dfir_lessons_learned_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_lessons_learned_v1 (
    id integer NOT NULL,
    case_key text,
    intent text,
    lesson_type text,
    lesson_text text,
    source_tables jsonb,
    source_artifacts jsonb,
    reusable_query_hints jsonb,
    approved_by_user boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_lessons_learned_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_lessons_learned_v1_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_lessons_learned_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_lessons_learned_v1_id_seq OWNED BY public.dfir_lessons_learned_v1.id;


--
-- Name: dfir_link_alert_seen_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_link_alert_seen_v1 (
    case_key text NOT NULL,
    sig text,
    alerted_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_model_routing_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_model_routing_audit (
    id bigint NOT NULL,
    task_name text NOT NULL,
    case_key text,
    chat_id text,
    model_used text NOT NULL,
    model_role text DEFAULT 'fast'::text NOT NULL,
    reason text,
    escalated_to_strong boolean DEFAULT false NOT NULL,
    escalation_reason text,
    input_tokens integer,
    output_tokens integer,
    duration_ms integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: dfir_model_routing_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_model_routing_audit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_model_routing_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_model_routing_audit_id_seq OWNED BY public.dfir_model_routing_audit.id;


--
-- Name: dfir_night_deep_done_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_night_deep_done_v1 (
    day date NOT NULL
);


--
-- Name: dfir_night_report_done; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_night_report_done (
    report_case_key text NOT NULL,
    done_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_playbook_learned_sources; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_playbook_learned_sources (
    id bigint NOT NULL,
    intent_name text NOT NULL,
    source_file text NOT NULL,
    hits integer DEFAULT 1,
    last_seen timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_playbook_learned_sources_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_playbook_learned_sources_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_playbook_learned_sources_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_playbook_learned_sources_id_seq OWNED BY public.dfir_playbook_learned_sources.id;


--
-- Name: dfir_playbook_suggestions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_playbook_suggestions (
    id integer NOT NULL,
    case_key text,
    source_learning_run_id integer,
    title text NOT NULL,
    problem text,
    suggested_change text NOT NULL,
    affected_module text,
    status text DEFAULT 'pending'::text,
    created_at timestamp with time zone DEFAULT now(),
    approved_at timestamp with time zone,
    applied_at timestamp with time zone
);


--
-- Name: dfir_playbook_suggestions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_playbook_suggestions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_playbook_suggestions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_playbook_suggestions_id_seq OWNED BY public.dfir_playbook_suggestions.id;


--
-- Name: dfir_playbooks_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_playbooks_v1 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_key text,
    gap_type text,
    title text,
    checklist jsonb DEFAULT '[]'::jsonb,
    sql_patterns jsonb DEFAULT '[]'::jsonb,
    evidence_rules jsonb DEFAULT '[]'::jsonb,
    source_run_id uuid,
    times_applied integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_qa_answers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_qa_answers (
    id bigint NOT NULL,
    answer_id uuid DEFAULT gen_random_uuid() NOT NULL,
    case_key text NOT NULL,
    chat_id text NOT NULL,
    user_id text,
    question text NOT NULL,
    normalized_question text,
    answer_markdown text NOT NULL,
    confidence real DEFAULT 1.0,
    status text DEFAULT 'pending'::text NOT NULL,
    evidence_json jsonb,
    search_trace_json jsonb,
    tools_used text[],
    tables_checked text[],
    source_files text[],
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    approved_at timestamp with time zone,
    rejected_at timestamp with time zone,
    validation_status text DEFAULT 'not_checked'::text NOT NULL,
    validation_reason text,
    not_in_report boolean DEFAULT false NOT NULL,
    conflict_with_report boolean DEFAULT false NOT NULL,
    source_ref text,
    model_used text,
    model_role text
);


--
-- Name: dfir_qa_answers_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_qa_answers_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_qa_answers_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_qa_answers_id_seq OWNED BY public.dfir_qa_answers.id;


--
-- Name: dfir_qa_cache_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_qa_cache_v1 (
    id bigint NOT NULL,
    case_key text NOT NULL,
    question text NOT NULL,
    answer text NOT NULL,
    source text DEFAULT 'user'::text NOT NULL,
    confidence real DEFAULT 1.0 NOT NULL,
    used_count integer DEFAULT 0 NOT NULL,
    analysis_ts timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    provenance jsonb,
    verified boolean DEFAULT false
);


--
-- Name: dfir_qa_cache_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_qa_cache_v1_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_qa_cache_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_qa_cache_v1_id_seq OWNED BY public.dfir_qa_cache_v1.id;


--
-- Name: dfir_qa_corrections_pending; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_qa_corrections_pending (
    id bigint NOT NULL,
    answer_id uuid NOT NULL,
    chat_id text NOT NULL,
    case_key text,
    waiting_for_correction boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '01:00:00'::interval) NOT NULL
);


--
-- Name: dfir_qa_corrections_pending_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_qa_corrections_pending_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_qa_corrections_pending_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_qa_corrections_pending_id_seq OWNED BY public.dfir_qa_corrections_pending.id;


--
-- Name: dfir_qa_feedback; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_qa_feedback (
    id bigint NOT NULL,
    answer_id uuid NOT NULL,
    case_key text,
    chat_id text,
    user_id text,
    feedback text NOT NULL,
    comment text,
    corrected_answer text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: dfir_qa_feedback_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_qa_feedback_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_qa_feedback_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_qa_feedback_id_seq OWNED BY public.dfir_qa_feedback.id;


--
-- Name: dfir_reusable_playbooks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_reusable_playbooks (
    id bigint NOT NULL,
    playbook_id uuid DEFAULT gen_random_uuid() NOT NULL,
    intent_name text NOT NULL,
    trigger_examples text[],
    question_pattern text,
    artifact_types text[],
    preferred_tables text[],
    preferred_event_ids text[],
    preferred_registry_paths text[],
    preferred_tools text[],
    sql_templates jsonb,
    evidence_requirements jsonb,
    output_template text,
    example_case_key text,
    example_question text,
    example_answer_summary text,
    example_evidence_json jsonb,
    success_count integer DEFAULT 1 NOT NULL,
    fail_count integer DEFAULT 0 NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: dfir_reusable_playbooks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_reusable_playbooks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_reusable_playbooks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_reusable_playbooks_id_seq OWNED BY public.dfir_reusable_playbooks.id;


--
-- Name: dfir_run_jobs_v2; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_run_jobs_v2 (
    job_id uuid NOT NULL,
    case_key text NOT NULL,
    status text NOT NULL,
    run_mode text DEFAULT 'full'::text NOT NULL,
    current_step integer DEFAULT 0 NOT NULL,
    total_steps integer DEFAULT 8 NOT NULL,
    progress_pct numeric(5,2) DEFAULT 0.00 NOT NULL,
    latest_step_code text,
    last_heartbeat_at timestamp with time zone,
    last_successful_step integer DEFAULT 0 NOT NULL,
    error_code text,
    error_short text,
    error_detail_ref text,
    status_chat_id text,
    status_message_id text,
    retry_of_job_id uuid,
    result_ref text,
    result_kind text,
    result_generated_at timestamp with time zone,
    txt_report_path text,
    txt_report_ready boolean DEFAULT false NOT NULL,
    triggered_by_user_id text,
    triggered_by_chat_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    delivered_at timestamp with time zone,
    CONSTRAINT dfir_run_jobs_v2_progress_pct_check CHECK (((progress_pct >= (0)::numeric) AND (progress_pct <= (100)::numeric))),
    CONSTRAINT dfir_run_jobs_v2_result_kind_check CHECK ((result_kind = ANY (ARRAY['completed'::text, 'partial'::text]))),
    CONSTRAINT dfir_run_jobs_v2_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'running'::text, 'completed'::text, 'failed'::text, 'partial'::text, 'cancelled'::text])))
);


--
-- Name: dfir_run_steps_v2; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_run_steps_v2 (
    step_id bigint NOT NULL,
    job_id uuid NOT NULL,
    step_no integer NOT NULL,
    step_code text NOT NULL,
    step_status text NOT NULL,
    progress_pct numeric(5,2),
    heartbeat_at timestamp with time zone,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    message text,
    error_code text,
    error_short text,
    meta_json jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT dfir_run_steps_v2_progress_pct_check CHECK (((progress_pct >= (0)::numeric) AND (progress_pct <= (100)::numeric))),
    CONSTRAINT dfir_run_steps_v2_step_status_check CHECK ((step_status = ANY (ARRAY['pending'::text, 'running'::text, 'success'::text, 'failed'::text, 'skipped'::text])))
);


--
-- Name: dfir_run_steps_v2_step_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_run_steps_v2_step_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_run_steps_v2_step_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_run_steps_v2_step_id_seq OWNED BY public.dfir_run_steps_v2.step_id;


--
-- Name: dfir_self_eval_gaps_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_self_eval_gaps_v1 (
    id integer NOT NULL,
    self_eval_run_id integer,
    case_key text,
    gap_type text,
    expected_fact text,
    bot_found boolean DEFAULT false,
    suggested_probe text,
    severity text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_self_eval_gaps_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_self_eval_gaps_v1_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_self_eval_gaps_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_self_eval_gaps_v1_id_seq OWNED BY public.dfir_self_eval_gaps_v1.id;


--
-- Name: dfir_self_eval_runs_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_self_eval_runs_v1 (
    id integer NOT NULL,
    case_key text,
    status text,
    started_at timestamp with time zone DEFAULT now(),
    finished_at timestamp with time zone,
    coverage_score double precision,
    notes text
);


--
-- Name: dfir_self_eval_runs_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_self_eval_runs_v1_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_self_eval_runs_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_self_eval_runs_v1_id_seq OWNED BY public.dfir_self_eval_runs_v1.id;


--
-- Name: dfir_skills_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_skills_v1 (
    id bigint NOT NULL,
    skill_id uuid DEFAULT gen_random_uuid() NOT NULL,
    intent text,
    title text,
    methodology text,
    artifact_hints jsonb,
    source_books text[],
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: dfir_skills_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_skills_v1_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_skills_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_skills_v1_id_seq OWNED BY public.dfir_skills_v1.id;


--
-- Name: dfir_user_feedback_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dfir_user_feedback_v1 (
    id integer NOT NULL,
    case_key text,
    question text,
    answer text,
    intent text,
    rating integer,
    feedback_text text,
    sources_used jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: dfir_user_feedback_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.dfir_user_feedback_v1_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: dfir_user_feedback_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.dfir_user_feedback_v1_id_seq OWNED BY public.dfir_user_feedback_v1.id;


--
-- Name: event_identity_v1; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.event_identity_v1 AS
 SELECT row_id,
    case_key,
    event_id,
    event_ts,
    COALESCE(event_ts, (NULLIF((regexp_match((payload)::text, '(?i)"timestamp"\s*:\s*"([0-9T:\.-]+(?:Z|[+\-][0-9:]+))"'::text))[1], ''::text))::timestamp with time zone) AS event_ts_norm,
    channel,
    provider,
    computer,
    source_file,
    remote_host,
    target_user,
    logon_type,
    process_name,
    command_line,
    payload,
    COALESCE(NULLIF((regexp_match((payload)::text, '(?i)"@Name":"TargetUserName"[^#]{0,80}"#text":"([^"]+)"'::text))[1], ''::text), NULLIF((regexp_match((payload)::text, '(?i)TargetUserName[^A-Za-z0-9]{0,40}([A-Za-z0-9_\.-]+)'::text))[1], ''::text), NULLIF((regexp_match((payload)::text, '(?i)"User"\s*:\s*"([^"]+)"'::text))[1], ''::text), NULLIF(target_user, ''::text)) AS target_user_name,
    COALESCE(NULLIF((regexp_match((payload)::text, '(?i)"@Name":"SubjectUserName"[^#]{0,80}"#text":"([^"]+)"'::text))[1], ''::text), NULLIF((regexp_match((payload)::text, '(?i)SubjectUserName[^A-Za-z0-9]{0,40}([A-Za-z0-9_\.-]+)'::text))[1], ''::text)) AS subject_user_name,
    COALESCE(NULLIF((regexp_match((payload)::text, '(?i)"@Name":"MemberName"[^#]{0,80}"#text":"([^"]+)"'::text))[1], ''::text), NULLIF((regexp_match((payload)::text, '(?i)MemberName[^A-Za-z0-9]{0,40}([A-Za-z0-9_\.-]+)'::text))[1], ''::text)) AS member_name,
    COALESCE(NULLIF((regexp_match((payload)::text, '(?i)"@Name":"TargetUserName"[^#]{0,80}"#text":"([^"]+)"'::text))[1], ''::text), NULLIF((regexp_match((payload)::text, '(?i)"User"\s*:\s*"([^"]+)"'::text))[1], ''::text), NULLIF(remote_host, ''::text)) AS group_name,
    COALESCE(NULLIF((regexp_match((payload)::text, '((?:\d{1,3}\.){3}\d{1,3})'::text))[1], ''::text), NULLIF((regexp_match(remote_host, '((?:\d{1,3}\.){3}\d{1,3})'::text))[1], ''::text)) AS ip_address,
    COALESCE(NULLIF((regexp_match((payload)::text, '(?i)"@Name":"WorkstationName"[^#]{0,80}"#text":"([^"]+)"'::text))[1], ''::text), NULLIF((regexp_match((payload)::text, '(?i)WorkstationName[^A-Za-z0-9]{0,40}([A-Za-z0-9_\.-]+)'::text))[1], ''::text)) AS workstation_name,
    COALESCE(NULLIF((regexp_match((payload)::text, '(?i)SessionGuid[^A-Za-z0-9]{0,20}([A-Za-z0-9\{}-]+)'::text))[1], ''::text), NULLIF((regexp_match((payload)::text, '(?i)LogonGuid[^A-Za-z0-9]{0,20}([A-Za-z0-9\{}-]+)'::text))[1], ''::text)) AS session_hint,
    COALESCE(NULLIF((regexp_match((payload)::text, '(?i)"@Name":"TargetSid"[^#]{0,80}"#text":"(S-[0-9-]+)"'::text))[1], ''::text), NULLIF((regexp_match((payload)::text, '(?i)"User SID"\s*:\s*"(S-[0-9-]+)"'::text))[1], ''::text), NULLIF((regexp_match(target_user, '(S-[0-9-]+)'::text))[1], ''::text)) AS target_sid,
    COALESCE(NULLIF((regexp_match((payload)::text, '(?i)"@Name":"MemberSid"[^#]{0,80}"#text":"(S-[0-9-]+)"'::text))[1], ''::text), NULLIF((regexp_match((payload)::text, '(?i)"Member SID"\s*:\s*"(S-[0-9-]+)"'::text))[1], ''::text)) AS member_sid,
    COALESCE(NULLIF((regexp_match((payload)::text, '(?i)"@Name":"SubjectUserSid"[^#]{0,80}"#text":"(S-[0-9-]+)"'::text))[1], ''::text), NULLIF((regexp_match((payload)::text, '(?i)SubjectUserSid[^A-Za-z0-9]{0,40}(S-[0-9-]+)'::text))[1], ''::text)) AS subject_sid
   FROM public.event_logs_v2 e;


--
-- Name: event_logs_v2_row_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.event_logs_v2_row_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: event_logs_v2_row_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.event_logs_v2_row_id_seq OWNED BY public.event_logs_v2.row_id;


--
-- Name: filesystem_v2_row_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.filesystem_v2_row_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: filesystem_v2_row_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.filesystem_v2_row_id_seq OWNED BY public.filesystem_v2.row_id;


--
-- Name: ingest_files; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ingest_files (
    file_id bigint NOT NULL,
    job_id bigint NOT NULL,
    case_key text NOT NULL,
    relative_path text NOT NULL,
    parser_family text,
    rows_count integer DEFAULT 0,
    ingested_at timestamp with time zone DEFAULT now()
);


--
-- Name: ingest_files_file_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ingest_files_file_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ingest_files_file_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ingest_files_file_id_seq OWNED BY public.ingest_files.file_id;


--
-- Name: ingest_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ingest_jobs (
    job_id bigint NOT NULL,
    case_key text NOT NULL,
    source_zip_path text,
    status text DEFAULT 'queued'::text NOT NULL,
    total_files integer DEFAULT 0,
    parsed_files integer DEFAULT 0,
    started_at timestamp with time zone DEFAULT now(),
    finished_at timestamp with time zone,
    errors_json jsonb DEFAULT '[]'::jsonb,
    coverage_json jsonb
);


--
-- Name: ingest_jobs_job_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ingest_jobs_job_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ingest_jobs_job_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ingest_jobs_job_id_seq OWNED BY public.ingest_jobs.job_id;


--
-- Name: ioc_enrichment; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_enrichment (
    ioc_norm text NOT NULL,
    ioc_type text,
    vt_malicious integer,
    vt_total integer,
    vt_names text,
    abuse_score integer,
    country text,
    last_checked timestamp with time zone DEFAULT now(),
    raw_vt jsonb,
    raw_abuse jsonb
);


--
-- Name: ioc_overlap; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ioc_overlap (
    overlap_id bigint NOT NULL,
    case_a text NOT NULL,
    case_b text NOT NULL,
    ioc_type text NOT NULL,
    ioc_norm text NOT NULL,
    first_seen timestamp with time zone,
    last_seen timestamp with time zone,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: ioc_overlap_overlap_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ioc_overlap_overlap_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ioc_overlap_overlap_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ioc_overlap_overlap_id_seq OWNED BY public.ioc_overlap.overlap_id;


--
-- Name: llm_self_improvement_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.llm_self_improvement_v1 (
    id bigint NOT NULL,
    case_key text NOT NULL,
    job_id uuid NOT NULL,
    verdict text,
    confidence text,
    initial_access_method text,
    what_worked jsonb,
    what_was_missing jsonb,
    how_gaps_were_filled jsonb,
    key_techniques jsonb,
    llm_reflection text,
    step_contributions jsonb,
    planner_confidence numeric,
    chains_found jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: llm_self_improvement_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.llm_self_improvement_v1_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: llm_self_improvement_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.llm_self_improvement_v1_id_seq OWNED BY public.llm_self_improvement_v1.id;


--
-- Name: local_accounts_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.local_accounts_v1 (
    row_id bigint NOT NULL,
    case_key text NOT NULL,
    username text,
    rid text,
    ntlm text,
    lm text,
    is_empty boolean,
    source text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: local_accounts_v1_row_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.local_accounts_v1_row_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: local_accounts_v1_row_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.local_accounts_v1_row_id_seq OWNED BY public.local_accounts_v1.row_id;


--
-- Name: pg_triggers_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pg_triggers_cache (
    trigger text NOT NULL,
    enabled boolean DEFAULT true,
    synced_at timestamp with time zone DEFAULT now()
);


--
-- Name: program_exec_v2; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.program_exec_v2 (
    row_id bigint NOT NULL,
    case_key text NOT NULL,
    file_id bigint,
    event_ts timestamp with time zone,
    executable_name text,
    full_path text,
    hash_sha1 text,
    source_file text,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: program_exec_v2_row_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.program_exec_v2_row_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: program_exec_v2_row_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.program_exec_v2_row_id_seq OWNED BY public.program_exec_v2.row_id;


--
-- Name: ram_jobs_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ram_jobs_v1 (
    id bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    case_key text NOT NULL,
    chat_id text,
    archive_path text NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    result text,
    rows_found integer,
    handled_at timestamp with time zone,
    kind text DEFAULT 'full'::text NOT NULL
);


--
-- Name: ram_jobs_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.ram_jobs_v1_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ram_jobs_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.ram_jobs_v1_id_seq OWNED BY public.ram_jobs_v1.id;


--
-- Name: raw_fallback_v2; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.raw_fallback_v2 (
    row_id bigint NOT NULL,
    case_key text NOT NULL,
    file_id bigint,
    parser_family text,
    source_file text,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    event_ts timestamp with time zone
);


--
-- Name: raw_fallback_v2_row_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.raw_fallback_v2_row_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: raw_fallback_v2_row_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.raw_fallback_v2_row_id_seq OWNED BY public.raw_fallback_v2.row_id;


--
-- Name: report_chunks_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.report_chunks_v1 (
    case_key text NOT NULL,
    source text NOT NULL,
    chunk_index integer NOT NULL,
    chunk_text text NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: study_courses; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.study_courses (
    id bigint NOT NULL,
    course_key text NOT NULL,
    title text NOT NULL,
    description text,
    created_by bigint,
    is_active boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: study_courses_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.study_courses_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: study_courses_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.study_courses_id_seq OWNED BY public.study_courses.id;


--
-- Name: study_import_jobs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.study_import_jobs (
    id bigint NOT NULL,
    chat_id bigint NOT NULL,
    user_id bigint NOT NULL,
    course_id bigint,
    file_name text,
    total_questions integer,
    added_questions integer,
    skipped_questions integer,
    error_count integer,
    status text DEFAULT 'pending'::text NOT NULL,
    summary jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone
);


--
-- Name: study_import_jobs_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.study_import_jobs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: study_import_jobs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.study_import_jobs_id_seq OWNED BY public.study_import_jobs.id;


--
-- Name: study_questions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.study_questions (
    id bigint NOT NULL,
    course_id bigint NOT NULL,
    q_en text NOT NULL,
    q_uk text NOT NULL,
    options jsonb NOT NULL,
    correct smallint NOT NULL,
    exp_en text NOT NULL,
    exp_uk text NOT NULL,
    tag text,
    source_hash text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT study_questions_correct_check CHECK (((correct >= 0) AND (correct <= 3)))
);


--
-- Name: study_questions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.study_questions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: study_questions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.study_questions_id_seq OWNED BY public.study_questions.id;


--
-- Name: study_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.study_sessions (
    id bigint NOT NULL,
    chat_id bigint NOT NULL,
    user_id bigint NOT NULL,
    course_id bigint NOT NULL,
    mode text NOT NULL,
    question_count integer NOT NULL,
    question_ids jsonb NOT NULL,
    current_index integer DEFAULT 0 NOT NULL,
    answers jsonb DEFAULT '{}'::jsonb NOT NULL,
    active boolean DEFAULT true NOT NULL,
    completed boolean DEFAULT false NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    CONSTRAINT study_sessions_mode_check CHECK ((mode = ANY (ARRAY['practice'::text, 'exam'::text])))
);


--
-- Name: study_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.study_sessions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: study_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.study_sessions_id_seq OWNED BY public.study_sessions.id;


--
-- Name: security_events_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.security_events_v1 (
    id bigint NOT NULL,
    first_seen timestamp with time zone DEFAULT now() NOT NULL,
    last_seen timestamp with time zone DEFAULT now() NOT NULL,
    src_ip text NOT NULL,
    kind text NOT NULL,
    detail text,
    hits integer DEFAULT 1 NOT NULL,
    alerted boolean DEFAULT false NOT NULL
);


--
-- Name: security_events_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.security_events_v1_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: security_events_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.security_events_v1_id_seq OWNED BY public.security_events_v1.id;


--
-- Name: srum_v2; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.srum_v2 (
    row_id bigint NOT NULL,
    case_key text NOT NULL,
    file_id bigint,
    event_ts timestamp with time zone,
    username text,
    exe_info text,
    source_file text,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: srum_v2_row_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.srum_v2_row_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: srum_v2_row_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.srum_v2_row_id_seq OWNED BY public.srum_v2.row_id;


--
-- Name: system_profile_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_profile_v1 (
    case_key text NOT NULL,
    computer_name text,
    hostname text,
    os_name text,
    build text,
    install_date_utc text,
    timezone text,
    utc_offset text,
    last_shutdown_utc text,
    users_json jsonb,
    source_kind text,
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: tool_alerts_v2; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tool_alerts_v2 (
    row_id bigint NOT NULL,
    case_key text NOT NULL,
    file_id bigint,
    tool text NOT NULL,
    severity text,
    rule text,
    event_ts timestamp with time zone,
    computer text,
    user_name text,
    ioc_value text,
    details text,
    source_file text,
    payload jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: tool_alerts_v2_row_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.tool_alerts_v2_row_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tool_alerts_v2_row_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.tool_alerts_v2_row_id_seq OWNED BY public.tool_alerts_v2.row_id;


--
-- Name: trigger_catalog_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trigger_catalog_v1 (
    trigger_id bigint NOT NULL,
    trigger_text text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    priority integer DEFAULT 100 NOT NULL,
    severity text,
    source text DEFAULT 'manual'::text NOT NULL,
    version integer DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_at timestamp with time zone
);


--
-- Name: trigger_catalog_v1_trigger_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.trigger_catalog_v1_trigger_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: trigger_catalog_v1_trigger_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.trigger_catalog_v1_trigger_id_seq OWNED BY public.trigger_catalog_v1.trigger_id;


--
-- Name: trigger_scan_jobs_v2; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trigger_scan_jobs_v2 (
    job_id text NOT NULL,
    case_key text NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    stage text,
    progress numeric DEFAULT 0 NOT NULL,
    error text,
    run_id text,
    ingest jsonb,
    result jsonb,
    started_at timestamp with time zone,
    finished_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: trigger_time_windows_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.trigger_time_windows_v1 (
    run_id text NOT NULL,
    case_key text NOT NULL,
    anchor_ts timestamp with time zone,
    month_start timestamp with time zone,
    month_end timestamp with time zone,
    window_start timestamp with time zone,
    window_end timestamp with time zone,
    first_relevant_ts timestamp with time zone,
    last_relevant_ts timestamp with time zone,
    hits_total integer DEFAULT 0 NOT NULL,
    hits_with_ts integer DEFAULT 0 NOT NULL,
    cluster_day_count integer DEFAULT 0 NOT NULL,
    rationale text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: upload_audit_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.upload_audit_v1 (
    id bigint NOT NULL,
    ts timestamp with time zone DEFAULT now() NOT NULL,
    verdict text NOT NULL,
    reason_code text,
    reason text,
    case_key text,
    mode text,
    file_name text,
    size_bytes bigint,
    sha256 text,
    vpn_ip text,
    vpn_client text,
    chat_id text,
    stored_path text,
    quarantine_path text
);


--
-- Name: upload_audit_v1_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.upload_audit_v1_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: upload_audit_v1_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.upload_audit_v1_id_seq OWNED BY public.upload_audit_v1.id;


--
-- Name: user_access_v1; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.user_access_v1 (
    user_id text NOT NULL,
    chat_id text,
    label text,
    bot_enabled boolean DEFAULT false NOT NULL,
    vpn_client_id text,
    vpn_ip text,
    vpn_enabled boolean DEFAULT false NOT NULL,
    vpn_created_at timestamp with time zone,
    webui_email text,
    webui_pw_hash text,
    webui_given_at timestamp with time zone,
    granted_by text,
    granted_at timestamp with time zone,
    revoked_at timestamp with time zone,
    notes text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: v_case_case_58_4624; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_case_case_58_4624 AS
 SELECT event_ts,
    remote_host,
    target_user,
    computer,
    source_file,
    payload
   FROM public.event_logs_v2
  WHERE ((case_key = 'case_07'::text) AND (event_id = 4624));


--
-- Name: v_case_case_58_4688; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_case_case_58_4688 AS
 SELECT event_ts,
    process_name,
    command_line,
    target_user,
    computer,
    source_file,
    payload
   FROM public.event_logs_v2
  WHERE ((case_key = 'case_07'::text) AND (event_id = 4688));


--
-- Name: v_case_case_58_core_stage1; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_case_case_58_core_stage1 AS
 SELECT event_ts,
    event_id,
    remote_host,
    target_user,
    computer,
    process_name,
    command_line,
    source_file,
    payload
   FROM public.event_logs_v2
  WHERE ((case_key = 'case_07'::text) AND (event_id = ANY (ARRAY[4624, 4625, 4648, 4672, 1149, 4778, 4779, 4688, 4697, 4698, 7045, 7035, 7036, 106, 4104, 400, 403, 1102, 4719, 5001, 1116, 5140, 5145, 4663])));


--
-- Name: v_case_case_58_ps_4104; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_case_case_58_ps_4104 AS
 SELECT event_ts,
    target_user,
    computer,
    source_file,
    payload
   FROM public.event_logs_v2
  WHERE ((case_key = 'case_07'::text) AND (event_id = 4104));


--
-- Name: v_case_similarity; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_case_similarity AS
 SELECT a.case_key AS case_a,
    b.case_key AS case_b,
    count(*) AS shared_iocs,
    count(*) FILTER (WHERE (a.ioc_type = 'trigger'::text)) AS shared_triggers,
    min(LEAST(a.event_ts, b.event_ts)) AS first_seen,
    max(GREATEST(a.event_ts, b.event_ts)) AS last_seen
   FROM (public.case_iocs a
     JOIN public.case_iocs b ON (((a.ioc_norm = b.ioc_norm) AND (a.ioc_type = b.ioc_type) AND (a.case_key < b.case_key))))
  GROUP BY a.case_key, b.case_key;


--
-- Name: v_case_similarity_trigger_only; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_case_similarity_trigger_only AS
 SELECT a.case_key AS case_a,
    b.case_key AS case_b,
    count(DISTINCT lower(TRIM(BOTH FROM a.trigger))) AS shared_triggers,
    min(LEAST(a.event_ts, b.event_ts)) AS first_seen,
    max(GREATEST(a.event_ts, b.event_ts)) AS last_seen
   FROM (public.case_trigger_hits_v2 a
     JOIN public.case_trigger_hits_v2 b ON (((lower(TRIM(BOTH FROM a.trigger)) = lower(TRIM(BOTH FROM b.trigger))) AND (a.case_key < b.case_key))))
  GROUP BY a.case_key, b.case_key;


--
-- Name: v_case_triage_first; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_case_triage_first AS
 SELECT tool_alerts_v2.case_key,
    'tool_alert'::text AS source_type,
    tool_alerts_v2.event_ts,
    tool_alerts_v2.tool AS source,
    tool_alerts_v2.severity,
    tool_alerts_v2.rule AS title,
    tool_alerts_v2.computer,
    tool_alerts_v2.user_name AS user_actor,
    tool_alerts_v2.ioc_value AS indicator,
    tool_alerts_v2.source_file,
    tool_alerts_v2.details
   FROM public.tool_alerts_v2
UNION ALL
 SELECT event_logs_v2.case_key,
    'event_log'::text AS source_type,
    event_logs_v2.event_ts,
    COALESCE(event_logs_v2.channel, 'eventlog'::text) AS source,
    NULL::text AS severity,
    ('EventID '::text || COALESCE((event_logs_v2.event_id)::text, 'null'::text)) AS title,
    event_logs_v2.computer,
    event_logs_v2.target_user AS user_actor,
        CASE
            WHEN (event_logs_v2.remote_host ~ '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'::text) THEN event_logs_v2.remote_host
            ELSE NULL::text
        END AS indicator,
    event_logs_v2.source_file,
    "left"(COALESCE(event_logs_v2.command_line, ''::text), 500) AS details
   FROM public.event_logs_v2
  WHERE (event_logs_v2.event_id = ANY (ARRAY[4624, 4625, 4688, 4104, 4697, 7045, 4720, 4732, 4672]));


--
-- Name: v_case_trigger_top_overlap; Type: VIEW; Schema: public; Owner: -
--

CREATE VIEW public.v_case_trigger_top_overlap AS
 SELECT case_a,
    case_b,
    shared_triggers,
    first_seen,
    last_seen,
    dense_rank() OVER (PARTITION BY case_a ORDER BY shared_triggers DESC) AS rank_in_case
   FROM public.v_case_similarity_trigger_only;


--
-- Name: access_audit_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_audit_v1 ALTER COLUMN id SET DEFAULT nextval('public.access_audit_v1_id_seq'::regclass);


--
-- Name: access_requests_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_requests_v1 ALTER COLUMN id SET DEFAULT nextval('public.access_requests_v1_id_seq'::regclass);


--
-- Name: agent_case_notes note_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_case_notes ALTER COLUMN note_id SET DEFAULT nextval('public.agent_case_notes_note_id_seq'::regclass);


--
-- Name: agent_kb kb_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_kb ALTER COLUMN kb_id SET DEFAULT nextval('public.agent_kb_kb_id_seq'::regclass);


--
-- Name: assistant_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assistant_log ALTER COLUMN id SET DEFAULT nextval('public.assistant_log_id_seq'::regclass);


--
-- Name: benign_allowlist_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.benign_allowlist_v1 ALTER COLUMN id SET DEFAULT nextval('public.benign_allowlist_v1_id_seq'::regclass);


--
-- Name: bot_audit_events id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_audit_events ALTER COLUMN id SET DEFAULT nextval('public.bot_audit_events_id_seq'::regclass);


--
-- Name: bot_free_chat_log id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_free_chat_log ALTER COLUMN id SET DEFAULT nextval('public.bot_free_chat_log_id_seq'::regclass);


--
-- Name: case_evidence seq; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_evidence ALTER COLUMN seq SET DEFAULT nextval('public.case_evidence_seq_seq'::regclass);


--
-- Name: case_feedback id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_feedback ALTER COLUMN id SET DEFAULT nextval('public.case_feedback_id_seq'::regclass);


--
-- Name: case_iocs ioc_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_iocs ALTER COLUMN ioc_id SET DEFAULT nextval('public.case_iocs_ioc_id_seq'::regclass);


--
-- Name: case_learnings_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_learnings_v1 ALTER COLUMN id SET DEFAULT nextval('public.case_learnings_v1_id_seq'::regclass);


--
-- Name: case_trigger_hits_v2 hit_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_trigger_hits_v2 ALTER COLUMN hit_id SET DEFAULT nextval('public.case_trigger_hits_v2_hit_id_seq'::regclass);


--
-- Name: case_verified_facts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_verified_facts ALTER COLUMN id SET DEFAULT nextval('public.case_verified_facts_id_seq'::regclass);


--
-- Name: communications_v1 row_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.communications_v1 ALTER COLUMN row_id SET DEFAULT nextval('public.communications_v1_row_id_seq'::regclass);


--
-- Name: dfir_agent_learnings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_agent_learnings ALTER COLUMN id SET DEFAULT nextval('public.dfir_agent_learnings_id_seq'::regclass);


--
-- Name: dfir_case_facts id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_case_facts ALTER COLUMN id SET DEFAULT nextval('public.dfir_case_facts_id_seq'::regclass);


--
-- Name: dfir_case_timeline_cache id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_case_timeline_cache ALTER COLUMN id SET DEFAULT nextval('public.dfir_case_timeline_cache_id_seq'::regclass);


--
-- Name: dfir_case_verified_findings id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_case_verified_findings ALTER COLUMN id SET DEFAULT nextval('public.dfir_case_verified_findings_id_seq'::regclass);


--
-- Name: dfir_finetune_dataset_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_finetune_dataset_v1 ALTER COLUMN id SET DEFAULT nextval('public.dfir_finetune_dataset_v1_id_seq'::regclass);


--
-- Name: dfir_global_artifact_playbooks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_global_artifact_playbooks ALTER COLUMN id SET DEFAULT nextval('public.dfir_global_artifact_playbooks_id_seq'::regclass);


--
-- Name: dfir_golden_facts_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_golden_facts_v1 ALTER COLUMN id SET DEFAULT nextval('public.dfir_golden_facts_v1_id_seq'::regclass);


--
-- Name: dfir_ingest_coverage_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_ingest_coverage_v1 ALTER COLUMN id SET DEFAULT nextval('public.dfir_ingest_coverage_v1_id_seq'::regclass);


--
-- Name: dfir_investigation_journal_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_investigation_journal_v1 ALTER COLUMN id SET DEFAULT nextval('public.dfir_investigation_journal_v1_id_seq'::regclass);


--
-- Name: dfir_learning_qa_eval id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_learning_qa_eval ALTER COLUMN id SET DEFAULT nextval('public.dfir_learning_qa_eval_id_seq'::regclass);


--
-- Name: dfir_learning_runs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_learning_runs ALTER COLUMN id SET DEFAULT nextval('public.dfir_learning_runs_id_seq'::regclass);


--
-- Name: dfir_lessons_learned_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_lessons_learned_v1 ALTER COLUMN id SET DEFAULT nextval('public.dfir_lessons_learned_v1_id_seq'::regclass);


--
-- Name: dfir_model_routing_audit id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_model_routing_audit ALTER COLUMN id SET DEFAULT nextval('public.dfir_model_routing_audit_id_seq'::regclass);


--
-- Name: dfir_playbook_learned_sources id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_playbook_learned_sources ALTER COLUMN id SET DEFAULT nextval('public.dfir_playbook_learned_sources_id_seq'::regclass);


--
-- Name: dfir_playbook_suggestions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_playbook_suggestions ALTER COLUMN id SET DEFAULT nextval('public.dfir_playbook_suggestions_id_seq'::regclass);


--
-- Name: dfir_qa_answers id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_qa_answers ALTER COLUMN id SET DEFAULT nextval('public.dfir_qa_answers_id_seq'::regclass);


--
-- Name: dfir_qa_cache_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_qa_cache_v1 ALTER COLUMN id SET DEFAULT nextval('public.dfir_qa_cache_v1_id_seq'::regclass);


--
-- Name: dfir_qa_corrections_pending id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_qa_corrections_pending ALTER COLUMN id SET DEFAULT nextval('public.dfir_qa_corrections_pending_id_seq'::regclass);


--
-- Name: dfir_qa_feedback id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_qa_feedback ALTER COLUMN id SET DEFAULT nextval('public.dfir_qa_feedback_id_seq'::regclass);


--
-- Name: dfir_reusable_playbooks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_reusable_playbooks ALTER COLUMN id SET DEFAULT nextval('public.dfir_reusable_playbooks_id_seq'::regclass);


--
-- Name: dfir_run_steps_v2 step_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_run_steps_v2 ALTER COLUMN step_id SET DEFAULT nextval('public.dfir_run_steps_v2_step_id_seq'::regclass);


--
-- Name: dfir_self_eval_gaps_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_self_eval_gaps_v1 ALTER COLUMN id SET DEFAULT nextval('public.dfir_self_eval_gaps_v1_id_seq'::regclass);


--
-- Name: dfir_self_eval_runs_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_self_eval_runs_v1 ALTER COLUMN id SET DEFAULT nextval('public.dfir_self_eval_runs_v1_id_seq'::regclass);


--
-- Name: dfir_skills_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_skills_v1 ALTER COLUMN id SET DEFAULT nextval('public.dfir_skills_v1_id_seq'::regclass);


--
-- Name: dfir_user_feedback_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_user_feedback_v1 ALTER COLUMN id SET DEFAULT nextval('public.dfir_user_feedback_v1_id_seq'::regclass);


--
-- Name: event_logs_v2 row_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_logs_v2 ALTER COLUMN row_id SET DEFAULT nextval('public.event_logs_v2_row_id_seq'::regclass);


--
-- Name: filesystem_v2 row_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.filesystem_v2 ALTER COLUMN row_id SET DEFAULT nextval('public.filesystem_v2_row_id_seq'::regclass);


--
-- Name: ingest_files file_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingest_files ALTER COLUMN file_id SET DEFAULT nextval('public.ingest_files_file_id_seq'::regclass);


--
-- Name: ingest_jobs job_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingest_jobs ALTER COLUMN job_id SET DEFAULT nextval('public.ingest_jobs_job_id_seq'::regclass);


--
-- Name: ioc_overlap overlap_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_overlap ALTER COLUMN overlap_id SET DEFAULT nextval('public.ioc_overlap_overlap_id_seq'::regclass);


--
-- Name: llm_self_improvement_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_self_improvement_v1 ALTER COLUMN id SET DEFAULT nextval('public.llm_self_improvement_v1_id_seq'::regclass);


--
-- Name: local_accounts_v1 row_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.local_accounts_v1 ALTER COLUMN row_id SET DEFAULT nextval('public.local_accounts_v1_row_id_seq'::regclass);


--
-- Name: program_exec_v2 row_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.program_exec_v2 ALTER COLUMN row_id SET DEFAULT nextval('public.program_exec_v2_row_id_seq'::regclass);


--
-- Name: ram_jobs_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ram_jobs_v1 ALTER COLUMN id SET DEFAULT nextval('public.ram_jobs_v1_id_seq'::regclass);


--
-- Name: raw_fallback_v2 row_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.raw_fallback_v2 ALTER COLUMN row_id SET DEFAULT nextval('public.raw_fallback_v2_row_id_seq'::regclass);


--
-- Name: study_courses id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.study_courses ALTER COLUMN id SET DEFAULT nextval('public.study_courses_id_seq'::regclass);


--
-- Name: study_import_jobs id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.study_import_jobs ALTER COLUMN id SET DEFAULT nextval('public.study_import_jobs_id_seq'::regclass);


--
-- Name: study_questions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.study_questions ALTER COLUMN id SET DEFAULT nextval('public.study_questions_id_seq'::regclass);


--
-- Name: study_sessions id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.study_sessions ALTER COLUMN id SET DEFAULT nextval('public.study_sessions_id_seq'::regclass);


--
-- Name: security_events_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events_v1 ALTER COLUMN id SET DEFAULT nextval('public.security_events_v1_id_seq'::regclass);


--
-- Name: srum_v2 row_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.srum_v2 ALTER COLUMN row_id SET DEFAULT nextval('public.srum_v2_row_id_seq'::regclass);


--
-- Name: tool_alerts_v2 row_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tool_alerts_v2 ALTER COLUMN row_id SET DEFAULT nextval('public.tool_alerts_v2_row_id_seq'::regclass);


--
-- Name: trigger_catalog_v1 trigger_id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trigger_catalog_v1 ALTER COLUMN trigger_id SET DEFAULT nextval('public.trigger_catalog_v1_trigger_id_seq'::regclass);


--
-- Name: upload_audit_v1 id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.upload_audit_v1 ALTER COLUMN id SET DEFAULT nextval('public.upload_audit_v1_id_seq'::regclass);


--
-- Name: access_audit_v1 access_audit_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_audit_v1
    ADD CONSTRAINT access_audit_v1_pkey PRIMARY KEY (id);


--
-- Name: access_requests_v1 access_requests_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.access_requests_v1
    ADD CONSTRAINT access_requests_v1_pkey PRIMARY KEY (id);


--
-- Name: agent_case_notes agent_case_notes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_case_notes
    ADD CONSTRAINT agent_case_notes_pkey PRIMARY KEY (note_id);


--
-- Name: agent_kb agent_kb_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_kb
    ADD CONSTRAINT agent_kb_pkey PRIMARY KEY (kb_id);


--
-- Name: assistant_log assistant_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.assistant_log
    ADD CONSTRAINT assistant_log_pkey PRIMARY KEY (id);


--
-- Name: autonomous_dfir_batches_v1 autonomous_dfir_batches_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.autonomous_dfir_batches_v1
    ADD CONSTRAINT autonomous_dfir_batches_v1_pkey PRIMARY KEY (batch_id);


--
-- Name: benign_allowlist_v1 benign_allowlist_v1_pattern_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.benign_allowlist_v1
    ADD CONSTRAINT benign_allowlist_v1_pattern_key UNIQUE (pattern);


--
-- Name: benign_allowlist_v1 benign_allowlist_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.benign_allowlist_v1
    ADD CONSTRAINT benign_allowlist_v1_pkey PRIMARY KEY (id);


--
-- Name: bot_audit_events bot_audit_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_audit_events
    ADD CONSTRAINT bot_audit_events_pkey PRIMARY KEY (id);


--
-- Name: bot_free_chat_acl bot_free_chat_acl_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_free_chat_acl
    ADD CONSTRAINT bot_free_chat_acl_pkey PRIMARY KEY (tg_id);


--
-- Name: bot_free_chat_log bot_free_chat_log_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_free_chat_log
    ADD CONSTRAINT bot_free_chat_log_pkey PRIMARY KEY (id);


--
-- Name: bot_free_chat_mirror bot_free_chat_mirror_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_free_chat_mirror
    ADD CONSTRAINT bot_free_chat_mirror_pkey PRIMARY KEY (chat_id);


--
-- Name: bot_free_chat_sessions bot_free_chat_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_free_chat_sessions
    ADD CONSTRAINT bot_free_chat_sessions_pkey PRIMARY KEY (tg_id);


--
-- Name: bot_users bot_users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bot_users
    ADD CONSTRAINT bot_users_pkey PRIMARY KEY (user_id);


--
-- Name: case_evidence case_evidence_case_key_row_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_evidence
    ADD CONSTRAINT case_evidence_case_key_row_hash_key UNIQUE (case_key, row_hash);


--
-- Name: case_evidence case_evidence_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_evidence
    ADD CONSTRAINT case_evidence_pkey PRIMARY KEY (seq);


--
-- Name: case_feedback case_feedback_case_key_claim_id_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_feedback
    ADD CONSTRAINT case_feedback_case_key_claim_id_user_id_key UNIQUE (case_key, claim_id, user_id);


--
-- Name: case_feedback case_feedback_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_feedback
    ADD CONSTRAINT case_feedback_pkey PRIMARY KEY (id);


--
-- Name: case_iocs case_iocs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_iocs
    ADD CONSTRAINT case_iocs_pkey PRIMARY KEY (ioc_id);


--
-- Name: case_learnings_v1 case_learnings_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_learnings_v1
    ADD CONSTRAINT case_learnings_v1_pkey PRIMARY KEY (id);


--
-- Name: case_trigger_hits_v2 case_trigger_hits_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_trigger_hits_v2
    ADD CONSTRAINT case_trigger_hits_v2_pkey PRIMARY KEY (hit_id);


--
-- Name: case_verified_facts case_verified_facts_case_key_claim_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_verified_facts
    ADD CONSTRAINT case_verified_facts_case_key_claim_id_key UNIQUE (case_key, claim_id);


--
-- Name: case_verified_facts case_verified_facts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_verified_facts
    ADD CONSTRAINT case_verified_facts_pkey PRIMARY KEY (id);


--
-- Name: cases cases_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cases
    ADD CONSTRAINT cases_pkey PRIMARY KEY (case_key);


--
-- Name: communications_v1 communications_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.communications_v1
    ADD CONSTRAINT communications_v1_pkey PRIMARY KEY (row_id);


--
-- Name: dfir_actor_profiles_v1 dfir_actor_profiles_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_actor_profiles_v1
    ADD CONSTRAINT dfir_actor_profiles_v1_pkey PRIMARY KEY (scope_key);


--
-- Name: dfir_actors_v1 dfir_actors_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_actors_v1
    ADD CONSTRAINT dfir_actors_v1_pkey PRIMARY KEY (actor_uid);


--
-- Name: dfir_agent_learnings dfir_agent_learnings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_agent_learnings
    ADD CONSTRAINT dfir_agent_learnings_pkey PRIMARY KEY (id);


--
-- Name: dfir_benchmark_gaps_v1 dfir_benchmark_gaps_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_benchmark_gaps_v1
    ADD CONSTRAINT dfir_benchmark_gaps_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_benchmark_runs_v1 dfir_benchmark_runs_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_benchmark_runs_v1
    ADD CONSTRAINT dfir_benchmark_runs_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_case_classification dfir_case_classification_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_case_classification
    ADD CONSTRAINT dfir_case_classification_pkey PRIMARY KEY (case_key);


--
-- Name: dfir_case_facts dfir_case_facts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_case_facts
    ADD CONSTRAINT dfir_case_facts_pkey PRIMARY KEY (id);


--
-- Name: dfir_case_qa_v1 dfir_case_qa_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_case_qa_v1
    ADD CONSTRAINT dfir_case_qa_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_case_reports_v1 dfir_case_reports_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_case_reports_v1
    ADD CONSTRAINT dfir_case_reports_v1_pkey PRIMARY KEY (case_key, job_id);


--
-- Name: dfir_case_timeline_cache dfir_case_timeline_cache_case_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_case_timeline_cache
    ADD CONSTRAINT dfir_case_timeline_cache_case_key_key UNIQUE (case_key);


--
-- Name: dfir_case_timeline_cache dfir_case_timeline_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_case_timeline_cache
    ADD CONSTRAINT dfir_case_timeline_cache_pkey PRIMARY KEY (id);


--
-- Name: dfir_case_verified_findings dfir_case_verified_findings_case_key_finding_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_case_verified_findings
    ADD CONSTRAINT dfir_case_verified_findings_case_key_finding_key_key UNIQUE (case_key, finding_key);


--
-- Name: dfir_case_verified_findings dfir_case_verified_findings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_case_verified_findings
    ADD CONSTRAINT dfir_case_verified_findings_pkey PRIMARY KEY (id);


--
-- Name: dfir_claim_evidence_links_v1 dfir_claim_evidence_links_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_claim_evidence_links_v1
    ADD CONSTRAINT dfir_claim_evidence_links_v1_pkey PRIMARY KEY (link_id);


--
-- Name: dfir_claims_v1 dfir_claims_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_claims_v1
    ADD CONSTRAINT dfir_claims_v1_pkey PRIMARY KEY (claim_id);


--
-- Name: dfir_eval_answers_v1 dfir_eval_answers_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_eval_answers_v1
    ADD CONSTRAINT dfir_eval_answers_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_eval_failures_v1 dfir_eval_failures_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_eval_failures_v1
    ADD CONSTRAINT dfir_eval_failures_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_eval_questions_v1 dfir_eval_questions_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_eval_questions_v1
    ADD CONSTRAINT dfir_eval_questions_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_finetune_dataset_v1 dfir_finetune_dataset_v1_case_key_source_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_finetune_dataset_v1
    ADD CONSTRAINT dfir_finetune_dataset_v1_case_key_source_key UNIQUE (case_key, source);


--
-- Name: dfir_finetune_dataset_v1 dfir_finetune_dataset_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_finetune_dataset_v1
    ADD CONSTRAINT dfir_finetune_dataset_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_fix_candidates_v1 dfir_fix_candidates_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_fix_candidates_v1
    ADD CONSTRAINT dfir_fix_candidates_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_global_artifact_playbooks dfir_global_artifact_playbooks_intent_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_global_artifact_playbooks
    ADD CONSTRAINT dfir_global_artifact_playbooks_intent_name_key UNIQUE (intent_name);


--
-- Name: dfir_global_artifact_playbooks dfir_global_artifact_playbooks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_global_artifact_playbooks
    ADD CONSTRAINT dfir_global_artifact_playbooks_pkey PRIMARY KEY (id);


--
-- Name: dfir_golden_facts_v1 dfir_golden_facts_v1_case_key_category_fact_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_golden_facts_v1
    ADD CONSTRAINT dfir_golden_facts_v1_case_key_category_fact_key_key UNIQUE (case_key, category, fact_key);


--
-- Name: dfir_golden_facts_v1 dfir_golden_facts_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_golden_facts_v1
    ADD CONSTRAINT dfir_golden_facts_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_ingest_coverage_v1 dfir_ingest_coverage_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_ingest_coverage_v1
    ADD CONSTRAINT dfir_ingest_coverage_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_investigation_journal_v1 dfir_investigation_journal_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_investigation_journal_v1
    ADD CONSTRAINT dfir_investigation_journal_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_investigation_snapshot_v1 dfir_investigation_snapshot_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_investigation_snapshot_v1
    ADD CONSTRAINT dfir_investigation_snapshot_v1_pkey PRIMARY KEY (job_id, phase);


--
-- Name: dfir_ioc_pending_v1 dfir_ioc_pending_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_ioc_pending_v1
    ADD CONSTRAINT dfir_ioc_pending_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_learning_qa_eval dfir_learning_qa_eval_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_learning_qa_eval
    ADD CONSTRAINT dfir_learning_qa_eval_pkey PRIMARY KEY (id);


--
-- Name: dfir_learning_runs dfir_learning_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_learning_runs
    ADD CONSTRAINT dfir_learning_runs_pkey PRIMARY KEY (id);


--
-- Name: dfir_learning_runs dfir_learning_runs_run_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_learning_runs
    ADD CONSTRAINT dfir_learning_runs_run_id_key UNIQUE (run_id);


--
-- Name: dfir_lessons_learned_v1 dfir_lessons_learned_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_lessons_learned_v1
    ADD CONSTRAINT dfir_lessons_learned_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_link_alert_seen_v1 dfir_link_alert_seen_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_link_alert_seen_v1
    ADD CONSTRAINT dfir_link_alert_seen_v1_pkey PRIMARY KEY (case_key);


--
-- Name: dfir_model_routing_audit dfir_model_routing_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_model_routing_audit
    ADD CONSTRAINT dfir_model_routing_audit_pkey PRIMARY KEY (id);


--
-- Name: dfir_night_deep_done_v1 dfir_night_deep_done_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_night_deep_done_v1
    ADD CONSTRAINT dfir_night_deep_done_v1_pkey PRIMARY KEY (day);


--
-- Name: dfir_night_report_done dfir_night_report_done_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_night_report_done
    ADD CONSTRAINT dfir_night_report_done_pkey PRIMARY KEY (report_case_key);


--
-- Name: dfir_playbook_learned_sources dfir_playbook_learned_sources_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_playbook_learned_sources
    ADD CONSTRAINT dfir_playbook_learned_sources_pkey PRIMARY KEY (id);


--
-- Name: dfir_playbook_suggestions dfir_playbook_suggestions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_playbook_suggestions
    ADD CONSTRAINT dfir_playbook_suggestions_pkey PRIMARY KEY (id);


--
-- Name: dfir_playbooks_v1 dfir_playbooks_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_playbooks_v1
    ADD CONSTRAINT dfir_playbooks_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_qa_answers dfir_qa_answers_answer_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_qa_answers
    ADD CONSTRAINT dfir_qa_answers_answer_id_key UNIQUE (answer_id);


--
-- Name: dfir_qa_answers dfir_qa_answers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_qa_answers
    ADD CONSTRAINT dfir_qa_answers_pkey PRIMARY KEY (id);


--
-- Name: dfir_qa_cache_v1 dfir_qa_cache_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_qa_cache_v1
    ADD CONSTRAINT dfir_qa_cache_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_qa_corrections_pending dfir_qa_corrections_pending_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_qa_corrections_pending
    ADD CONSTRAINT dfir_qa_corrections_pending_pkey PRIMARY KEY (id);


--
-- Name: dfir_qa_feedback dfir_qa_feedback_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_qa_feedback
    ADD CONSTRAINT dfir_qa_feedback_pkey PRIMARY KEY (id);


--
-- Name: dfir_reusable_playbooks dfir_reusable_playbooks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_reusable_playbooks
    ADD CONSTRAINT dfir_reusable_playbooks_pkey PRIMARY KEY (id);


--
-- Name: dfir_reusable_playbooks dfir_reusable_playbooks_playbook_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_reusable_playbooks
    ADD CONSTRAINT dfir_reusable_playbooks_playbook_id_key UNIQUE (playbook_id);


--
-- Name: dfir_run_jobs_v2 dfir_run_jobs_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_run_jobs_v2
    ADD CONSTRAINT dfir_run_jobs_v2_pkey PRIMARY KEY (job_id);


--
-- Name: dfir_run_steps_v2 dfir_run_steps_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_run_steps_v2
    ADD CONSTRAINT dfir_run_steps_v2_pkey PRIMARY KEY (step_id);


--
-- Name: dfir_self_eval_gaps_v1 dfir_self_eval_gaps_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_self_eval_gaps_v1
    ADD CONSTRAINT dfir_self_eval_gaps_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_self_eval_runs_v1 dfir_self_eval_runs_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_self_eval_runs_v1
    ADD CONSTRAINT dfir_self_eval_runs_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_skills_v1 dfir_skills_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_skills_v1
    ADD CONSTRAINT dfir_skills_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_skills_v1 dfir_skills_v1_skill_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_skills_v1
    ADD CONSTRAINT dfir_skills_v1_skill_id_key UNIQUE (skill_id);


--
-- Name: dfir_user_feedback_v1 dfir_user_feedback_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_user_feedback_v1
    ADD CONSTRAINT dfir_user_feedback_v1_pkey PRIMARY KEY (id);


--
-- Name: event_logs_v2 event_logs_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_logs_v2
    ADD CONSTRAINT event_logs_v2_pkey PRIMARY KEY (row_id);


--
-- Name: filesystem_v2 filesystem_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.filesystem_v2
    ADD CONSTRAINT filesystem_v2_pkey PRIMARY KEY (row_id);


--
-- Name: ingest_files ingest_files_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingest_files
    ADD CONSTRAINT ingest_files_pkey PRIMARY KEY (file_id);


--
-- Name: ingest_jobs ingest_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingest_jobs
    ADD CONSTRAINT ingest_jobs_pkey PRIMARY KEY (job_id);


--
-- Name: ioc_enrichment ioc_enrichment_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_enrichment
    ADD CONSTRAINT ioc_enrichment_pkey PRIMARY KEY (ioc_norm);


--
-- Name: ioc_overlap ioc_overlap_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ioc_overlap
    ADD CONSTRAINT ioc_overlap_pkey PRIMARY KEY (overlap_id);


--
-- Name: llm_self_improvement_v1 llm_self_improvement_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_self_improvement_v1
    ADD CONSTRAINT llm_self_improvement_v1_pkey PRIMARY KEY (id);


--
-- Name: local_accounts_v1 local_accounts_v1_case_key_rid_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.local_accounts_v1
    ADD CONSTRAINT local_accounts_v1_case_key_rid_key UNIQUE (case_key, rid);


--
-- Name: local_accounts_v1 local_accounts_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.local_accounts_v1
    ADD CONSTRAINT local_accounts_v1_pkey PRIMARY KEY (row_id);


--
-- Name: pg_triggers_cache pg_triggers_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pg_triggers_cache
    ADD CONSTRAINT pg_triggers_cache_pkey PRIMARY KEY (trigger);


--
-- Name: program_exec_v2 program_exec_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.program_exec_v2
    ADD CONSTRAINT program_exec_v2_pkey PRIMARY KEY (row_id);


--
-- Name: ram_jobs_v1 ram_jobs_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ram_jobs_v1
    ADD CONSTRAINT ram_jobs_v1_pkey PRIMARY KEY (id);


--
-- Name: raw_fallback_v2 raw_fallback_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.raw_fallback_v2
    ADD CONSTRAINT raw_fallback_v2_pkey PRIMARY KEY (row_id);


--
-- Name: report_chunks_v1 report_chunks_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.report_chunks_v1
    ADD CONSTRAINT report_chunks_v1_pkey PRIMARY KEY (case_key, source, chunk_index);


--
-- Name: study_courses study_courses_course_key_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.study_courses
    ADD CONSTRAINT study_courses_course_key_key UNIQUE (course_key);


--
-- Name: study_courses study_courses_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.study_courses
    ADD CONSTRAINT study_courses_pkey PRIMARY KEY (id);


--
-- Name: study_import_jobs study_import_jobs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.study_import_jobs
    ADD CONSTRAINT study_import_jobs_pkey PRIMARY KEY (id);


--
-- Name: study_questions study_questions_course_id_source_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.study_questions
    ADD CONSTRAINT study_questions_course_id_source_hash_key UNIQUE (course_id, source_hash);


--
-- Name: study_questions study_questions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.study_questions
    ADD CONSTRAINT study_questions_pkey PRIMARY KEY (id);


--
-- Name: study_sessions study_sessions_chat_id_user_id_active_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.study_sessions
    ADD CONSTRAINT study_sessions_chat_id_user_id_active_key UNIQUE (chat_id, user_id, active);


--
-- Name: study_sessions study_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.study_sessions
    ADD CONSTRAINT study_sessions_pkey PRIMARY KEY (id);


--
-- Name: security_events_v1 security_events_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events_v1
    ADD CONSTRAINT security_events_v1_pkey PRIMARY KEY (id);


--
-- Name: security_events_v1 security_events_v1_src_ip_kind_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.security_events_v1
    ADD CONSTRAINT security_events_v1_src_ip_kind_key UNIQUE (src_ip, kind);


--
-- Name: srum_v2 srum_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.srum_v2
    ADD CONSTRAINT srum_v2_pkey PRIMARY KEY (row_id);


--
-- Name: system_profile_v1 system_profile_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_profile_v1
    ADD CONSTRAINT system_profile_v1_pkey PRIMARY KEY (case_key);


--
-- Name: tool_alerts_v2 tool_alerts_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tool_alerts_v2
    ADD CONSTRAINT tool_alerts_v2_pkey PRIMARY KEY (row_id);


--
-- Name: trigger_catalog_v1 trigger_catalog_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trigger_catalog_v1
    ADD CONSTRAINT trigger_catalog_v1_pkey PRIMARY KEY (trigger_id);


--
-- Name: trigger_catalog_v1 trigger_catalog_v1_trigger_text_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trigger_catalog_v1
    ADD CONSTRAINT trigger_catalog_v1_trigger_text_key UNIQUE (trigger_text);


--
-- Name: trigger_scan_jobs_v2 trigger_scan_jobs_v2_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trigger_scan_jobs_v2
    ADD CONSTRAINT trigger_scan_jobs_v2_pkey PRIMARY KEY (job_id);


--
-- Name: trigger_time_windows_v1 trigger_time_windows_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.trigger_time_windows_v1
    ADD CONSTRAINT trigger_time_windows_v1_pkey PRIMARY KEY (run_id);


--
-- Name: upload_audit_v1 upload_audit_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.upload_audit_v1
    ADD CONSTRAINT upload_audit_v1_pkey PRIMARY KEY (id);


--
-- Name: dfir_run_steps_v2 uq_dfir_steps_job_step; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_run_steps_v2
    ADD CONSTRAINT uq_dfir_steps_job_step UNIQUE (job_id, step_no);


--
-- Name: user_access_v1 user_access_v1_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.user_access_v1
    ADD CONSTRAINT user_access_v1_pkey PRIMARY KEY (user_id);


--
-- Name: idx_access_audit_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_access_audit_ts ON public.access_audit_v1 USING btree (ts DESC);


--
-- Name: idx_access_req_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_access_req_status ON public.access_requests_v1 USING btree (status, id);


--
-- Name: idx_acn_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_acn_case ON public.agent_case_notes USING btree (case_key);


--
-- Name: idx_assistant_log_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_assistant_log_ts ON public.assistant_log USING btree (ts DESC);


--
-- Name: idx_autonomous_dfir_batches_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_autonomous_dfir_batches_case ON public.autonomous_dfir_batches_v1 USING btree (case_key, created_at DESC);


--
-- Name: idx_bmark_gaps_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_bmark_gaps_run ON public.dfir_benchmark_gaps_v1 USING btree (run_id);


--
-- Name: idx_bmark_runs_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_bmark_runs_case ON public.dfir_benchmark_runs_v1 USING btree (case_key, started_at DESC);


--
-- Name: idx_bot_audit_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_bot_audit_ts ON public.bot_audit_events USING btree (ts DESC);


--
-- Name: idx_bot_audit_user; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_bot_audit_user ON public.bot_audit_events USING btree (user_id);


--
-- Name: idx_bot_users_role; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_bot_users_role ON public.bot_users USING btree (role);


--
-- Name: idx_case_evidence_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_evidence_case ON public.case_evidence USING btree (case_key, seq);


--
-- Name: idx_case_evidence_sha256; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_evidence_sha256 ON public.case_evidence USING btree (sha256);


--
-- Name: idx_case_facts_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_facts_case ON public.dfir_case_facts USING btree (case_key);


--
-- Name: idx_case_facts_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_facts_status ON public.dfir_case_facts USING btree (status);


--
-- Name: idx_case_facts_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_facts_type ON public.dfir_case_facts USING btree (case_key, fact_type);


--
-- Name: idx_case_feedback_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_feedback_case ON public.case_feedback USING btree (case_key);


--
-- Name: idx_case_feedback_verdict; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_feedback_verdict ON public.case_feedback USING btree (verdict);


--
-- Name: idx_case_iocs_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_iocs_case ON public.case_iocs USING btree (case_key);


--
-- Name: idx_case_iocs_norm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_iocs_norm ON public.case_iocs USING btree (ioc_norm);


--
-- Name: idx_case_learnings_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_learnings_case ON public.case_learnings_v1 USING btree (case_key);


--
-- Name: idx_case_learnings_topic; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_learnings_topic ON public.case_learnings_v1 USING btree (topic, created_at DESC);


--
-- Name: idx_case_qa_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_case_qa_case ON public.dfir_case_qa_v1 USING btree (case_key);


--
-- Name: idx_cth2_case_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_cth2_case_run ON public.case_trigger_hits_v2 USING btree (case_key, run_id);


--
-- Name: idx_dfir_claim_links_v1_case_job; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dfir_claim_links_v1_case_job ON public.dfir_claim_evidence_links_v1 USING btree (case_key, job_id);


--
-- Name: idx_dfir_claim_links_v1_claim; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dfir_claim_links_v1_claim ON public.dfir_claim_evidence_links_v1 USING btree (claim_id);


--
-- Name: idx_dfir_claims_v1_case_job; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dfir_claims_v1_case_job ON public.dfir_claims_v1 USING btree (case_key, job_id);


--
-- Name: idx_dfir_claims_v1_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dfir_claims_v1_type ON public.dfir_claims_v1 USING btree (claim_type);


--
-- Name: idx_dfir_jobs_case_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dfir_jobs_case_created ON public.dfir_run_jobs_v2 USING btree (case_key, created_at DESC);


--
-- Name: idx_dfir_jobs_case_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dfir_jobs_case_status ON public.dfir_run_jobs_v2 USING btree (case_key, status);


--
-- Name: idx_dfir_jobs_retry_of; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dfir_jobs_retry_of ON public.dfir_run_jobs_v2 USING btree (retry_of_job_id);


--
-- Name: idx_dfir_steps_job_heartbeat; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dfir_steps_job_heartbeat ON public.dfir_run_steps_v2 USING btree (job_id, heartbeat_at DESC);


--
-- Name: idx_dfir_steps_job_no; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dfir_steps_job_no ON public.dfir_run_steps_v2 USING btree (job_id, step_no);


--
-- Name: idx_dfir_steps_job_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dfir_steps_job_status ON public.dfir_run_steps_v2 USING btree (job_id, step_status);


--
-- Name: idx_ev2_case_computer; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ev2_case_computer ON public.event_logs_v2 USING btree (case_key, computer);


--
-- Name: idx_ev2_case_eid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ev2_case_eid ON public.event_logs_v2 USING btree (case_key, event_id);


--
-- Name: idx_ev2_case_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ev2_case_ts ON public.event_logs_v2 USING btree (case_key, event_ts);


--
-- Name: idx_ev2_payload_gin; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ev2_payload_gin ON public.event_logs_v2 USING gin (payload);


--
-- Name: idx_ev2_payload_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ev2_payload_trgm ON public.event_logs_v2 USING gin (((payload)::text) public.gin_trgm_ops);


--
-- Name: idx_eval_f_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_eval_f_case ON public.dfir_eval_failures_v1 USING btree (case_key, failure_type);


--
-- Name: idx_eval_fc_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_eval_fc_type ON public.dfir_fix_candidates_v1 USING btree (failure_type, priority);


--
-- Name: idx_eval_q_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_eval_q_case ON public.dfir_eval_questions_v1 USING btree (case_key);


--
-- Name: idx_fs2_case_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fs2_case_ts ON public.filesystem_v2 USING btree (case_key, event_ts);


--
-- Name: idx_fs2_fname_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fs2_fname_trgm ON public.filesystem_v2 USING gin (file_name public.gin_trgm_ops);


--
-- Name: idx_fs2_payload_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fs2_payload_trgm ON public.filesystem_v2 USING gin (((payload)::text) public.gin_trgm_ops);


--
-- Name: idx_fs2_ppath_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fs2_ppath_trgm ON public.filesystem_v2 USING gin (parent_path public.gin_trgm_ops);


--
-- Name: idx_gap_intent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_gap_intent ON public.dfir_global_artifact_playbooks USING btree (intent_name);


--
-- Name: idx_golden_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_golden_case ON public.dfir_golden_facts_v1 USING btree (case_key, category);


--
-- Name: idx_ingest_cov_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ingest_cov_case ON public.dfir_ingest_coverage_v1 USING btree (case_key);


--
-- Name: idx_invjournal_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_invjournal_case ON public.dfir_investigation_journal_v1 USING btree (case_key, created_at DESC);


--
-- Name: idx_invjournal_job; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_invjournal_job ON public.dfir_investigation_journal_v1 USING btree (job_id, id);


--
-- Name: idx_ioc_overlap_cases; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ioc_overlap_cases ON public.ioc_overlap USING btree (case_a, case_b);


--
-- Name: idx_learning_qa_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_learning_qa_case ON public.dfir_learning_qa_eval USING btree (case_key);


--
-- Name: idx_learning_qa_run; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_learning_qa_run ON public.dfir_learning_qa_eval USING btree (learning_run_id);


--
-- Name: idx_learning_runs_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_learning_runs_case ON public.dfir_learning_runs USING btree (case_key, created_at DESC);


--
-- Name: idx_llm_selfimprove_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_llm_selfimprove_case ON public.llm_self_improvement_v1 USING btree (case_key, created_at DESC);


--
-- Name: idx_llm_selfimprove_verdict; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_llm_selfimprove_verdict ON public.llm_self_improvement_v1 USING btree (verdict, confidence);


--
-- Name: idx_mra_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mra_case ON public.dfir_model_routing_audit USING btree (case_key);


--
-- Name: idx_mra_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mra_created ON public.dfir_model_routing_audit USING btree (created_at DESC);


--
-- Name: idx_mra_task; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mra_task ON public.dfir_model_routing_audit USING btree (task_name);


--
-- Name: idx_pb_intent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_intent ON public.dfir_reusable_playbooks USING btree (intent_name);


--
-- Name: idx_pb_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pb_status ON public.dfir_reusable_playbooks USING btree (status);


--
-- Name: idx_pe2_case_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pe2_case_ts ON public.program_exec_v2 USING btree (case_key, event_ts);


--
-- Name: idx_playbook_sug_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbook_sug_status ON public.dfir_playbook_suggestions USING btree (status, created_at DESC);


--
-- Name: idx_playbooks_gap; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_playbooks_gap ON public.dfir_playbooks_v1 USING btree (gap_type);


--
-- Name: idx_progexec_payload_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_progexec_payload_trgm ON public.program_exec_v2 USING gin (((payload)::text) public.gin_trgm_ops);


--
-- Name: idx_qa_ans_aid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_qa_ans_aid ON public.dfir_qa_answers USING btree (answer_id);


--
-- Name: idx_qa_ans_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_qa_ans_case ON public.dfir_qa_answers USING btree (case_key);


--
-- Name: idx_qa_cache_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_qa_cache_case ON public.dfir_qa_cache_v1 USING btree (case_key);


--
-- Name: idx_qa_cache_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_qa_cache_trgm ON public.dfir_qa_cache_v1 USING gin (question public.gin_trgm_ops);


--
-- Name: idx_qa_corr_chat; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_qa_corr_chat ON public.dfir_qa_corrections_pending USING btree (chat_id, waiting_for_correction);


--
-- Name: idx_qa_fb_aid; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_qa_fb_aid ON public.dfir_qa_feedback USING btree (answer_id);


--
-- Name: idx_rawfb_payload_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rawfb_payload_trgm ON public.raw_fallback_v2 USING gin (((payload)::text) public.gin_trgm_ops);


--
-- Name: idx_rc_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rc_case ON public.report_chunks_v1 USING btree (case_key);


--
-- Name: idx_rc_trgm; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rc_trgm ON public.report_chunks_v1 USING gin (chunk_text public.gin_trgm_ops);


--
-- Name: idx_rf2_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_rf2_case ON public.raw_fallback_v2 USING btree (case_key);


--
-- Name: idx_study_questions_course; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_study_questions_course ON public.study_questions USING btree (course_id);


--
-- Name: idx_study_sessions_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_study_sessions_lookup ON public.study_sessions USING btree (chat_id, user_id, active);


--
-- Name: idx_skills_intent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_skills_intent ON public.dfir_skills_v1 USING btree (intent);


--
-- Name: idx_srum2_case_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_srum2_case_ts ON public.srum_v2 USING btree (case_key, event_ts);


--
-- Name: idx_ta2_case_tool; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ta2_case_tool ON public.tool_alerts_v2 USING btree (case_key, tool);


--
-- Name: idx_ta2_case_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_ta2_case_ts ON public.tool_alerts_v2 USING btree (case_key, event_ts);


--
-- Name: idx_tl_cache_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tl_cache_case ON public.dfir_case_timeline_cache USING btree (case_key);


--
-- Name: idx_trigger_catalog_enabled_priority; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_trigger_catalog_enabled_priority ON public.trigger_catalog_v1 USING btree (enabled, priority, trigger_text);


--
-- Name: idx_trigger_catalog_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_trigger_catalog_source ON public.trigger_catalog_v1 USING btree (source);


--
-- Name: idx_trigger_scan_jobs_case_started; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_trigger_scan_jobs_case_started ON public.trigger_scan_jobs_v2 USING btree (case_key, started_at DESC);


--
-- Name: idx_trigger_time_windows_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_trigger_time_windows_case ON public.trigger_time_windows_v1 USING btree (case_key, updated_at DESC);


--
-- Name: idx_upload_audit_client; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_upload_audit_client ON public.upload_audit_v1 USING btree (vpn_client);


--
-- Name: idx_upload_audit_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_upload_audit_ts ON public.upload_audit_v1 USING btree (ts DESC);


--
-- Name: idx_verified_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_verified_case ON public.case_verified_facts USING btree (case_key);


--
-- Name: idx_verified_findings_case; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_verified_findings_case ON public.dfir_case_verified_findings USING btree (case_key, approval_status);


--
-- Name: idx_verified_findings_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_verified_findings_type ON public.dfir_case_verified_findings USING btree (case_key, finding_type);


--
-- Name: ix_comms_ck; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_comms_ck ON public.communications_v1 USING btree (case_key);


--
-- Name: ix_comms_ck_contact; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_comms_ck_contact ON public.communications_v1 USING btree (case_key, contact_id);


--
-- Name: ix_comms_ck_plat; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_comms_ck_plat ON public.communications_v1 USING btree (case_key, platform);


--
-- Name: ix_ev2_ck_cmdline; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_ev2_ck_cmdline ON public.event_logs_v2 USING btree (case_key) WHERE ((COALESCE(command_line, ''::text) <> ''::text) OR (COALESCE(process_name, ''::text) <> ''::text));


--
-- Name: ix_event_logs_v2_ck_src; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_event_logs_v2_ck_src ON public.event_logs_v2 USING btree (case_key, source_file);


--
-- Name: ix_fcl_tg; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fcl_tg ON public.bot_free_chat_log USING btree (tg_id, ts DESC);


--
-- Name: ix_filesystem_v2_ck_src; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_filesystem_v2_ck_src ON public.filesystem_v2 USING btree (case_key, source_file);


--
-- Name: ix_fs2_ck_lname; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fs2_ck_lname ON public.filesystem_v2 USING btree (case_key, lower(file_name));


--
-- Name: ix_fs2_ck_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fs2_ck_name ON public.filesystem_v2 USING btree (case_key, file_name);


--
-- Name: ix_fs2_ck_parent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_fs2_ck_parent ON public.filesystem_v2 USING btree (case_key, parent_path);


--
-- Name: ix_localacc_ck; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_localacc_ck ON public.local_accounts_v1 USING btree (case_key);


--
-- Name: ix_program_exec_v2_ck_src; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_program_exec_v2_ck_src ON public.program_exec_v2 USING btree (case_key, source_file);


--
-- Name: ix_raw_fallback_v2_ck_src; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_raw_fallback_v2_ck_src ON public.raw_fallback_v2 USING btree (case_key, source_file);


--
-- Name: ix_rf2_ck_fam_ts; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_rf2_ck_fam_ts ON public.raw_fallback_v2 USING btree (case_key, parser_family, event_ts);


--
-- Name: ix_secevt_last; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_secevt_last ON public.security_events_v1 USING btree (last_seen DESC);


--
-- Name: ix_srum_v2_ck_src; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX ix_srum_v2_ck_src ON public.srum_v2 USING btree (case_key, source_file);


--
-- Name: uq_case_iocs_dedupe; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_case_iocs_dedupe ON public.case_iocs USING btree (case_key, ioc_type, ioc_norm);


--
-- Name: uq_case_qa; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_case_qa ON public.dfir_case_qa_v1 USING btree (case_key, question);


--
-- Name: uq_dfir_jobs_active_per_case; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_dfir_jobs_active_per_case ON public.dfir_run_jobs_v2 USING btree (case_key) WHERE (status = ANY (ARRAY['queued'::text, 'running'::text]));


--
-- Name: uq_ioc_overlap; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_ioc_overlap ON public.ioc_overlap USING btree (case_a, case_b, ioc_type, ioc_norm);


--
-- Name: uq_pb_learned; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX uq_pb_learned ON public.dfir_playbook_learned_sources USING btree (intent_name, source_file);


--
-- Name: ux_dfir_active_case; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX ux_dfir_active_case ON public.dfir_run_jobs_v2 USING btree (case_key) WHERE (status = ANY (ARRAY['queued'::text, 'running'::text]));


--
-- Name: raw_fallback_v2 trg_raw_fallback_event_ts; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_raw_fallback_event_ts BEFORE INSERT ON public.raw_fallback_v2 FOR EACH ROW EXECUTE FUNCTION public.raw_fallback_set_event_ts();


--
-- Name: case_trigger_hits_v2 case_trigger_hits_v2_case_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.case_trigger_hits_v2
    ADD CONSTRAINT case_trigger_hits_v2_case_key_fkey FOREIGN KEY (case_key) REFERENCES public.cases(case_key) ON DELETE CASCADE;


--
-- Name: dfir_learning_qa_eval dfir_learning_qa_eval_learning_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_learning_qa_eval
    ADD CONSTRAINT dfir_learning_qa_eval_learning_run_id_fkey FOREIGN KEY (learning_run_id) REFERENCES public.dfir_learning_runs(id) ON DELETE CASCADE;


--
-- Name: dfir_playbook_suggestions dfir_playbook_suggestions_source_learning_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_playbook_suggestions
    ADD CONSTRAINT dfir_playbook_suggestions_source_learning_run_id_fkey FOREIGN KEY (source_learning_run_id) REFERENCES public.dfir_learning_runs(id) ON DELETE SET NULL;


--
-- Name: dfir_run_jobs_v2 dfir_run_jobs_v2_retry_of_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_run_jobs_v2
    ADD CONSTRAINT dfir_run_jobs_v2_retry_of_job_id_fkey FOREIGN KEY (retry_of_job_id) REFERENCES public.dfir_run_jobs_v2(job_id);


--
-- Name: dfir_run_steps_v2 dfir_run_steps_v2_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dfir_run_steps_v2
    ADD CONSTRAINT dfir_run_steps_v2_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.dfir_run_jobs_v2(job_id) ON DELETE CASCADE;


--
-- Name: event_logs_v2 event_logs_v2_case_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_logs_v2
    ADD CONSTRAINT event_logs_v2_case_key_fkey FOREIGN KEY (case_key) REFERENCES public.cases(case_key) ON DELETE CASCADE;


--
-- Name: event_logs_v2 event_logs_v2_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.event_logs_v2
    ADD CONSTRAINT event_logs_v2_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.ingest_files(file_id) ON DELETE SET NULL;


--
-- Name: filesystem_v2 filesystem_v2_case_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.filesystem_v2
    ADD CONSTRAINT filesystem_v2_case_key_fkey FOREIGN KEY (case_key) REFERENCES public.cases(case_key) ON DELETE CASCADE;


--
-- Name: filesystem_v2 filesystem_v2_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.filesystem_v2
    ADD CONSTRAINT filesystem_v2_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.ingest_files(file_id) ON DELETE SET NULL;


--
-- Name: ingest_files ingest_files_case_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingest_files
    ADD CONSTRAINT ingest_files_case_key_fkey FOREIGN KEY (case_key) REFERENCES public.cases(case_key) ON DELETE CASCADE;


--
-- Name: ingest_files ingest_files_job_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingest_files
    ADD CONSTRAINT ingest_files_job_id_fkey FOREIGN KEY (job_id) REFERENCES public.ingest_jobs(job_id) ON DELETE CASCADE;


--
-- Name: ingest_jobs ingest_jobs_case_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ingest_jobs
    ADD CONSTRAINT ingest_jobs_case_key_fkey FOREIGN KEY (case_key) REFERENCES public.cases(case_key) ON DELETE CASCADE;


--
-- Name: program_exec_v2 program_exec_v2_case_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.program_exec_v2
    ADD CONSTRAINT program_exec_v2_case_key_fkey FOREIGN KEY (case_key) REFERENCES public.cases(case_key) ON DELETE CASCADE;


--
-- Name: program_exec_v2 program_exec_v2_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.program_exec_v2
    ADD CONSTRAINT program_exec_v2_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.ingest_files(file_id) ON DELETE SET NULL;


--
-- Name: raw_fallback_v2 raw_fallback_v2_case_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.raw_fallback_v2
    ADD CONSTRAINT raw_fallback_v2_case_key_fkey FOREIGN KEY (case_key) REFERENCES public.cases(case_key) ON DELETE CASCADE;


--
-- Name: raw_fallback_v2 raw_fallback_v2_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.raw_fallback_v2
    ADD CONSTRAINT raw_fallback_v2_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.ingest_files(file_id) ON DELETE SET NULL;


--
-- Name: study_import_jobs study_import_jobs_course_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.study_import_jobs
    ADD CONSTRAINT study_import_jobs_course_id_fkey FOREIGN KEY (course_id) REFERENCES public.study_courses(id) ON DELETE CASCADE;


--
-- Name: study_questions study_questions_course_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.study_questions
    ADD CONSTRAINT study_questions_course_id_fkey FOREIGN KEY (course_id) REFERENCES public.study_courses(id) ON DELETE CASCADE;


--
-- Name: study_sessions study_sessions_course_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.study_sessions
    ADD CONSTRAINT study_sessions_course_id_fkey FOREIGN KEY (course_id) REFERENCES public.study_courses(id) ON DELETE CASCADE;


--
-- Name: srum_v2 srum_v2_case_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.srum_v2
    ADD CONSTRAINT srum_v2_case_key_fkey FOREIGN KEY (case_key) REFERENCES public.cases(case_key) ON DELETE CASCADE;


--
-- Name: srum_v2 srum_v2_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.srum_v2
    ADD CONSTRAINT srum_v2_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.ingest_files(file_id) ON DELETE SET NULL;


--
-- Name: tool_alerts_v2 tool_alerts_v2_case_key_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tool_alerts_v2
    ADD CONSTRAINT tool_alerts_v2_case_key_fkey FOREIGN KEY (case_key) REFERENCES public.cases(case_key) ON DELETE CASCADE;


--
-- Name: tool_alerts_v2 tool_alerts_v2_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tool_alerts_v2
    ADD CONSTRAINT tool_alerts_v2_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.ingest_files(file_id) ON DELETE SET NULL;


--
-- PostgreSQL database dump complete
--

\unrestrict IJwPaWyQOq6y7Vn2VLSTaZ4jAhWj4SyQeMSHIgj9TdKdU67hxpFSgsUEEZDuOIP


-- P9: who uploaded what through the Open WebUI chat (sandbox analysis)
CREATE TABLE IF NOT EXISTS public.portal_upload_audit_v1 (
    id bigserial PRIMARY KEY,
    ts timestamptz NOT NULL DEFAULT now(),
    owui_user_id text, owui_email text, owui_name text, client_ip text,
    file_name text, size_bytes bigint, sha256 text,
    verdict text NOT NULL, reason text, job text, seconds real);
CREATE INDEX IF NOT EXISTS portal_upload_audit_v1_ts ON public.portal_upload_audit_v1 (ts DESC);
CREATE INDEX IF NOT EXISTS portal_upload_audit_v1_email ON public.portal_upload_audit_v1 (owui_email);
-- private: the MCP / LLM read-only role must not see who uploaded what
DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='dfir_mcp') THEN REVOKE ALL ON public.portal_upload_audit_v1 FROM dfir_mcp; END IF; END $$;
