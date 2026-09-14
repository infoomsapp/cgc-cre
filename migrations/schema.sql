-- CGC Core -- schema reference archive
--
-- Generated 2026-09-14 via `pg_dump --schema-only --no-owner --no-privileges`
-- against a disposable Postgres 17 container with every step in
-- scripts/run_schema_migrations.py applied (the 5 core schema methods plus
-- launch_readiness, calibration_changelog, tenant_webhooks,
-- webhook_retry_queue, tenant_weighting_overrides, saml_connections).
-- This is documentation, not something anything loads or applies -- the
-- real, authoritative migration path is still run_schema_migrations.py,
-- which is idempotent and safe to re-run against any environment.
--
-- Known gap: the cgc_app role and its RLS policies (database.py's
-- _create_rls_policies()) do NOT appear below. That step needs Supabase's
-- `extensions` schema (for extensions.uuid_generate_v5, used by the
-- pod_ledger policy) to exist, which a vanilla postgres:17 container
-- doesn't have -- it fails non-fatally and is skipped there, same as it
-- would on any environment missing CGC_APP_ROLE_PASSWORD. Production
-- Supabase has that schema; the real policy definitions live in
-- _create_rls_policies()'s source, not here.
--
-- PostgreSQL database dump
--

-- Dumped from database version 17.11 (Debian 17.11-1.pgdg13+2)
-- Dumped by pg_dump version 17.11 (Debian 17.11-1.pgdg13+2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: cgc_auth; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA cgc_auth;


--
-- Name: cgc_guard; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA cgc_guard;


--
-- Name: cgc_jla; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA cgc_jla;


--
-- Name: cgc_pod; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA cgc_pod;


--
-- Name: cgc_tco; Type: SCHEMA; Schema: -; Owner: -
--

CREATE SCHEMA cgc_tco;


--
-- Name: prevent_ledger_mutation(); Type: FUNCTION; Schema: cgc_pod; Owner: -
--

CREATE FUNCTION cgc_pod.prevent_ledger_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
                        BEGIN
                            RAISE EXCEPTION 'cgc_pod.pod_ledger is append-only: % not permitted', TG_OP;
                        END;
                        $$;


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: api_keys; Type: TABLE; Schema: cgc_auth; Owner: -
--

CREATE TABLE cgc_auth.api_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    app_source text NOT NULL,
    key_prefix text NOT NULL,
    key_hash text NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    created_by text,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone
);


--
-- Name: blocklist; Type: TABLE; Schema: cgc_auth; Owner: -
--

CREATE TABLE cgc_auth.blocklist (
    id integer NOT NULL,
    ip text,
    email text,
    reason text,
    blocked_at text NOT NULL
);


--
-- Name: blocklist_id_seq; Type: SEQUENCE; Schema: cgc_auth; Owner: -
--

CREATE SEQUENCE cgc_auth.blocklist_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: blocklist_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_auth; Owner: -
--

ALTER SEQUENCE cgc_auth.blocklist_id_seq OWNED BY cgc_auth.blocklist.id;


--
-- Name: sessions; Type: TABLE; Schema: cgc_auth; Owner: -
--

CREATE TABLE cgc_auth.sessions (
    token text NOT NULL,
    email text NOT NULL,
    role text NOT NULL,
    created_at text NOT NULL,
    expires_at text NOT NULL,
    ip text
);


--
-- Name: users; Type: TABLE; Schema: cgc_auth; Owner: -
--

CREATE TABLE cgc_auth.users (
    email text NOT NULL,
    password_hash text NOT NULL,
    role text DEFAULT 'user'::text NOT NULL,
    created_at text NOT NULL,
    created_by text,
    active boolean DEFAULT true,
    last_login text,
    login_count integer DEFAULT 0,
    reset_token text,
    reset_expires text
);


--
-- Name: internal_flags; Type: TABLE; Schema: cgc_guard; Owner: -
--

CREATE TABLE cgc_guard.internal_flags (
    id integer NOT NULL,
    flag_type text NOT NULL,
    tenant_id text,
    module_source text,
    details jsonb,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: internal_flags_id_seq; Type: SEQUENCE; Schema: cgc_guard; Owner: -
--

CREATE SEQUENCE cgc_guard.internal_flags_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: internal_flags_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_guard; Owner: -
--

ALTER SEQUENCE cgc_guard.internal_flags_id_seq OWNED BY cgc_guard.internal_flags.id;


--
-- Name: login_attempts; Type: TABLE; Schema: cgc_guard; Owner: -
--

CREATE TABLE cgc_guard.login_attempts (
    id integer NOT NULL,
    ip text,
    email text,
    success boolean,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: login_attempts_id_seq; Type: SEQUENCE; Schema: cgc_guard; Owner: -
--

CREATE SEQUENCE cgc_guard.login_attempts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: login_attempts_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_guard; Owner: -
--

ALTER SEQUENCE cgc_guard.login_attempts_id_seq OWNED BY cgc_guard.login_attempts.id;


--
-- Name: rate_limit_events; Type: TABLE; Schema: cgc_guard; Owner: -
--

CREATE TABLE cgc_guard.rate_limit_events (
    id integer NOT NULL,
    key text NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: rate_limit_events_id_seq; Type: SEQUENCE; Schema: cgc_guard; Owner: -
--

CREATE SEQUENCE cgc_guard.rate_limit_events_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: rate_limit_events_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_guard; Owner: -
--

ALTER SEQUENCE cgc_guard.rate_limit_events_id_seq OWNED BY cgc_guard.rate_limit_events.id;


--
-- Name: suspicious_payloads; Type: TABLE; Schema: cgc_guard; Owner: -
--

CREATE TABLE cgc_guard.suspicious_payloads (
    id integer NOT NULL,
    decision_id text,
    org_id text,
    field text,
    pattern_matched text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: suspicious_payloads_id_seq; Type: SEQUENCE; Schema: cgc_guard; Owner: -
--

CREATE SEQUENCE cgc_guard.suspicious_payloads_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: suspicious_payloads_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_guard; Owner: -
--

ALTER SEQUENCE cgc_guard.suspicious_payloads_id_seq OWNED BY cgc_guard.suspicious_payloads.id;


--
-- Name: tenant_plans; Type: TABLE; Schema: cgc_guard; Owner: -
--

CREATE TABLE cgc_guard.tenant_plans (
    org_id text NOT NULL,
    plan text NOT NULL,
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: tenant_usage; Type: TABLE; Schema: cgc_guard; Owner: -
--

CREATE TABLE cgc_guard.tenant_usage (
    id integer NOT NULL,
    org_id text NOT NULL,
    resource text NOT NULL,
    period text NOT NULL,
    count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: tenant_usage_id_seq; Type: SEQUENCE; Schema: cgc_guard; Owner: -
--

CREATE SEQUENCE cgc_guard.tenant_usage_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tenant_usage_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_guard; Owner: -
--

ALTER SEQUENCE cgc_guard.tenant_usage_id_seq OWNED BY cgc_guard.tenant_usage.id;


--
-- Name: ecm_calibration; Type: TABLE; Schema: cgc_jla; Owner: -
--

CREATE TABLE cgc_jla.ecm_calibration (
    id integer NOT NULL,
    governance_area character varying(50) NOT NULL,
    base_frameworks jsonb NOT NULL,
    sensitivity_modulation jsonb NOT NULL,
    compliance_owner_bonus numeric NOT NULL,
    critical_frameworks jsonb NOT NULL,
    description text,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: ecm_calibration_id_seq; Type: SEQUENCE; Schema: cgc_jla; Owner: -
--

CREATE SEQUENCE cgc_jla.ecm_calibration_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ecm_calibration_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_jla; Owner: -
--

ALTER SEQUENCE cgc_jla.ecm_calibration_id_seq OWNED BY cgc_jla.ecm_calibration.id;


--
-- Name: pan_domain_patterns; Type: TABLE; Schema: cgc_jla; Owner: -
--

CREATE TABLE cgc_jla.pan_domain_patterns (
    id integer NOT NULL,
    governance_area character varying(50) NOT NULL,
    keywords jsonb DEFAULT '[]'::jsonb NOT NULL,
    patterns jsonb DEFAULT '{}'::jsonb NOT NULL,
    sensitivity_multiplier numeric DEFAULT 1.0 NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: pan_domain_patterns_id_seq; Type: SEQUENCE; Schema: cgc_jla; Owner: -
--

CREATE SEQUENCE cgc_jla.pan_domain_patterns_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: pan_domain_patterns_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_jla; Owner: -
--

ALTER SEQUENCE cgc_jla.pan_domain_patterns_id_seq OWNED BY cgc_jla.pan_domain_patterns.id;


--
-- Name: pfm_risk_models; Type: TABLE; Schema: cgc_jla; Owner: -
--

CREATE TABLE cgc_jla.pfm_risk_models (
    id integer NOT NULL,
    governance_area character varying(50) NOT NULL,
    action_type character varying(50) NOT NULL,
    baseline_risk integer NOT NULL,
    sensitivity_multiplier numeric NOT NULL,
    critical_factors jsonb DEFAULT '[]'::jsonb NOT NULL,
    success_probability_baseline numeric,
    failure_modes jsonb DEFAULT '[]'::jsonb NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: pfm_risk_models_id_seq; Type: SEQUENCE; Schema: cgc_jla; Owner: -
--

CREATE SEQUENCE cgc_jla.pfm_risk_models_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: pfm_risk_models_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_jla; Owner: -
--

ALTER SEQUENCE cgc_jla.pfm_risk_models_id_seq OWNED BY cgc_jla.pfm_risk_models.id;


--
-- Name: scm_compliance_standards; Type: TABLE; Schema: cgc_jla; Owner: -
--

CREATE TABLE cgc_jla.scm_compliance_standards (
    id integer NOT NULL,
    standard character varying(50) NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: scm_compliance_standards_id_seq; Type: SEQUENCE; Schema: cgc_jla; Owner: -
--

CREATE SEQUENCE cgc_jla.scm_compliance_standards_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scm_compliance_standards_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_jla; Owner: -
--

ALTER SEQUENCE cgc_jla.scm_compliance_standards_id_seq OWNED BY cgc_jla.scm_compliance_standards.id;


--
-- Name: scm_security_policies; Type: TABLE; Schema: cgc_jla; Owner: -
--

CREATE TABLE cgc_jla.scm_security_policies (
    id integer NOT NULL,
    governance_area character varying(50) NOT NULL,
    encryption_required boolean DEFAULT true NOT NULL,
    signing_required boolean DEFAULT true NOT NULL,
    fingerprint_required boolean DEFAULT false NOT NULL,
    min_key_rotation_days integer DEFAULT 90 NOT NULL,
    audit_log_required boolean DEFAULT true NOT NULL,
    chain_validation_strict boolean DEFAULT false NOT NULL,
    hash_algorithm character varying(20) DEFAULT 'sha256'::character varying NOT NULL,
    signing_algorithm character varying(30) DEFAULT 'rsa_pss_2048'::character varying NOT NULL,
    double_encryption_threshold integer DEFAULT 5 NOT NULL,
    audit_retention_years integer DEFAULT 2 NOT NULL,
    description text,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: scm_security_policies_id_seq; Type: SEQUENCE; Schema: cgc_jla; Owner: -
--

CREATE SEQUENCE cgc_jla.scm_security_policies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scm_security_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_jla; Owner: -
--

ALTER SEQUENCE cgc_jla.scm_security_policies_id_seq OWNED BY cgc_jla.scm_security_policies.id;


--
-- Name: scm_sensitivity_config; Type: TABLE; Schema: cgc_jla; Owner: -
--

CREATE TABLE cgc_jla.scm_sensitivity_config (
    id integer NOT NULL,
    sensitivity_level character varying(20) NOT NULL,
    additional_encryption boolean NOT NULL,
    compression_enabled boolean NOT NULL,
    include_metadata boolean NOT NULL,
    ttl_hours integer NOT NULL,
    require_compliance_owner_sig boolean NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: scm_sensitivity_config_id_seq; Type: SEQUENCE; Schema: cgc_jla; Owner: -
--

CREATE SEQUENCE cgc_jla.scm_sensitivity_config_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: scm_sensitivity_config_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_jla; Owner: -
--

ALTER SEQUENCE cgc_jla.scm_sensitivity_config_id_seq OWNED BY cgc_jla.scm_sensitivity_config.id;


--
-- Name: sda_best_practices; Type: TABLE; Schema: cgc_jla; Owner: -
--

CREATE TABLE cgc_jla.sda_best_practices (
    id integer NOT NULL,
    governance_area character varying(50) NOT NULL,
    data_requirements jsonb DEFAULT '[]'::jsonb NOT NULL,
    quality_factors jsonb DEFAULT '{}'::jsonb NOT NULL,
    risk_mitigations jsonb DEFAULT '[]'::jsonb NOT NULL,
    optimization_priorities jsonb DEFAULT '[]'::jsonb NOT NULL,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: sda_best_practices_id_seq; Type: SEQUENCE; Schema: cgc_jla; Owner: -
--

CREATE SEQUENCE cgc_jla.sda_best_practices_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sda_best_practices_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_jla; Owner: -
--

ALTER SEQUENCE cgc_jla.sda_best_practices_id_seq OWNED BY cgc_jla.sda_best_practices.id;


--
-- Name: tco_retention_policies; Type: TABLE; Schema: cgc_jla; Owner: -
--

CREATE TABLE cgc_jla.tco_retention_policies (
    id integer NOT NULL,
    governance_area character varying(50) NOT NULL,
    retention_days integer DEFAULT 365 NOT NULL,
    compression_enabled boolean DEFAULT true NOT NULL,
    archival_required boolean DEFAULT false NOT NULL,
    blockchain_sync boolean DEFAULT false NOT NULL,
    tamper_detection_level character varying(20) DEFAULT 'MEDIUM'::character varying NOT NULL,
    description text,
    is_active boolean DEFAULT true NOT NULL
);


--
-- Name: tco_retention_policies_id_seq; Type: SEQUENCE; Schema: cgc_jla; Owner: -
--

CREATE SEQUENCE cgc_jla.tco_retention_policies_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: tco_retention_policies_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_jla; Owner: -
--

ALTER SEQUENCE cgc_jla.tco_retention_policies_id_seq OWNED BY cgc_jla.tco_retention_policies.id;


--
-- Name: chain_integrity_log; Type: TABLE; Schema: cgc_pod; Owner: -
--

CREATE TABLE cgc_pod.chain_integrity_log (
    id integer NOT NULL,
    tenant_id text NOT NULL,
    verified_from_block integer,
    verified_to_block integer,
    blocks_verified integer NOT NULL,
    integrity_passed boolean NOT NULL,
    broken_at_block integer,
    verification_time_ms numeric,
    verified_by text,
    verified_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: chain_integrity_log_id_seq; Type: SEQUENCE; Schema: cgc_pod; Owner: -
--

CREATE SEQUENCE cgc_pod.chain_integrity_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: chain_integrity_log_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_pod; Owner: -
--

ALTER SEQUENCE cgc_pod.chain_integrity_log_id_seq OWNED BY cgc_pod.chain_integrity_log.id;


--
-- Name: inference_intercepts; Type: TABLE; Schema: cgc_pod; Owner: -
--

CREATE TABLE cgc_pod.inference_intercepts (
    intercept_id text NOT NULL,
    decision_id text NOT NULL,
    tenant_id text NOT NULL,
    input_payload_hash text NOT NULL,
    model_identifier text NOT NULL,
    output_payload_hash text NOT NULL,
    intercepted_at timestamp with time zone NOT NULL,
    delivery_at timestamp with time zone,
    latency_ms numeric,
    triplet_hash text NOT NULL,
    triplet_signature text NOT NULL,
    signing_key_id text NOT NULL,
    timestamp_token text,
    timestamp_authority text,
    pii_detected boolean DEFAULT false NOT NULL,
    pii_fields_count integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: pod_ledger; Type: TABLE; Schema: cgc_pod; Owner: -
--

CREATE TABLE cgc_pod.pod_ledger (
    block_id bigint NOT NULL,
    block_uuid uuid NOT NULL,
    tenant_id uuid NOT NULL,
    intercept_id uuid NOT NULL,
    decision_id uuid NOT NULL,
    block_number bigint NOT NULL,
    previous_block_hash character varying NOT NULL,
    block_hash character varying NOT NULL,
    merkle_root character varying,
    triplet_hash character varying NOT NULL,
    governance_outcome character varying NOT NULL,
    compliance_score numeric,
    chain_height bigint NOT NULL,
    sealed_at timestamp with time zone DEFAULT now() NOT NULL,
    sealed_by character varying NOT NULL,
    tamper_detected boolean DEFAULT false NOT NULL,
    last_verified_at timestamp with time zone
);


--
-- Name: pod_ledger_block_id_seq; Type: SEQUENCE; Schema: cgc_pod; Owner: -
--

CREATE SEQUENCE cgc_pod.pod_ledger_block_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: pod_ledger_block_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_pod; Owner: -
--

ALTER SEQUENCE cgc_pod.pod_ledger_block_id_seq OWNED BY cgc_pod.pod_ledger.block_id;


--
-- Name: audit_trail; Type: TABLE; Schema: cgc_tco; Owner: -
--

CREATE TABLE cgc_tco.audit_trail (
    id integer NOT NULL,
    block_number integer NOT NULL,
    "timestamp" text NOT NULL,
    decision_id text NOT NULL,
    module_source text,
    area text NOT NULL,
    sensitivity_level text,
    action text NOT NULL,
    data_hash text NOT NULL,
    result_hash text NOT NULL,
    previous_hash text NOT NULL,
    block_hash text NOT NULL,
    compliance_owner_present boolean DEFAULT false,
    critical_framework_violated boolean DEFAULT false,
    human_review_required boolean DEFAULT false,
    retention_days integer DEFAULT 365,
    tamper_detection_level text DEFAULT 'HIGH'::text,
    verified boolean DEFAULT true,
    verification_time_ms numeric DEFAULT 0.0,
    created_at timestamp with time zone DEFAULT now(),
    verified_at timestamp with time zone,
    app_source text,
    outcome text,
    tenant_id text,
    aggregated_score numeric
);


--
-- Name: audit_trail_id_seq; Type: SEQUENCE; Schema: cgc_tco; Owner: -
--

CREATE SEQUENCE cgc_tco.audit_trail_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: audit_trail_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_tco; Owner: -
--

ALTER SEQUENCE cgc_tco.audit_trail_id_seq OWNED BY cgc_tco.audit_trail.id;


--
-- Name: chain_integrity_log; Type: TABLE; Schema: cgc_tco; Owner: -
--

CREATE TABLE cgc_tco.chain_integrity_log (
    id integer NOT NULL,
    "timestamp" text NOT NULL,
    block_number integer,
    verification_result text,
    integrity_score numeric,
    tamper_detected boolean DEFAULT false,
    details text,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: chain_integrity_log_id_seq; Type: SEQUENCE; Schema: cgc_tco; Owner: -
--

CREATE SEQUENCE cgc_tco.chain_integrity_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: chain_integrity_log_id_seq; Type: SEQUENCE OWNED BY; Schema: cgc_tco; Owner: -
--

ALTER SEQUENCE cgc_tco.chain_integrity_log_id_seq OWNED BY cgc_tco.chain_integrity_log.id;


--
-- Name: cgc_audit_traces; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cgc_audit_traces (
    id bigint NOT NULL,
    decision_id character varying(255),
    block_hash character varying(128),
    block_number bigint,
    immutable boolean DEFAULT true,
    verified boolean DEFAULT true,
    merkle_root character varying(128),
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: cgc_audit_traces_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cgc_audit_traces_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cgc_audit_traces_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cgc_audit_traces_id_seq OWNED BY public.cgc_audit_traces.id;


--
-- Name: cgc_calibration_changelog; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cgc_calibration_changelog (
    id bigint NOT NULL,
    module character varying(20) NOT NULL,
    governance_area character varying(50) NOT NULL,
    action_type character varying(50),
    previous_value jsonb,
    new_value jsonb NOT NULL,
    reason text NOT NULL,
    source_name text,
    source_url text,
    changed_by character varying(255) NOT NULL,
    changed_at timestamp with time zone DEFAULT now()
);


--
-- Name: cgc_calibration_changelog_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cgc_calibration_changelog_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cgc_calibration_changelog_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cgc_calibration_changelog_id_seq OWNED BY public.cgc_calibration_changelog.id;


--
-- Name: cgc_error_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cgc_error_reports (
    fingerprint character varying(32) NOT NULL,
    app_source character varying(50) NOT NULL,
    environment character varying(20) DEFAULT 'production'::character varying,
    severity character varying(20) DEFAULT 'error'::character varying,
    message text NOT NULL,
    stack text,
    url text,
    user_agent text,
    context jsonb,
    count integer DEFAULT 1,
    resolved boolean DEFAULT false,
    first_seen timestamp with time zone DEFAULT now(),
    last_seen timestamp with time zone DEFAULT now()
);


--
-- Name: cgc_feedback; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cgc_feedback (
    id bigint NOT NULL,
    decision_id character varying(255),
    source_type character varying(20),
    feedback_type character varying(50),
    feedback_data jsonb,
    processed boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: cgc_feedback_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cgc_feedback_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cgc_feedback_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cgc_feedback_id_seq OWNED BY public.cgc_feedback.id;


--
-- Name: cgc_launch_checklist_items; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cgc_launch_checklist_items (
    id bigint NOT NULL,
    app_source character varying(50) NOT NULL,
    category character varying(100) NOT NULL,
    item text NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    note text,
    updated_by character varying(255),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: cgc_launch_checklist_items_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cgc_launch_checklist_items_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cgc_launch_checklist_items_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cgc_launch_checklist_items_id_seq OWNED BY public.cgc_launch_checklist_items.id;


--
-- Name: cgc_launch_errors; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cgc_launch_errors (
    id bigint NOT NULL,
    app_source character varying(50) NOT NULL,
    source character varying(50) NOT NULL,
    severity character varying(20) DEFAULT 'error'::character varying NOT NULL,
    message text NOT NULL,
    detail jsonb,
    status character varying(20) DEFAULT 'open'::character varying NOT NULL,
    resolved_by character varying(255),
    resolved_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: cgc_launch_errors_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cgc_launch_errors_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cgc_launch_errors_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cgc_launch_errors_id_seq OWNED BY public.cgc_launch_errors.id;


--
-- Name: cgc_launch_snapshot; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cgc_launch_snapshot (
    id bigint NOT NULL,
    app_source character varying(50) NOT NULL,
    source character varying(20) NOT NULL,
    payload jsonb NOT NULL,
    fetched_at timestamp with time zone DEFAULT now()
);


--
-- Name: cgc_launch_snapshot_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cgc_launch_snapshot_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cgc_launch_snapshot_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cgc_launch_snapshot_id_seq OWNED BY public.cgc_launch_snapshot.id;


--
-- Name: cgc_loop_decisions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cgc_loop_decisions (
    decision_id character varying(255) NOT NULL,
    prefilter_result jsonb,
    module_scores jsonb,
    final_outcome character varying(20),
    risk_level character varying(20),
    ethical_score double precision,
    policy_version character varying(50),
    signed_artifact_hash character varying(128),
    confidence double precision,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: cgc_module_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cgc_module_results (
    id bigint NOT NULL,
    decision_id character varying(255),
    module_name character varying(20),
    scores jsonb,
    approved boolean,
    latency_ms double precision,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: cgc_module_results_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cgc_module_results_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cgc_module_results_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cgc_module_results_id_seq OWNED BY public.cgc_module_results.id;


--
-- Name: cgc_prefilter_results; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cgc_prefilter_results (
    decision_id character varying(255) NOT NULL,
    correlation_id character varying(255),
    area character varying(50),
    outcome character varying(20),
    sensitive_count integer DEFAULT 0,
    agent_id character varying(255),
    metrics jsonb,
    latency_ms double precision,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: cgc_saml_connections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cgc_saml_connections (
    id bigint NOT NULL,
    domain character varying(255) NOT NULL,
    idp_entity_id text NOT NULL,
    idp_sso_url text NOT NULL,
    idp_x509_cert text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_by character varying(255),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: cgc_saml_connections_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cgc_saml_connections_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cgc_saml_connections_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cgc_saml_connections_id_seq OWNED BY public.cgc_saml_connections.id;


--
-- Name: cgc_tenant_webhooks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cgc_tenant_webhooks (
    id bigint NOT NULL,
    app_source character varying(50) NOT NULL,
    url text NOT NULL,
    secret text NOT NULL,
    active boolean DEFAULT true NOT NULL,
    created_by character varying(255),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    last_delivery_at timestamp with time zone,
    last_delivery_status text
);


--
-- Name: cgc_tenant_webhooks_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cgc_tenant_webhooks_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cgc_tenant_webhooks_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cgc_tenant_webhooks_id_seq OWNED BY public.cgc_tenant_webhooks.id;


--
-- Name: cgc_tenant_weighting_overrides; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cgc_tenant_weighting_overrides (
    id bigint NOT NULL,
    app_source character varying(50) NOT NULL,
    area character varying(50) NOT NULL,
    sensitivity_level character varying(20) NOT NULL,
    ecm_weight numeric(4,3) NOT NULL,
    pfm_weight numeric(4,3) NOT NULL,
    pan_weight numeric(4,3) NOT NULL,
    sda_weight numeric(4,3) NOT NULL,
    approval_threshold numeric(4,3) NOT NULL,
    critical_framework_enforcement boolean DEFAULT false NOT NULL,
    require_human_review boolean DEFAULT false NOT NULL,
    updated_by character varying(255),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);


--
-- Name: cgc_tenant_weighting_overrides_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cgc_tenant_weighting_overrides_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cgc_tenant_weighting_overrides_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cgc_tenant_weighting_overrides_id_seq OWNED BY public.cgc_tenant_weighting_overrides.id;


--
-- Name: cgc_webhook_retry_queue; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.cgc_webhook_retry_queue (
    id bigint NOT NULL,
    app_source character varying(50) NOT NULL,
    event character varying(100) NOT NULL,
    payload jsonb NOT NULL,
    attempts integer DEFAULT 0 NOT NULL,
    next_retry_at timestamp with time zone DEFAULT now() NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    last_error text,
    created_at timestamp with time zone DEFAULT now(),
    delivered_at timestamp with time zone
);


--
-- Name: cgc_webhook_retry_queue_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.cgc_webhook_retry_queue_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cgc_webhook_retry_queue_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.cgc_webhook_retry_queue_id_seq OWNED BY public.cgc_webhook_retry_queue.id;


--
-- Name: sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.sessions (
    token character varying(255) NOT NULL,
    email character varying(255) NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone
);


--
-- Name: tenants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenants (
    tenant_id character varying(255) NOT NULL,
    org_name character varying(255) NOT NULL,
    plan character varying(50) DEFAULT 'basic'::character varying,
    api_key character varying(255),
    status character varying(50) DEFAULT 'active'::character varying,
    created_at timestamp with time zone DEFAULT now()
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    name character varying(255),
    role character varying(50) DEFAULT 'user'::character varying,
    tenant_id character varying(255),
    created_at timestamp with time zone DEFAULT now(),
    last_login timestamp with time zone
);


--
-- Name: blocklist id; Type: DEFAULT; Schema: cgc_auth; Owner: -
--

ALTER TABLE ONLY cgc_auth.blocklist ALTER COLUMN id SET DEFAULT nextval('cgc_auth.blocklist_id_seq'::regclass);


--
-- Name: internal_flags id; Type: DEFAULT; Schema: cgc_guard; Owner: -
--

ALTER TABLE ONLY cgc_guard.internal_flags ALTER COLUMN id SET DEFAULT nextval('cgc_guard.internal_flags_id_seq'::regclass);


--
-- Name: login_attempts id; Type: DEFAULT; Schema: cgc_guard; Owner: -
--

ALTER TABLE ONLY cgc_guard.login_attempts ALTER COLUMN id SET DEFAULT nextval('cgc_guard.login_attempts_id_seq'::regclass);


--
-- Name: rate_limit_events id; Type: DEFAULT; Schema: cgc_guard; Owner: -
--

ALTER TABLE ONLY cgc_guard.rate_limit_events ALTER COLUMN id SET DEFAULT nextval('cgc_guard.rate_limit_events_id_seq'::regclass);


--
-- Name: suspicious_payloads id; Type: DEFAULT; Schema: cgc_guard; Owner: -
--

ALTER TABLE ONLY cgc_guard.suspicious_payloads ALTER COLUMN id SET DEFAULT nextval('cgc_guard.suspicious_payloads_id_seq'::regclass);


--
-- Name: tenant_usage id; Type: DEFAULT; Schema: cgc_guard; Owner: -
--

ALTER TABLE ONLY cgc_guard.tenant_usage ALTER COLUMN id SET DEFAULT nextval('cgc_guard.tenant_usage_id_seq'::regclass);


--
-- Name: ecm_calibration id; Type: DEFAULT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.ecm_calibration ALTER COLUMN id SET DEFAULT nextval('cgc_jla.ecm_calibration_id_seq'::regclass);


--
-- Name: pan_domain_patterns id; Type: DEFAULT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.pan_domain_patterns ALTER COLUMN id SET DEFAULT nextval('cgc_jla.pan_domain_patterns_id_seq'::regclass);


--
-- Name: pfm_risk_models id; Type: DEFAULT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.pfm_risk_models ALTER COLUMN id SET DEFAULT nextval('cgc_jla.pfm_risk_models_id_seq'::regclass);


--
-- Name: scm_compliance_standards id; Type: DEFAULT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.scm_compliance_standards ALTER COLUMN id SET DEFAULT nextval('cgc_jla.scm_compliance_standards_id_seq'::regclass);


--
-- Name: scm_security_policies id; Type: DEFAULT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.scm_security_policies ALTER COLUMN id SET DEFAULT nextval('cgc_jla.scm_security_policies_id_seq'::regclass);


--
-- Name: scm_sensitivity_config id; Type: DEFAULT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.scm_sensitivity_config ALTER COLUMN id SET DEFAULT nextval('cgc_jla.scm_sensitivity_config_id_seq'::regclass);


--
-- Name: sda_best_practices id; Type: DEFAULT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.sda_best_practices ALTER COLUMN id SET DEFAULT nextval('cgc_jla.sda_best_practices_id_seq'::regclass);


--
-- Name: tco_retention_policies id; Type: DEFAULT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.tco_retention_policies ALTER COLUMN id SET DEFAULT nextval('cgc_jla.tco_retention_policies_id_seq'::regclass);


--
-- Name: chain_integrity_log id; Type: DEFAULT; Schema: cgc_pod; Owner: -
--

ALTER TABLE ONLY cgc_pod.chain_integrity_log ALTER COLUMN id SET DEFAULT nextval('cgc_pod.chain_integrity_log_id_seq'::regclass);


--
-- Name: pod_ledger block_id; Type: DEFAULT; Schema: cgc_pod; Owner: -
--

ALTER TABLE ONLY cgc_pod.pod_ledger ALTER COLUMN block_id SET DEFAULT nextval('cgc_pod.pod_ledger_block_id_seq'::regclass);


--
-- Name: audit_trail id; Type: DEFAULT; Schema: cgc_tco; Owner: -
--

ALTER TABLE ONLY cgc_tco.audit_trail ALTER COLUMN id SET DEFAULT nextval('cgc_tco.audit_trail_id_seq'::regclass);


--
-- Name: chain_integrity_log id; Type: DEFAULT; Schema: cgc_tco; Owner: -
--

ALTER TABLE ONLY cgc_tco.chain_integrity_log ALTER COLUMN id SET DEFAULT nextval('cgc_tco.chain_integrity_log_id_seq'::regclass);


--
-- Name: cgc_audit_traces id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_audit_traces ALTER COLUMN id SET DEFAULT nextval('public.cgc_audit_traces_id_seq'::regclass);


--
-- Name: cgc_calibration_changelog id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_calibration_changelog ALTER COLUMN id SET DEFAULT nextval('public.cgc_calibration_changelog_id_seq'::regclass);


--
-- Name: cgc_feedback id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_feedback ALTER COLUMN id SET DEFAULT nextval('public.cgc_feedback_id_seq'::regclass);


--
-- Name: cgc_launch_checklist_items id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_launch_checklist_items ALTER COLUMN id SET DEFAULT nextval('public.cgc_launch_checklist_items_id_seq'::regclass);


--
-- Name: cgc_launch_errors id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_launch_errors ALTER COLUMN id SET DEFAULT nextval('public.cgc_launch_errors_id_seq'::regclass);


--
-- Name: cgc_launch_snapshot id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_launch_snapshot ALTER COLUMN id SET DEFAULT nextval('public.cgc_launch_snapshot_id_seq'::regclass);


--
-- Name: cgc_module_results id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_module_results ALTER COLUMN id SET DEFAULT nextval('public.cgc_module_results_id_seq'::regclass);


--
-- Name: cgc_saml_connections id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_saml_connections ALTER COLUMN id SET DEFAULT nextval('public.cgc_saml_connections_id_seq'::regclass);


--
-- Name: cgc_tenant_webhooks id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_tenant_webhooks ALTER COLUMN id SET DEFAULT nextval('public.cgc_tenant_webhooks_id_seq'::regclass);


--
-- Name: cgc_tenant_weighting_overrides id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_tenant_weighting_overrides ALTER COLUMN id SET DEFAULT nextval('public.cgc_tenant_weighting_overrides_id_seq'::regclass);


--
-- Name: cgc_webhook_retry_queue id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_webhook_retry_queue ALTER COLUMN id SET DEFAULT nextval('public.cgc_webhook_retry_queue_id_seq'::regclass);


--
-- Name: api_keys api_keys_key_hash_key; Type: CONSTRAINT; Schema: cgc_auth; Owner: -
--

ALTER TABLE ONLY cgc_auth.api_keys
    ADD CONSTRAINT api_keys_key_hash_key UNIQUE (key_hash);


--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: cgc_auth; Owner: -
--

ALTER TABLE ONLY cgc_auth.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);


--
-- Name: blocklist blocklist_pkey; Type: CONSTRAINT; Schema: cgc_auth; Owner: -
--

ALTER TABLE ONLY cgc_auth.blocklist
    ADD CONSTRAINT blocklist_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: cgc_auth; Owner: -
--

ALTER TABLE ONLY cgc_auth.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (token);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: cgc_auth; Owner: -
--

ALTER TABLE ONLY cgc_auth.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (email);


--
-- Name: internal_flags internal_flags_pkey; Type: CONSTRAINT; Schema: cgc_guard; Owner: -
--

ALTER TABLE ONLY cgc_guard.internal_flags
    ADD CONSTRAINT internal_flags_pkey PRIMARY KEY (id);


--
-- Name: login_attempts login_attempts_pkey; Type: CONSTRAINT; Schema: cgc_guard; Owner: -
--

ALTER TABLE ONLY cgc_guard.login_attempts
    ADD CONSTRAINT login_attempts_pkey PRIMARY KEY (id);


--
-- Name: rate_limit_events rate_limit_events_pkey; Type: CONSTRAINT; Schema: cgc_guard; Owner: -
--

ALTER TABLE ONLY cgc_guard.rate_limit_events
    ADD CONSTRAINT rate_limit_events_pkey PRIMARY KEY (id);


--
-- Name: suspicious_payloads suspicious_payloads_pkey; Type: CONSTRAINT; Schema: cgc_guard; Owner: -
--

ALTER TABLE ONLY cgc_guard.suspicious_payloads
    ADD CONSTRAINT suspicious_payloads_pkey PRIMARY KEY (id);


--
-- Name: tenant_plans tenant_plans_pkey; Type: CONSTRAINT; Schema: cgc_guard; Owner: -
--

ALTER TABLE ONLY cgc_guard.tenant_plans
    ADD CONSTRAINT tenant_plans_pkey PRIMARY KEY (org_id);


--
-- Name: tenant_usage tenant_usage_org_id_resource_period_key; Type: CONSTRAINT; Schema: cgc_guard; Owner: -
--

ALTER TABLE ONLY cgc_guard.tenant_usage
    ADD CONSTRAINT tenant_usage_org_id_resource_period_key UNIQUE (org_id, resource, period);


--
-- Name: tenant_usage tenant_usage_pkey; Type: CONSTRAINT; Schema: cgc_guard; Owner: -
--

ALTER TABLE ONLY cgc_guard.tenant_usage
    ADD CONSTRAINT tenant_usage_pkey PRIMARY KEY (id);


--
-- Name: ecm_calibration ecm_calibration_governance_area_key; Type: CONSTRAINT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.ecm_calibration
    ADD CONSTRAINT ecm_calibration_governance_area_key UNIQUE (governance_area);


--
-- Name: ecm_calibration ecm_calibration_pkey; Type: CONSTRAINT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.ecm_calibration
    ADD CONSTRAINT ecm_calibration_pkey PRIMARY KEY (id);


--
-- Name: pan_domain_patterns pan_domain_patterns_governance_area_key; Type: CONSTRAINT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.pan_domain_patterns
    ADD CONSTRAINT pan_domain_patterns_governance_area_key UNIQUE (governance_area);


--
-- Name: pan_domain_patterns pan_domain_patterns_pkey; Type: CONSTRAINT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.pan_domain_patterns
    ADD CONSTRAINT pan_domain_patterns_pkey PRIMARY KEY (id);


--
-- Name: pfm_risk_models pfm_risk_models_governance_area_action_type_key; Type: CONSTRAINT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.pfm_risk_models
    ADD CONSTRAINT pfm_risk_models_governance_area_action_type_key UNIQUE (governance_area, action_type);


--
-- Name: pfm_risk_models pfm_risk_models_pkey; Type: CONSTRAINT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.pfm_risk_models
    ADD CONSTRAINT pfm_risk_models_pkey PRIMARY KEY (id);


--
-- Name: scm_compliance_standards scm_compliance_standards_pkey; Type: CONSTRAINT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.scm_compliance_standards
    ADD CONSTRAINT scm_compliance_standards_pkey PRIMARY KEY (id);


--
-- Name: scm_compliance_standards scm_compliance_standards_standard_key; Type: CONSTRAINT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.scm_compliance_standards
    ADD CONSTRAINT scm_compliance_standards_standard_key UNIQUE (standard);


--
-- Name: scm_security_policies scm_security_policies_governance_area_key; Type: CONSTRAINT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.scm_security_policies
    ADD CONSTRAINT scm_security_policies_governance_area_key UNIQUE (governance_area);


--
-- Name: scm_security_policies scm_security_policies_pkey; Type: CONSTRAINT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.scm_security_policies
    ADD CONSTRAINT scm_security_policies_pkey PRIMARY KEY (id);


--
-- Name: scm_sensitivity_config scm_sensitivity_config_pkey; Type: CONSTRAINT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.scm_sensitivity_config
    ADD CONSTRAINT scm_sensitivity_config_pkey PRIMARY KEY (id);


--
-- Name: scm_sensitivity_config scm_sensitivity_config_sensitivity_level_key; Type: CONSTRAINT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.scm_sensitivity_config
    ADD CONSTRAINT scm_sensitivity_config_sensitivity_level_key UNIQUE (sensitivity_level);


--
-- Name: sda_best_practices sda_best_practices_governance_area_key; Type: CONSTRAINT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.sda_best_practices
    ADD CONSTRAINT sda_best_practices_governance_area_key UNIQUE (governance_area);


--
-- Name: sda_best_practices sda_best_practices_pkey; Type: CONSTRAINT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.sda_best_practices
    ADD CONSTRAINT sda_best_practices_pkey PRIMARY KEY (id);


--
-- Name: tco_retention_policies tco_retention_policies_governance_area_key; Type: CONSTRAINT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.tco_retention_policies
    ADD CONSTRAINT tco_retention_policies_governance_area_key UNIQUE (governance_area);


--
-- Name: tco_retention_policies tco_retention_policies_pkey; Type: CONSTRAINT; Schema: cgc_jla; Owner: -
--

ALTER TABLE ONLY cgc_jla.tco_retention_policies
    ADD CONSTRAINT tco_retention_policies_pkey PRIMARY KEY (id);


--
-- Name: chain_integrity_log chain_integrity_log_pkey; Type: CONSTRAINT; Schema: cgc_pod; Owner: -
--

ALTER TABLE ONLY cgc_pod.chain_integrity_log
    ADD CONSTRAINT chain_integrity_log_pkey PRIMARY KEY (id);


--
-- Name: inference_intercepts inference_intercepts_pkey; Type: CONSTRAINT; Schema: cgc_pod; Owner: -
--

ALTER TABLE ONLY cgc_pod.inference_intercepts
    ADD CONSTRAINT inference_intercepts_pkey PRIMARY KEY (intercept_id);


--
-- Name: pod_ledger pod_ledger_block_hash_key; Type: CONSTRAINT; Schema: cgc_pod; Owner: -
--

ALTER TABLE ONLY cgc_pod.pod_ledger
    ADD CONSTRAINT pod_ledger_block_hash_key UNIQUE (block_hash);


--
-- Name: pod_ledger pod_ledger_block_uuid_key; Type: CONSTRAINT; Schema: cgc_pod; Owner: -
--

ALTER TABLE ONLY cgc_pod.pod_ledger
    ADD CONSTRAINT pod_ledger_block_uuid_key UNIQUE (block_uuid);


--
-- Name: pod_ledger pod_ledger_pkey; Type: CONSTRAINT; Schema: cgc_pod; Owner: -
--

ALTER TABLE ONLY cgc_pod.pod_ledger
    ADD CONSTRAINT pod_ledger_pkey PRIMARY KEY (block_id);


--
-- Name: pod_ledger ux_pod_ledger_tenant_block; Type: CONSTRAINT; Schema: cgc_pod; Owner: -
--

ALTER TABLE ONLY cgc_pod.pod_ledger
    ADD CONSTRAINT ux_pod_ledger_tenant_block UNIQUE (tenant_id, block_number);


--
-- Name: audit_trail audit_trail_block_hash_key; Type: CONSTRAINT; Schema: cgc_tco; Owner: -
--

ALTER TABLE ONLY cgc_tco.audit_trail
    ADD CONSTRAINT audit_trail_block_hash_key UNIQUE (block_hash);


--
-- Name: audit_trail audit_trail_block_number_key; Type: CONSTRAINT; Schema: cgc_tco; Owner: -
--

ALTER TABLE ONLY cgc_tco.audit_trail
    ADD CONSTRAINT audit_trail_block_number_key UNIQUE (block_number);


--
-- Name: audit_trail audit_trail_pkey; Type: CONSTRAINT; Schema: cgc_tco; Owner: -
--

ALTER TABLE ONLY cgc_tco.audit_trail
    ADD CONSTRAINT audit_trail_pkey PRIMARY KEY (id);


--
-- Name: chain_integrity_log chain_integrity_log_pkey; Type: CONSTRAINT; Schema: cgc_tco; Owner: -
--

ALTER TABLE ONLY cgc_tco.chain_integrity_log
    ADD CONSTRAINT chain_integrity_log_pkey PRIMARY KEY (id);


--
-- Name: cgc_audit_traces cgc_audit_traces_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_audit_traces
    ADD CONSTRAINT cgc_audit_traces_pkey PRIMARY KEY (id);


--
-- Name: cgc_calibration_changelog cgc_calibration_changelog_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_calibration_changelog
    ADD CONSTRAINT cgc_calibration_changelog_pkey PRIMARY KEY (id);


--
-- Name: cgc_error_reports cgc_error_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_error_reports
    ADD CONSTRAINT cgc_error_reports_pkey PRIMARY KEY (fingerprint);


--
-- Name: cgc_feedback cgc_feedback_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_feedback
    ADD CONSTRAINT cgc_feedback_pkey PRIMARY KEY (id);


--
-- Name: cgc_launch_checklist_items cgc_launch_checklist_items_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_launch_checklist_items
    ADD CONSTRAINT cgc_launch_checklist_items_pkey PRIMARY KEY (id);


--
-- Name: cgc_launch_errors cgc_launch_errors_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_launch_errors
    ADD CONSTRAINT cgc_launch_errors_pkey PRIMARY KEY (id);


--
-- Name: cgc_launch_snapshot cgc_launch_snapshot_app_source_source_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_launch_snapshot
    ADD CONSTRAINT cgc_launch_snapshot_app_source_source_key UNIQUE (app_source, source);


--
-- Name: cgc_launch_snapshot cgc_launch_snapshot_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_launch_snapshot
    ADD CONSTRAINT cgc_launch_snapshot_pkey PRIMARY KEY (id);


--
-- Name: cgc_loop_decisions cgc_loop_decisions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_loop_decisions
    ADD CONSTRAINT cgc_loop_decisions_pkey PRIMARY KEY (decision_id);


--
-- Name: cgc_module_results cgc_module_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_module_results
    ADD CONSTRAINT cgc_module_results_pkey PRIMARY KEY (id);


--
-- Name: cgc_prefilter_results cgc_prefilter_results_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_prefilter_results
    ADD CONSTRAINT cgc_prefilter_results_pkey PRIMARY KEY (decision_id);


--
-- Name: cgc_saml_connections cgc_saml_connections_domain_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_saml_connections
    ADD CONSTRAINT cgc_saml_connections_domain_key UNIQUE (domain);


--
-- Name: cgc_saml_connections cgc_saml_connections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_saml_connections
    ADD CONSTRAINT cgc_saml_connections_pkey PRIMARY KEY (id);


--
-- Name: cgc_tenant_webhooks cgc_tenant_webhooks_app_source_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_tenant_webhooks
    ADD CONSTRAINT cgc_tenant_webhooks_app_source_key UNIQUE (app_source);


--
-- Name: cgc_tenant_webhooks cgc_tenant_webhooks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_tenant_webhooks
    ADD CONSTRAINT cgc_tenant_webhooks_pkey PRIMARY KEY (id);


--
-- Name: cgc_tenant_weighting_overrides cgc_tenant_weighting_override_app_source_area_sensitivity_l_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_tenant_weighting_overrides
    ADD CONSTRAINT cgc_tenant_weighting_override_app_source_area_sensitivity_l_key UNIQUE (app_source, area, sensitivity_level);


--
-- Name: cgc_tenant_weighting_overrides cgc_tenant_weighting_overrides_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_tenant_weighting_overrides
    ADD CONSTRAINT cgc_tenant_weighting_overrides_pkey PRIMARY KEY (id);


--
-- Name: cgc_webhook_retry_queue cgc_webhook_retry_queue_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_webhook_retry_queue
    ADD CONSTRAINT cgc_webhook_retry_queue_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (token);


--
-- Name: tenants tenants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (tenant_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (email);


--
-- Name: idx_api_keys_app_source; Type: INDEX; Schema: cgc_auth; Owner: -
--

CREATE INDEX idx_api_keys_app_source ON cgc_auth.api_keys USING btree (app_source);


--
-- Name: idx_api_keys_hash_active; Type: INDEX; Schema: cgc_auth; Owner: -
--

CREATE INDEX idx_api_keys_hash_active ON cgc_auth.api_keys USING btree (key_hash) WHERE (revoked_at IS NULL);


--
-- Name: idx_auth_blocklist_email; Type: INDEX; Schema: cgc_auth; Owner: -
--

CREATE INDEX idx_auth_blocklist_email ON cgc_auth.blocklist USING btree (email);


--
-- Name: idx_auth_blocklist_ip; Type: INDEX; Schema: cgc_auth; Owner: -
--

CREATE INDEX idx_auth_blocklist_ip ON cgc_auth.blocklist USING btree (ip);


--
-- Name: idx_auth_sessions_email; Type: INDEX; Schema: cgc_auth; Owner: -
--

CREATE INDEX idx_auth_sessions_email ON cgc_auth.sessions USING btree (email);


--
-- Name: idx_guard_internal_flags_type; Type: INDEX; Schema: cgc_guard; Owner: -
--

CREATE INDEX idx_guard_internal_flags_type ON cgc_guard.internal_flags USING btree (flag_type);


--
-- Name: idx_guard_login_ip_created; Type: INDEX; Schema: cgc_guard; Owner: -
--

CREATE INDEX idx_guard_login_ip_created ON cgc_guard.login_attempts USING btree (ip, created_at);


--
-- Name: idx_guard_rate_key_created; Type: INDEX; Schema: cgc_guard; Owner: -
--

CREATE INDEX idx_guard_rate_key_created ON cgc_guard.rate_limit_events USING btree (key, created_at);


--
-- Name: idx_guard_tenant_usage_lookup; Type: INDEX; Schema: cgc_guard; Owner: -
--

CREATE INDEX idx_guard_tenant_usage_lookup ON cgc_guard.tenant_usage USING btree (org_id, resource, period);


--
-- Name: idx_intercepts_decision; Type: INDEX; Schema: cgc_pod; Owner: -
--

CREATE INDEX idx_intercepts_decision ON cgc_pod.inference_intercepts USING btree (decision_id, tenant_id);


--
-- Name: idx_ledger_tenant_block; Type: INDEX; Schema: cgc_pod; Owner: -
--

CREATE INDEX idx_ledger_tenant_block ON cgc_pod.pod_ledger USING btree (tenant_id, block_number);


--
-- Name: idx_tco_app_source; Type: INDEX; Schema: cgc_tco; Owner: -
--

CREATE INDEX idx_tco_app_source ON cgc_tco.audit_trail USING btree (app_source);


--
-- Name: idx_tco_area; Type: INDEX; Schema: cgc_tco; Owner: -
--

CREATE INDEX idx_tco_area ON cgc_tco.audit_trail USING btree (area);


--
-- Name: idx_tco_block_hash; Type: INDEX; Schema: cgc_tco; Owner: -
--

CREATE INDEX idx_tco_block_hash ON cgc_tco.audit_trail USING btree (block_hash);


--
-- Name: idx_tco_block_number; Type: INDEX; Schema: cgc_tco; Owner: -
--

CREATE INDEX idx_tco_block_number ON cgc_tco.audit_trail USING btree (block_number);


--
-- Name: idx_tco_decision_id; Type: INDEX; Schema: cgc_tco; Owner: -
--

CREATE INDEX idx_tco_decision_id ON cgc_tco.audit_trail USING btree (decision_id);


--
-- Name: idx_tco_integrity_block; Type: INDEX; Schema: cgc_tco; Owner: -
--

CREATE INDEX idx_tco_integrity_block ON cgc_tco.chain_integrity_log USING btree (block_number);


--
-- Name: idx_tco_tamper_detected; Type: INDEX; Schema: cgc_tco; Owner: -
--

CREATE INDEX idx_tco_tamper_detected ON cgc_tco.chain_integrity_log USING btree (tamper_detected);


--
-- Name: idx_tco_tenant_id; Type: INDEX; Schema: cgc_tco; Owner: -
--

CREATE INDEX idx_tco_tenant_id ON cgc_tco.audit_trail USING btree (tenant_id);


--
-- Name: idx_tco_timestamp; Type: INDEX; Schema: cgc_tco; Owner: -
--

CREATE INDEX idx_tco_timestamp ON cgc_tco.audit_trail USING btree ("timestamp");


--
-- Name: idx_calibration_changelog_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_calibration_changelog_lookup ON public.cgc_calibration_changelog USING btree (module, governance_area);


--
-- Name: idx_launch_checklist_app_source; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_launch_checklist_app_source ON public.cgc_launch_checklist_items USING btree (app_source);


--
-- Name: idx_launch_errors_app_source_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_launch_errors_app_source_status ON public.cgc_launch_errors USING btree (app_source, status);


--
-- Name: idx_webhook_retry_queue_due; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_retry_queue_due ON public.cgc_webhook_retry_queue USING btree (status, next_retry_at);


--
-- Name: pod_ledger pod_ledger_append_only; Type: TRIGGER; Schema: cgc_pod; Owner: -
--

CREATE TRIGGER pod_ledger_append_only BEFORE DELETE OR UPDATE ON cgc_pod.pod_ledger FOR EACH ROW EXECUTE FUNCTION cgc_pod.prevent_ledger_mutation();


--
-- Name: cgc_audit_traces cgc_audit_traces_decision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_audit_traces
    ADD CONSTRAINT cgc_audit_traces_decision_id_fkey FOREIGN KEY (decision_id) REFERENCES public.cgc_prefilter_results(decision_id);


--
-- Name: cgc_module_results cgc_module_results_decision_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.cgc_module_results
    ADD CONSTRAINT cgc_module_results_decision_id_fkey FOREIGN KEY (decision_id) REFERENCES public.cgc_prefilter_results(decision_id);


--
-- Name: sessions sessions_email_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_email_fkey FOREIGN KEY (email) REFERENCES public.users(email);


--
-- PostgreSQL database dump complete
--

