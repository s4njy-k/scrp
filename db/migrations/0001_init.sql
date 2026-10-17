-- Cybercrime web collection — authoritative job ledger (blueprint §12).
-- PostgreSQL is the only scheduler of record. Applied by `node dist/cli.js migrate`.

CREATE TYPE processing_state AS ENUM (
  'QUEUED', 'LEASED', 'CAPTURING', 'FINALISING',
  'COMPLETE', 'PARTIAL', 'DEFERRED', 'MANUAL_REVIEW', 'FAILED_FINAL'
);

CREATE TYPE acquisition_outcome AS ENUM (
  'CONTENT_CAPTURED', 'CONTENT_INCOMPLETE', 'CHALLENGE_PAGE_CAPTURED', 'ACCESS_BLOCKED',
  'AUTH_REQUIRED', 'DNS_FAILURE', 'TLS_FAILURE', 'NOT_FOUND', 'ORIGIN_UNAVAILABLE',
  'INFRASTRUCTURE_DEFERRED'
);

-- Which acquisition stage a job is waiting for. Workers lease only their own stage.
CREATE TYPE job_stage AS ENUM ('http', 'browser_primary', 'browser_alternate', 'scrapling', 'done');

-- Monotonic fencing tokens for every lease (§12).
CREATE SEQUENCE lease_token_seq AS bigint;

CREATE TABLE capture_profiles (
  name                text PRIMARY KEY,
  description         text NOT NULL,
  required_artifacts  text[] NOT NULL,
  browser_evidence    boolean NOT NULL,
  settings            jsonb NOT NULL DEFAULT '{}'::jsonb
);

INSERT INTO capture_profiles (name, description, required_artifacts, browser_evidence) VALUES
  ('data_triage',
   'Recorded HTTP outcome, headers/body where received, links and identifiers. Never browser evidence.',
   ARRAY['http_response_record'], false),
  ('browser_evidence',
   'Screenshots, rendered DOM/text, observed network metadata, manifest and artifact-status records.',
   ARRAY['screenshot_viewport', 'rendered_dom', 'rendered_text', 'network_events', 'har', 'manifest'], true);

CREATE TABLE import_batches (
  id            bigserial PRIMARY KEY,
  filename      text NOT NULL,
  file_sha256   text NOT NULL,
  format        text NOT NULL CHECK (format IN ('csv', 'jsonl')),
  default_profile text NOT NULL REFERENCES capture_profiles(name),
  imported_by   text NOT NULL,
  counts        jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at    timestamptz NOT NULL DEFAULT now()
);

-- One row per distinct acquisition location. Original input is preserved verbatim on
-- source_records; the parsed/normalised representations live here (§6).
CREATE TABLE targets (
  id                  bigserial PRIMARY KEY,
  input_kind          text NOT NULL CHECK (input_kind IN ('url', 'domain', 'subdomain', 'ip')),
  candidate_of_input  text,             -- set for scheme candidates generated from a domain-only seed
  candidate_scheme    text,
  url                 text NOT NULL,    -- exact URL to visit; fragment and query order preserved
  scheme              text NOT NULL,
  hostname_ascii      text NOT NULL,
  hostname_unicode    text NOT NULL,
  port                integer,
  path_and_query      text NOT NULL,
  fragment            text,             -- client-side route selector; never sent over HTTP
  registrable_domain  text NOT NULL,    -- Public Suffix List aware grouping key
  is_ip_literal       boolean NOT NULL DEFAULT false,
  nonstandard_port    boolean NOT NULL DEFAULT false,
  dedup_key           text NOT NULL UNIQUE,
  created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX targets_registrable_domain_idx ON targets (registrable_domain);

CREATE TABLE source_records (
  id               bigserial PRIMARY KEY,
  import_batch_id  bigint NOT NULL REFERENCES import_batches(id),
  line_number      integer NOT NULL,
  original_input   text NOT NULL,
  source_ref       text,
  case_ref         text,
  priority         integer NOT NULL DEFAULT 0,
  raw_record       jsonb NOT NULL,
  rejected         boolean NOT NULL DEFAULT false,
  rejection_reason text,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX source_records_case_ref_idx ON source_records (case_ref);

CREATE TABLE source_record_targets (
  source_record_id bigint NOT NULL REFERENCES source_records(id),
  target_id        bigint NOT NULL REFERENCES targets(id),
  PRIMARY KEY (source_record_id, target_id)
);

CREATE TABLE jobs (
  id                    bigserial PRIMARY KEY,
  target_id             bigint NOT NULL REFERENCES targets(id),
  parent_job_id         bigint REFERENCES jobs(id),
  profile               text NOT NULL REFERENCES capture_profiles(name),
  window_key            text NOT NULL,           -- target/profile/window deduplication
  registrable_domain    text NOT NULL,           -- denormalised for per-domain admission
  priority              integer NOT NULL DEFAULT 0,
  urgent                boolean NOT NULL DEFAULT false,
  required_artifacts    text[] NOT NULL,
  capture_variant       text NOT NULL DEFAULT 'desktop',
  scope                 jsonb NOT NULL DEFAULT '{}'::jsonb,
  allowed_interactions  text[] NOT NULL DEFAULT ARRAY['scroll']::text[],
  retention_class       text NOT NULL,
  case_ref              text,
  deadline              timestamptz,

  state                 processing_state NOT NULL DEFAULT 'QUEUED',
  stage                 job_stage NOT NULL,
  outcome               acquisition_outcome,
  outcome_reason        text,
  classification        text,

  -- Coordinator-owned budget shared by all adapters (§8).
  http_attempts         integer NOT NULL DEFAULT 0,
  browser_attempts      integer NOT NULL DEFAULT 0,
  active_seconds_used   double precision NOT NULL DEFAULT 0,
  alternate_used        boolean NOT NULL DEFAULT false,

  next_eligible_at      timestamptz NOT NULL DEFAULT now(),
  lease_owner           text,
  lease_token           bigint,
  lease_expires_at      timestamptz,
  heartbeat_at          timestamptz,
  current_attempt_id    uuid,

  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  finished_at           timestamptz,

  CONSTRAINT jobs_budget_nonnegative CHECK (http_attempts >= 0 AND browser_attempts >= 0 AND active_seconds_used >= 0),
  CONSTRAINT jobs_lease_consistent CHECK (
    (state IN ('LEASED', 'CAPTURING', 'FINALISING')) = (lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
  )
);
-- Conservative deduplication: one top-level job per target/profile/variant/window.
CREATE UNIQUE INDEX jobs_dedup_idx ON jobs (target_id, profile, capture_variant, window_key) WHERE parent_job_id IS NULL;
CREATE INDEX jobs_due_idx ON jobs (stage, priority DESC, next_eligible_at) WHERE state IN ('QUEUED', 'DEFERRED');
CREATE INDEX jobs_active_domain_idx ON jobs (registrable_domain) WHERE state IN ('LEASED', 'CAPTURING', 'FINALISING');
CREATE INDEX jobs_lease_expiry_idx ON jobs (lease_expires_at) WHERE state IN ('LEASED', 'CAPTURING', 'FINALISING');
CREATE INDEX jobs_parent_idx ON jobs (parent_job_id);

-- Seed provenance survives acquisition deduplication (§6).
CREATE TABLE job_sources (
  job_id           bigint NOT NULL REFERENCES jobs(id),
  source_record_id bigint NOT NULL REFERENCES source_records(id),
  PRIMARY KEY (job_id, source_record_id)
);

-- Consistent identity within one target session (§8). Never shared between targets.
CREATE TABLE sessions (
  id              uuid PRIMARY KEY,
  target_id       bigint NOT NULL REFERENCES targets(id),
  job_id          bigint NOT NULL REFERENCES jobs(id),
  engine          text NOT NULL,
  vantage         text NOT NULL,
  user_agent      text,
  locale          text,
  timezone        text,
  viewport        jsonb,
  storage_state_artifact text,   -- restricted artifact path; cookies never go to general logs
  created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE attempts (
  id                uuid PRIMARY KEY,
  job_id            bigint NOT NULL REFERENCES jobs(id),
  attempt_no        integer NOT NULL,
  kind              text NOT NULL CHECK (kind IN ('http', 'browser')),
  engine            text NOT NULL,
  adapter           text NOT NULL,
  capture_variant   text NOT NULL DEFAULT 'desktop',
  vantage           text NOT NULL,
  session_id        uuid REFERENCES sessions(id),
  lease_token       bigint NOT NULL,
  worker_id         text NOT NULL,
  status            text NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending', 'committed', 'committed_lease_lost', 'interrupted', 'recovered')),
  outcome           acquisition_outcome,
  classification    text,
  error             text,
  started_at        timestamptz NOT NULL DEFAULT now(),
  ended_at          timestamptz,
  active_seconds    double precision,
  artifact_dir      text,             -- relative to ARTIFACT_ROOT; never derived from URL text
  manifest_sha256   text,
  total_bytes       bigint,
  required_satisfied boolean,
  missing_required  text[],
  engine_version    text,
  user_agent        text,
  settings          jsonb NOT NULL DEFAULT '{}'::jsonb,
  extraction_state  text NOT NULL DEFAULT 'pending'
                     CHECK (extraction_state IN ('pending', 'running', 'done', 'failed', 'not_applicable')),
  retention_class   text NOT NULL,
  expires_at        timestamptz,
  deleted_at        timestamptz,
  UNIQUE (job_id, attempt_no)
);
CREATE INDEX attempts_status_idx ON attempts (status);
CREATE INDEX attempts_extraction_idx ON attempts (extraction_state) WHERE extraction_state IN ('pending', 'running');

-- Global browser permits cover every engine and manual sessions combined (§5).
CREATE TABLE global_permits (
  slot            integer PRIMARY KEY,
  holder_job_id   bigint REFERENCES jobs(id),
  holder_owner    text,
  lease_token     bigint,
  adapter         text,
  acquired_at     timestamptz,
  expires_at      timestamptz
);

-- Per-registrable-domain pacing (top-level concurrency and delay).
CREATE TABLE domain_pacing (
  registrable_domain text PRIMARY KEY,
  next_allowed_at    timestamptz NOT NULL DEFAULT now(),
  last_status        integer,
  backoff_level      integer NOT NULL DEFAULT 0,
  updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE artifacts (
  id                bigserial PRIMARY KEY,
  attempt_id        uuid NOT NULL REFERENCES attempts(id),
  artifact_type     text NOT NULL,
  relative_path     text,               -- NULL when the artifact failed; never invented
  size_bytes        bigint,
  sha256            text,
  observed_start    timestamptz,
  observed_end      timestamptz,
  creation_method   text NOT NULL,
  completeness      text NOT NULL CHECK (completeness IN ('complete', 'partial', 'truncated', 'failed', 'omitted')),
  limitations       text[] NOT NULL DEFAULT ARRAY[]::text[],
  restricted        boolean NOT NULL DEFAULT false,
  derived_from      bigint REFERENCES artifacts(id),
  is_derivative     boolean NOT NULL DEFAULT false,
  error             text,
  metadata          jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX artifacts_attempt_idx ON artifacts (attempt_id);
CREATE INDEX artifacts_sha_idx ON artifacts (sha256);

CREATE TABLE identifiers (
  id                bigserial PRIMARY KEY,
  attempt_id        uuid NOT NULL REFERENCES attempts(id),
  job_id            bigint NOT NULL REFERENCES jobs(id),
  target_id         bigint NOT NULL REFERENCES targets(id),
  field_type        text NOT NULL,
  raw_value         text NOT NULL,
  normalised_value  text,
  method            text NOT NULL CHECK (method IN ('dom', 'attribute', 'json', 'http_body', 'network', 'qr', 'ocr', 'adaptive', 'ai')),
  source_url        text,
  frame_url         text,
  locator           text,
  bbox              jsonb,
  context           text,
  artifact_sha256   text,
  validation_state  text NOT NULL CHECK (validation_state IN ('format_valid', 'format_invalid', 'uncertain', 'unvalidated')),
  display_context   text NOT NULL DEFAULT 'unknown' CHECK (display_context IN ('displayed', 'resource_string', 'unknown')),
  adaptive          jsonb,
  observed_at       timestamptz,
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX identifiers_value_idx ON identifiers (field_type, normalised_value);

-- observed / not_observed / extraction_failed are distinct states (§11).
CREATE TABLE identifier_field_status (
  attempt_id   uuid NOT NULL REFERENCES attempts(id),
  field_type   text NOT NULL,
  status       text NOT NULL CHECK (status IN ('observed', 'not_observed', 'extraction_failed', 'not_applicable')),
  detail       text,
  PRIMARY KEY (attempt_id, field_type)
);

CREATE TABLE domain_edges (
  id           bigserial PRIMARY KEY,
  attempt_id   uuid NOT NULL REFERENCES attempts(id),
  edge_type    text NOT NULL CHECK (edge_type IN (
                 'redirect', 'meta_refresh', 'js_navigation', 'subresource', 'frame', 'popup',
                 'websocket', 'service_worker', 'form_action', 'link_discovered')),
  from_url     text,
  to_url       text NOT NULL,
  from_host    text,
  to_host      text,
  contacted    boolean NOT NULL,   -- discovered links are NOT contacted
  observed_at  timestamptz
);
CREATE INDEX domain_edges_attempt_idx ON domain_edges (attempt_id);
CREATE INDEX domain_edges_to_host_idx ON domain_edges (to_host);

-- Acquisition completeness, extraction quality and fraud assessment are separate (§11).
CREATE TABLE findings (
  id             bigserial PRIMARY KEY,
  job_id         bigint NOT NULL REFERENCES jobs(id),
  target_id      bigint NOT NULL REFERENCES targets(id),
  assessment     text NOT NULL CHECK (assessment IN ('suspected_fraud', 'not_suspected', 'unknown', 'inconclusive')),
  rationale      text NOT NULL,
  evidence_refs  jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_by     text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE case_holds (
  case_ref     text PRIMARY KEY,
  reason       text NOT NULL,
  placed_by    text NOT NULL,
  placed_at    timestamptz NOT NULL DEFAULT now(),
  released_by  text,
  released_at  timestamptz
);

CREATE TABLE audit_events (
  id          bigserial PRIMARY KEY,
  at          timestamptz NOT NULL DEFAULT now(),
  actor       text NOT NULL,
  event_type  text NOT NULL,
  job_id      bigint,
  attempt_id  uuid,
  details     jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_events_job_idx ON audit_events (job_id);
CREATE INDEX audit_events_type_at_idx ON audit_events (event_type, at);

CREATE TABLE exports (
  id           bigserial PRIMARY KEY,
  export_date  date NOT NULL,
  format       text NOT NULL CHECK (format IN ('jsonl', 'csv')),
  relative_path text NOT NULL,
  sha256       text NOT NULL,
  row_count    integer NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now()
);

-- Admission control flags and heartbeat facts (disk pause, gateway health, backups).
CREATE TABLE system_state (
  key        text PRIMARY KEY,
  value      jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO system_state (key, value) VALUES
  ('admission', '{"paused": false, "low_priority_paused": false, "reasons": []}'::jsonb);

CREATE TABLE worker_heartbeats (
  worker_id    text PRIMARY KEY,
  role         text NOT NULL,
  started_at   timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  details      jsonb NOT NULL DEFAULT '{}'::jsonb
);
