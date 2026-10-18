-- Analyst access, sessions, cases and case-level authorisation
-- (blueprint v4 §22, §23, §27.1; checklist §6, §7, §9, §10).

-- Local accounts. SSO/OIDC is not configured in this release; MFA is TOTP.
CREATE TABLE users (
  id                    uuid PRIMARY KEY,
  username              text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9._-]{2,63}$'),
  display_name          text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  password_hash         text NOT NULL,            -- scrypt$N$r$p$salt$hash (never logged)
  roles                 text[] NOT NULL DEFAULT ARRAY[]::text[]
                        CHECK (roles <@ ARRAY['admin','intake','analyst','approver','evidence','auditor','report']::text[]),
  totp_secret           text,                     -- base32; active only once totp_enabled
  totp_enabled          boolean NOT NULL DEFAULT false,
  totp_last_counter     bigint,                   -- replay protection for TOTP codes
  must_change_password  boolean NOT NULL DEFAULT true,
  failed_logins         integer NOT NULL DEFAULT 0,
  locked_until          timestamptz,
  disabled_at           timestamptz,
  password_changed_at   timestamptz NOT NULL DEFAULT now(),
  created_at            timestamptz NOT NULL DEFAULT now(),
  created_by            text NOT NULL
);

CREATE TABLE user_sessions (
  id               uuid PRIMARY KEY,
  user_id          uuid NOT NULL REFERENCES users(id),
  token_sha256     text NOT NULL UNIQUE,          -- only the hash of the bearer cookie is stored
  csrf_token       text NOT NULL,
  mfa_verified     boolean NOT NULL DEFAULT false,
  created_at       timestamptz NOT NULL DEFAULT now(),
  last_seen_at     timestamptz NOT NULL DEFAULT now(),
  expires_at       timestamptz NOT NULL,          -- absolute lifetime
  revoked_at       timestamptz,
  revoked_reason   text,
  ip               text,
  user_agent       text
);
CREATE INDEX user_sessions_user_idx ON user_sessions (user_id) WHERE revoked_at IS NULL;

CREATE TABLE cases (
  id             uuid PRIMARY KEY,
  case_ref       text NOT NULL UNIQUE CHECK (length(case_ref) BETWEEN 1 AND 120),
  title          text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
  category       text NOT NULL DEFAULT 'other'
                 CHECK (category IN ('financial_fraud','phishing','impersonation','investment_scam','loan_app','job_task_scam','sextortion','other')),
  sensitivity    text NOT NULL DEFAULT 'restricted' CHECK (sensitivity IN ('restricted','confidential','secret')),
  owner_unit     text,
  status         text NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed')),
  -- Restricted references: never returned by list endpoints, masked unless the viewer is a case member.
  ncrp_refs      text[] NOT NULL DEFAULT ARRAY[]::text[],
  fir_refs       text[] NOT NULL DEFAULT ARRAY[]::text[],
  description    text,
  opened_at      timestamptz NOT NULL DEFAULT now(),
  opened_by      uuid REFERENCES users(id),
  closed_at      timestamptz,
  closed_by      uuid REFERENCES users(id),
  version        integer NOT NULL DEFAULT 1
);

CREATE TABLE case_members (
  case_id     uuid NOT NULL REFERENCES cases(id),
  user_id     uuid NOT NULL REFERENCES users(id),
  case_role   text NOT NULL CHECK (case_role IN ('owner','investigator','viewer')),
  added_by    uuid REFERENCES users(id),
  added_at    timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (case_id, user_id)
);
CREATE INDEX case_members_user_idx ON case_members (user_id);

-- Every case a job belongs to, through its own case_ref or any of its seeds (including merged duplicates).
CREATE VIEW job_case_links AS
  SELECT j.id AS job_id, j.case_ref FROM jobs j WHERE j.case_ref IS NOT NULL
  UNION
  SELECT js.job_id, s.case_ref FROM job_sources js JOIN source_records s ON s.id = js.source_record_id WHERE s.case_ref IS NOT NULL;

-- Intake batches: idempotent API submissions with a durable batch id.
ALTER TABLE import_batches DROP CONSTRAINT import_batches_format_check;
ALTER TABLE import_batches ADD CONSTRAINT import_batches_format_check CHECK (format IN ('csv', 'jsonl', 'xlsx', 'text'));
ALTER TABLE import_batches
  ADD COLUMN batch_uuid        uuid UNIQUE,
  ADD COLUMN submitted_by_user uuid REFERENCES users(id),
  ADD COLUMN idempotency_key   text CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 8 AND 200),
  ADD COLUMN case_id           uuid REFERENCES cases(id),
  ADD COLUMN request_id        text,
  ADD COLUMN lawful_basis      text,
  ADD COLUMN authorisation_ref text;
CREATE UNIQUE INDEX import_batches_idempotency_idx ON import_batches (imported_by, idempotency_key) WHERE idempotency_key IS NOT NULL;

CREATE INDEX jobs_case_ref_idx ON jobs (case_ref);
CREATE INDEX jobs_updated_idx ON jobs (updated_at DESC, id DESC);
CREATE INDEX job_sources_source_idx ON job_sources (source_record_id);
