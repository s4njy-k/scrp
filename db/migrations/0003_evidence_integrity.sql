-- Evidence integrity, provenance and chain of custody (blueprint v4 §23.3, §24;
-- checklist §1). Forward-only and additive: existing rows and APIs keep working.

-- ---------------------------------------------------------------------------
-- Tamper-evident custody chain on the existing audit log.
--
-- Every audit event is sealed into a single SHA-256 hash chain by the
-- coordinator's sealer (src/evidence/custody.ts) a few seconds after commit:
--   event_hash = sha256(prev_hash || '\n' || chain_pos || '\n' || sealed_payload)
-- sealed_payload is the canonical JSON of the event row, stored verbatim so an
-- independent verifier can recompute the chain without this application.
--
-- Rows are append-only: DELETE is refused and UPDATE is allowed only once, to
-- add the seal. A database owner or host administrator can still drop the
-- trigger: the chain is tamper-EVIDENT relative to externally held signed
-- checkpoints (custody_checkpoints), not WORM storage.
-- ---------------------------------------------------------------------------
ALTER TABLE audit_events
  ADD COLUMN actor_kind     text NOT NULL DEFAULT 'service' CHECK (actor_kind IN ('service', 'user', 'operator')),
  ADD COLUMN case_ref       text,
  ADD COLUMN object_type    text,
  ADD COLUMN object_id      text,
  ADD COLUMN outcome        text,
  ADD COLUMN request_id     text,
  ADD COLUMN chain_pos      bigint UNIQUE,
  ADD COLUMN prev_hash      text,
  ADD COLUMN event_hash     text,
  ADD COLUMN sealed_payload text,
  ADD COLUMN sealed_at      timestamptz;
CREATE INDEX audit_events_unsealed_idx ON audit_events (id) WHERE chain_pos IS NULL;
CREATE INDEX audit_events_object_idx ON audit_events (object_type, object_id);
CREATE INDEX audit_events_case_idx ON audit_events (case_ref, at);

CREATE FUNCTION audit_events_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'audit_events is append-only (custody chain)';
  END IF;
  -- The only permitted update adds the seal to an unsealed row and changes nothing else.
  IF OLD.chain_pos IS NOT NULL OR NEW.chain_pos IS NULL
     OR NEW.id IS DISTINCT FROM OLD.id OR NEW.at IS DISTINCT FROM OLD.at
     OR NEW.actor IS DISTINCT FROM OLD.actor OR NEW.actor_kind IS DISTINCT FROM OLD.actor_kind
     OR NEW.event_type IS DISTINCT FROM OLD.event_type OR NEW.job_id IS DISTINCT FROM OLD.job_id
     OR NEW.attempt_id IS DISTINCT FROM OLD.attempt_id OR NEW.details IS DISTINCT FROM OLD.details
     OR NEW.case_ref IS DISTINCT FROM OLD.case_ref OR NEW.object_type IS DISTINCT FROM OLD.object_type
     OR NEW.object_id IS DISTINCT FROM OLD.object_id OR NEW.outcome IS DISTINCT FROM OLD.outcome
     OR NEW.request_id IS DISTINCT FROM OLD.request_id THEN
    RAISE EXCEPTION 'audit_events is append-only (custody chain): only a one-time seal is permitted';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER audit_events_append_only BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();

-- Signed chain heads exported for storage outside the collector's control.
CREATE TABLE custody_checkpoints (
  id                  bigserial PRIMARY KEY,
  chain_pos           bigint NOT NULL,
  event_hash          text NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  created_by          text NOT NULL,
  signature_alg       text,              -- 'ed25519' or NULL when no signing key is configured
  signature           text,
  public_key_sha256   text,
  exported_path       text,              -- relative to ARTIFACT_ROOT
  exported_sha256     text,
  note                text
);

-- ---------------------------------------------------------------------------
-- Artifact verification state. 'verified_at_commit' means the bytes were
-- re-opened in their final location after the atomic rename and re-hashed.
-- ---------------------------------------------------------------------------
ALTER TABLE artifacts
  ADD COLUMN verification_state text NOT NULL DEFAULT 'unverified'
    CHECK (verification_state IN ('unverified', 'verified_at_commit', 'verified', 'mismatch', 'missing', 'not_applicable')),
  ADD COLUMN last_verified_at timestamptz;

ALTER TABLE attempts
  ADD COLUMN manifest_version integer,
  -- First validated viewport image, visible to analysts while the attempt is still finalising.
  ADD COLUMN first_image_rel     text,
  ADD COLUMN first_image_sha256  text,
  ADD COLUMN first_image_at      timestamptz,
  ADD COLUMN progress_stage      text,
  ADD COLUMN progress_at         timestamptz;
CREATE INDEX attempts_job_idx ON attempts (job_id, attempt_no);

-- Verify Evidence runs and their exported reports.
CREATE TABLE verification_runs (
  id             uuid PRIMARY KEY,
  scope          text NOT NULL CHECK (scope IN ('attempt', 'job', 'case', 'package', 'custody_chain')),
  object_id      text NOT NULL,
  requested_by   text NOT NULL,
  started_at     timestamptz NOT NULL DEFAULT now(),
  finished_at    timestamptz,
  result         text CHECK (result IN ('pass', 'fail', 'error')),
  counts         jsonb NOT NULL DEFAULT '{}'::jsonb,
  report_path    text,
  report_sha256  text
);
CREATE INDEX verification_runs_object_idx ON verification_runs (scope, object_id, started_at DESC);

-- Evidence packages: a parent index lists every file and manifest hash, so a
-- manifest is never hashed inside itself (checklist §1 "seal the manifest").
CREATE TABLE evidence_packages (
  id             uuid PRIMARY KEY,
  case_ref       text,
  purpose        text NOT NULL,
  scope          jsonb NOT NULL,
  created_by     text NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  relative_path  text NOT NULL,
  index_sha256   text NOT NULL,
  file_count     integer NOT NULL,
  total_bytes    bigint NOT NULL
);

-- Clock discipline facts recorded by the host preflight (UTC stored; IST rendered).
INSERT INTO system_state (key, value) VALUES
  ('clock', '{"source": "unrecorded", "sync_verified": false, "offset_ms": null, "recorded_at": null}'::jsonb)
ON CONFLICT (key) DO NOTHING;
