-- Investigation layer (blueprint v4 §23.1, §25; checklist §3, §5, §7):
-- typed findings with provenance and review states, explainable versioned risk
-- assessments, append-only analyst decisions and annotations. Original evidence
-- is never edited: interpretations are separate, attributed records.

-- Shared guard for append-only tables (corrections are new rows, never edits).
CREATE FUNCTION forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION '% is append-only; record a new entry instead', TG_TABLE_NAME;
END $$;

-- Extraction provenance (checklist §3 "attach source provenance to every extracted identifier").
ALTER TABLE identifiers
  ADD COLUMN value_key          text,           -- field_type-scoped stable key for reviews across re-extraction
  ADD COLUMN extractor_version  text,
  ADD COLUMN confidence         numeric(4,3) CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
  ADD COLUMN source_artifact_id bigint REFERENCES artifacts(id),
  ADD COLUMN conflicts          jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN signal_only        boolean NOT NULL DEFAULT false;  -- analytics/template signals: never identity
CREATE INDEX identifiers_value_key_idx ON identifiers (field_type, value_key);
CREATE INDEX identifiers_target_idx ON identifiers (target_id);
CREATE INDEX identifiers_attempt_idx ON identifiers (attempt_id);
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX identifiers_value_trgm_idx ON identifiers USING gin (normalised_value gin_trgm_ops);

-- Analyst interpretation of an extracted value: unverified / candidate / corroborated / rejected.
CREATE TABLE identifier_reviews (
  id               bigserial PRIMARY KEY,
  target_id        bigint NOT NULL REFERENCES targets(id),
  field_type       text NOT NULL,
  value_key        text NOT NULL,
  state            text NOT NULL CHECK (state IN ('unverified', 'candidate', 'corroborated', 'rejected')),
  corrected_value  text,
  reason_code      text NOT NULL,
  reason           text NOT NULL,
  evidence_refs    jsonb NOT NULL DEFAULT '[]'::jsonb,
  actor            text NOT NULL,
  actor_id         uuid REFERENCES users(id),
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX identifier_reviews_key_idx ON identifier_reviews (target_id, field_type, value_key, id DESC);
CREATE TRIGGER identifier_reviews_append_only BEFORE UPDATE OR DELETE ON identifier_reviews FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- Versioned, explainable triage aid. Never a legal finding; immutable per version.
CREATE TABLE risk_assessments (
  id               bigserial PRIMARY KEY,
  target_id        bigint NOT NULL REFERENCES targets(id),
  job_id           bigint REFERENCES jobs(id),
  attempt_id       uuid REFERENCES attempts(id),
  policy_version   text NOT NULL,
  score            integer NOT NULL CHECK (score BETWEEN 0 AND 100),
  band             text NOT NULL CHECK (band IN ('insufficient_evidence', 'low', 'medium', 'high')),
  signals          jsonb NOT NULL,        -- [{code, label, weight, direction, evidence:[...]}]
  benign_context   jsonb NOT NULL,        -- matched benign-context checklist items
  conflicts        jsonb NOT NULL DEFAULT '[]'::jsonb,
  capture_quality  text NOT NULL,         -- separate from suspicion (checklist §5)
  created_at       timestamptz NOT NULL DEFAULT now(),
  created_by       text NOT NULL
);
CREATE INDEX risk_assessments_target_idx ON risk_assessments (target_id, id DESC);
CREATE TRIGGER risk_assessments_append_only BEFORE UPDATE OR DELETE ON risk_assessments FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- Analyst decisions: append-only; the latest decision per target is the current verdict.
CREATE TABLE analyst_decisions (
  id                   bigserial PRIMARY KEY,
  target_id            bigint NOT NULL REFERENCES targets(id),
  case_id              uuid REFERENCES cases(id),
  decision             text NOT NULL CHECK (decision IN ('retain', 'investigate', 'false_positive', 'benign', 'inconclusive', 'recapture', 'escalate_for_approval', 'confirm_suspicious', 'likely_malicious', 'override_suppression')),
  verdict              text NOT NULL CHECK (verdict IN ('unreviewed', 'suspicious', 'likely_malicious', 'benign', 'false_positive', 'inconclusive')),
  reason_code          text NOT NULL,
  reason               text NOT NULL CHECK (length(reason) >= 3),
  evidence_refs        jsonb NOT NULL DEFAULT '[]'::jsonb,
  risk_assessment_id   bigint REFERENCES risk_assessments(id),
  new_evidence_attempt uuid REFERENCES attempts(id),   -- required to override a false-positive suppression
  supersedes           bigint REFERENCES analyst_decisions(id),
  actor                text NOT NULL,
  actor_id             uuid REFERENCES users(id),
  request_id           text,
  created_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX analyst_decisions_target_idx ON analyst_decisions (target_id, id DESC);
CREATE TRIGGER analyst_decisions_append_only BEFORE UPDATE OR DELETE ON analyst_decisions FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

CREATE VIEW target_verdicts AS
  SELECT DISTINCT ON (target_id) target_id, id AS decision_id, decision, verdict, reason_code, actor, created_at
    FROM analyst_decisions ORDER BY target_id, id DESC;

-- Analyst notes and annotations: separate from evidence, never rewriting originals.
CREATE TABLE annotations (
  id           bigserial PRIMARY KEY,
  object_type  text NOT NULL CHECK (object_type IN ('target', 'attempt', 'artifact', 'identifier', 'case')),
  object_id    text NOT NULL,
  case_id      uuid REFERENCES cases(id),
  body         text NOT NULL CHECK (length(body) BETWEEN 1 AND 10000),
  supersedes   bigint REFERENCES annotations(id),
  actor        text NOT NULL,
  actor_id     uuid REFERENCES users(id),
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX annotations_object_idx ON annotations (object_type, object_id, id DESC);
CREATE TRIGGER annotations_append_only BEFORE UPDATE OR DELETE ON annotations FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
