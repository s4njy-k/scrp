-- Post-action monitoring and asynchronous infrastructure enrichment
-- (blueprint v4 §25.4, §28.1; checklist §4, §8).

-- Authorised, proportionate revisit schedules. Every revisit is a NEW job and
-- attempt; earlier observations are never modified.
CREATE TABLE monitoring_rules (
  id               uuid PRIMARY KEY,
  target_id        bigint NOT NULL REFERENCES targets(id),
  case_id          uuid NOT NULL REFERENCES cases(id),
  notice_id        uuid REFERENCES notices(id),
  baseline_attempt uuid REFERENCES attempts(id),
  interval_hours   numeric NOT NULL CHECK (interval_hours > 0),
  max_per_day      integer NOT NULL CHECK (max_per_day BETWEEN 1 AND 6),
  capture_variant  text NOT NULL DEFAULT 'desktop' CHECK (capture_variant IN ('desktop', 'mobile')),
  active           boolean NOT NULL DEFAULT true,
  reason           text NOT NULL,
  created_by       text NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  ends_at          timestamptz NOT NULL,
  next_due_at      timestamptz NOT NULL,
  last_job_id      bigint REFERENCES jobs(id),
  revisits         integer NOT NULL DEFAULT 0,
  stopped_by       text,
  stopped_at       timestamptz
);
CREATE INDEX monitoring_rules_due_idx ON monitoring_rules (next_due_at) WHERE active;
CREATE UNIQUE INDEX monitoring_rules_one_active_idx ON monitoring_rules (target_id, capture_variant) WHERE active;

-- Comparison of a revisit with the baseline; outcome classes are distinct (checklist §8).
CREATE TABLE monitoring_observations (
  id                 bigserial PRIMARY KEY,
  rule_id            uuid NOT NULL REFERENCES monitoring_rules(id),
  job_id             bigint NOT NULL REFERENCES jobs(id),
  attempt_id         uuid REFERENCES attempts(id),
  baseline_attempt   uuid REFERENCES attempts(id),
  outcome_class      text NOT NULL CHECK (outcome_class IN ('still_live', 'observed_changed_content', 'temporarily_unreachable', 'challenged',
                                                           'blocked_at_tested_vantage', 'dns_not_resolving', 'parked_or_suspended_page',
                                                           'redirected_elsewhere', 'reported_removal', 'provider_confirmed_suspension', 'inconclusive')),
  differences        jsonb NOT NULL,
  created_at         timestamptz NOT NULL DEFAULT now(),
  analyst_note       text
);
CREATE INDEX monitoring_observations_rule_idx ON monitoring_observations (rule_id, id DESC);
CREATE TRIGGER monitoring_observations_append_only BEFORE UPDATE OR DELETE ON monitoring_observations FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- Reappearance alerts: corroborated unusual identifiers seen on a NEW domain. Evidence, not attribution.
CREATE TABLE reappearance_alerts (
  id                bigserial PRIMARY KEY,
  source_target_id  bigint NOT NULL REFERENCES targets(id),
  new_target_id     bigint NOT NULL REFERENCES targets(id),
  shared            jsonb NOT NULL,
  strength          text NOT NULL CHECK (strength IN ('possible', 'strong_possible')),
  created_at        timestamptz NOT NULL DEFAULT now(),
  acknowledged_by   text,
  acknowledged_at   timestamptz,
  UNIQUE (source_target_id, new_target_id)
);

-- Cached enrichment results with source, retrieval time, TTL and source-specific errors.
CREATE TABLE enrichment_results (
  id             bigserial PRIMARY KEY,
  subject_kind   text NOT NULL CHECK (subject_kind IN ('domain', 'host', 'ip')),
  subject        text NOT NULL,
  source         text NOT NULL CHECK (source IN ('dns', 'tls', 'rdap_domain', 'rdap_ip', 'ct')),
  status         text NOT NULL CHECK (status IN ('ok', 'error', 'not_found', 'redacted', 'disabled')),
  data           jsonb NOT NULL DEFAULT '{}'::jsonb,
  error          text,
  method         text NOT NULL,
  observation_point text NOT NULL,      -- where the lookup was made from (recorded uncertainty)
  retrieved_at   timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz NOT NULL
);
CREATE INDEX enrichment_results_subject_idx ON enrichment_results (subject_kind, subject, source, retrieved_at DESC);

ALTER TABLE targets ADD COLUMN enrichment_requested_at timestamptz;
ALTER TABLE targets ADD COLUMN enrichment_done_at timestamptz;
