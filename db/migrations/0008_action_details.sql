-- Route-specific notice fields, eligibility check snapshots, and retention
-- protection for evidence cited by actions (blueprint v4 §26, §27.3).

ALTER TABLE notices
  ADD COLUMN route_fields     jsonb NOT NULL DEFAULT '{}'::jsonb,   -- e.g. statutory ground, data categories, time window
  ADD COLUMN last_eligibility jsonb NOT NULL DEFAULT '[]'::jsonb,   -- checks evaluated at the last transition
  ADD COLUMN outcome_note     text;

-- Report packages generated from an approved snapshot (one per generation).
CREATE TABLE notice_reports (
  id               uuid PRIMARY KEY,
  notice_id        uuid NOT NULL REFERENCES notices(id),
  snapshot_sha256  text NOT NULL,
  relative_dir     text NOT NULL,
  files            jsonb NOT NULL,        -- [{path, sha256, size_bytes, format}]
  index_sha256     text NOT NULL,
  evidence_package_id uuid REFERENCES evidence_packages(id),
  generated_by     text NOT NULL,
  generated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER notice_reports_append_only BEFORE UPDATE OR DELETE ON notice_reports FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- Template verification register: a certificate/notice template may be used only
-- after a named person has checked it against the official text.
CREATE TABLE template_verifications (
  id              bigserial PRIMARY KEY,
  template_id     text NOT NULL,
  template_version text NOT NULL,
  source_reference text NOT NULL,
  verified_by     text NOT NULL,
  verified_at     timestamptz NOT NULL DEFAULT now(),
  note            text
);
CREATE INDEX template_verifications_idx ON template_verifications (template_id, template_version);
CREATE TRIGGER template_verifications_append_only BEFORE UPDATE OR DELETE ON template_verifications FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
