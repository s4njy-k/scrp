-- Legally routed actions, official report drafts and BSA 2023 Section 63
-- certificate worksheets (blueprint v4 §24.3, §26; checklist §1, §6).
-- Nothing here sends anything: issuance is an authorised human act outside the
-- collector, recorded afterwards with proof of submission/receipt.

-- Uploaded documents (signed certificates, dispatch proofs, provider acknowledgements).
-- Stored under ARTIFACT_ROOT/uploads/ as separately hashed files; never served inline.
CREATE TABLE uploads (
  id             uuid PRIMARY KEY,
  case_id        uuid NOT NULL REFERENCES cases(id),
  purpose        text NOT NULL CHECK (purpose IN ('signed_certificate', 'dispatch_proof', 'receipt_proof', 'provider_acknowledgement', 'legal_authority', 'other')),
  filename       text NOT NULL,          -- display only; never used to build a path
  content_type   text NOT NULL,
  relative_path  text NOT NULL,
  sha256         text NOT NULL,
  size_bytes     bigint NOT NULL,
  uploaded_by    text NOT NULL,
  uploaded_at    timestamptz NOT NULL DEFAULT now(),
  note           text
);
CREATE TRIGGER uploads_append_only BEFORE UPDATE OR DELETE ON uploads FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

CREATE TABLE notices (
  id                   uuid PRIMARY KEY,
  case_id              uuid NOT NULL REFERENCES cases(id),
  route                text NOT NULL CHECK (route IN ('it_act_69a_blocking', 'it_act_79_3_b_intimation', 'registrar_abuse', 'registry_escalation',
                                                     'hosting_cdn_abuse', 'app_store_complaint', 'preservation_request', 'bnss_94_production',
                                                     'financial_fraud_alert', 'investigation_lead_package')),
  state                text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'analyst_review', 'legal_check', 'approved', 'generated', 'issued',
                                                     'acknowledged', 'complied', 'partially_complied', 'rejected', 'no_response',
                                                     'verified_closed', 'escalated', 'withdrawn', 'disputed')),
  reference_no         text,
  language             text NOT NULL DEFAULT 'en' CHECK (language IN ('en', 'hi', 'en_hi')),
  recipient            jsonb NOT NULL,        -- {name, kind, contact, jurisdiction}
  legal_basis          text,
  authority_ref        text,                  -- authorisation / competent-authority reference
  issuing_authority    text,
  signatory_name       text,
  signatory_designation text,
  jurisdiction         text,
  facts_summary        text,
  requested_action     text,
  necessity_note       text,
  proportionality_note text,
  lawful_deadline      text,                  -- only where a legal response period genuinely applies
  internal_followup_at timestamptz,           -- internal SLA; never presented as a legal deadline
  created_by           text NOT NULL,
  created_by_id        uuid REFERENCES users(id),
  created_at           timestamptz NOT NULL DEFAULT now(),
  approved_by          text,
  approved_by_id       uuid REFERENCES users(id),
  approved_at          timestamptz,
  approved_snapshot_sha256 text,              -- hash of the exact content the checker approved
  generated_package_id uuid REFERENCES evidence_packages(id),
  report_path          text,
  report_sha256        text,
  issued_at            timestamptz,           -- recorded by a human after authorised dispatch
  issued_by            text,
  issue_channel        text,
  dispatch_upload_id   uuid REFERENCES uploads(id),
  received_at          timestamptz,           -- only from documented receipt evidence
  receipt_upload_id    uuid REFERENCES uploads(id),
  version              integer NOT NULL DEFAULT 1,
  CONSTRAINT notices_checker_differs CHECK (approved_by_id IS NULL OR approved_by_id IS DISTINCT FROM created_by_id)
);
CREATE INDEX notices_case_idx ON notices (case_id, state);
CREATE INDEX notices_followup_idx ON notices (state, internal_followup_at);

-- One evidence basis and status per URL/domain, so partial compliance is unambiguous.
CREATE TABLE notice_targets (
  notice_id       uuid NOT NULL REFERENCES notices(id),
  target_id       bigint NOT NULL REFERENCES targets(id),
  evidence_attempt_ids uuid[] NOT NULL,
  legal_ground    text,
  target_status   text NOT NULL DEFAULT 'pending' CHECK (target_status IN ('pending', 'acted_upon', 'not_acted', 'disputed', 'withdrawn', 'verified_removed', 'still_live')),
  status_note     text,
  updated_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (notice_id, target_id)
);
CREATE INDEX notice_targets_target_idx ON notice_targets (target_id);

CREATE TABLE notice_events (
  id          bigserial PRIMARY KEY,
  notice_id   uuid NOT NULL REFERENCES notices(id),
  from_state  text,
  to_state    text NOT NULL,
  actor       text NOT NULL,
  actor_id    uuid REFERENCES users(id),
  note        text,
  details     jsonb NOT NULL DEFAULT '{}'::jsonb,
  at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX notice_events_notice_idx ON notice_events (notice_id, id);
CREATE TRIGGER notice_events_append_only BEFORE UPDATE OR DELETE ON notice_events FOR EACH ROW EXECUTE FUNCTION forbid_mutation();

-- BSA 2023 s.63(4)(c) Schedule certificate preparation. The platform prepares a
-- fact sheet and a worksheet; it never signs. Unknown statutory fields stay blank.
CREATE TABLE certificates (
  id                   uuid PRIMARY KEY,
  case_id              uuid NOT NULL REFERENCES cases(id),
  attempt_ids          uuid[] NOT NULL,
  part                 text NOT NULL CHECK (part IN ('A', 'B', 'A_and_B')),
  state                text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'completed', 'signed', 'attached_to_submission', 'withdrawn')),
  template_source_version text NOT NULL,
  fact_sheet_path      text NOT NULL,
  fact_sheet_sha256    text NOT NULL,
  hash_report_path     text NOT NULL,
  hash_report_sha256   text NOT NULL,
  worksheet            jsonb NOT NULL,        -- Part A/B fields; blank unless verified by the responsible person
  prepared_by          text NOT NULL,
  prepared_by_id       uuid REFERENCES users(id),
  completed_by         text,
  completed_at         timestamptz,
  signed_upload_id     uuid REFERENCES uploads(id),
  signed_recorded_by   text,
  signed_recorded_at   timestamptz,
  submissions          jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at           timestamptz NOT NULL DEFAULT now(),
  version              integer NOT NULL DEFAULT 1
);
CREATE INDEX certificates_case_idx ON certificates (case_id);

CREATE TABLE certificate_events (
  id              bigserial PRIMARY KEY,
  certificate_id  uuid NOT NULL REFERENCES certificates(id),
  from_state      text,
  to_state        text NOT NULL,
  actor           text NOT NULL,
  note            text,
  at              timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER certificate_events_append_only BEFORE UPDATE OR DELETE ON certificate_events FOR EACH ROW EXECUTE FUNCTION forbid_mutation();
