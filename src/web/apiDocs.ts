/**
 * Human-maintained documentation for every API route. Method, path, auth
 * level, roles, body kind and CSRF come from the live route table; this file
 * adds summaries, parameters and request schemas. `npm run openapi` writes
 * docs/openapi.json and a test fails if any route is undocumented or the
 * committed document is stale.
 */

type Schema = Record<string, unknown>;
export interface RouteDoc {
  tag: string;
  summary: string;
  description?: string;
  query?: [name: string, description: string, required?: boolean][];
  body?: Schema;
  /** Content types accepted for raw bodies. */
  rawTypes?: string[];
  /** Binary or text download instead of JSON. */
  download?: string;
}

const str = (o: Schema = {}): Schema => ({ type: 'string', ...o });
const int = (o: Schema = {}): Schema => ({ type: 'integer', ...o });
const bool: Schema = { type: 'boolean' };
const uuid = str({ format: 'uuid' });
const arr = (items: Schema, o: Schema = {}): Schema => ({ type: 'array', items, ...o });
const enm = (...v: string[]): Schema => ({ type: 'string', enum: v });
const obj = (properties: Record<string, Schema>, required: string[] = []): Schema => ({ type: 'object', additionalProperties: false, properties, required });
const reason = str({ minLength: 5, maxLength: 1000 });
const ROLES = enm('admin', 'intake', 'analyst', 'approver', 'evidence', 'auditor', 'report');
const RECIPIENT = obj({ name: str({ maxLength: 300 }), kind: enm('government_nodal', 'intermediary', 'registrar', 'registry', 'hosting_provider', 'cdn', 'app_distributor', 'record_holder', 'bank_or_psp', 'investigating_officer'), contact: str(), jurisdiction: str() }, ['name', 'kind']);
const NOTICE_FIELDS: Record<string, Schema> = {
  reference_no: str(), language: enm('en', 'hi', 'en_hi'), legal_basis: str(), authority_ref: str(), issuing_authority: str(), signatory_name: str(), signatory_designation: str(),
  jurisdiction: str(), facts_summary: str(), requested_action: str(), necessity_note: str(), proportionality_note: str(), lawful_deadline: str(),
  internal_followup_at: str({ format: 'date-time', description: 'Internal follow-up target; never a legal deadline.' }), route_fields: { type: 'object', description: 'Route-specific particulars (see GET /api/v1/legal-routes).' },
};
const NOTICE_TARGETS = arr(obj({ target_id: int(), evidence_attempt_ids: arr(uuid, { maxItems: 10 }), legal_ground: str() }, ['target_id']), { minItems: 1, maxItems: 200 });
const CASE_LIST: RouteDoc['query'] = [['case_id', 'Restrict to one case (UUID)']];

export const ROUTE_DOCS: Record<string, RouteDoc> = {
  // ---- Health and authentication
  'GET /api/v1/health': { tag: 'ops', summary: 'Liveness of the API process and database' },
  'POST /api/v1/auth/login': { tag: 'auth', summary: 'Password step of sign-in', description: 'Returns `next` (mfa, enrol_mfa, change_password or null) and a CSRF token. Rate-limited per account and per client address; repeated failures lock the account.', body: obj({ username: str({ maxLength: 64 }), password: str({ maxLength: 256 }) }, ['username', 'password']) },
  'POST /api/v1/auth/logout': { tag: 'auth', summary: 'Revoke the current session' },
  'GET /api/v1/auth/me': { tag: 'auth', summary: 'Current user, roles, pending sign-in step and UI policy' },
  'POST /api/v1/auth/mfa/enrol': { tag: 'auth', summary: 'Start TOTP enrolment (returns the secret and otpauth URI once)' },
  'POST /api/v1/auth/mfa/confirm': { tag: 'auth', summary: 'Confirm TOTP enrolment with a code', body: obj({ code: str({ pattern: '^\\d{6}$' }) }, ['code']) },
  'POST /api/v1/auth/mfa/verify': { tag: 'auth', summary: 'TOTP step of sign-in (each time-step code is accepted once)', body: obj({ code: str({ pattern: '^\\d{6}$' }) }, ['code']) },
  'POST /api/v1/auth/password': { tag: 'auth', summary: 'Change password; other sessions are revoked', body: obj({ current_password: str(), new_password: str({ minLength: 12 }) }, ['current_password', 'new_password']) },
  'GET /api/v1/auth/sessions': { tag: 'auth', summary: 'List my active sessions' },

  // ---- Administration
  'GET /api/v1/admin/users': { tag: 'admin', summary: 'List accounts' },
  'POST /api/v1/admin/users': { tag: 'admin', summary: 'Create an account with a one-time password', body: obj({ username: str({ pattern: '^[a-z0-9][a-z0-9._-]{2,63}$' }), display_name: str(), roles: arr(ROLES, { maxItems: 7 }) }, ['username', 'display_name', 'roles']) },
  'PATCH /api/v1/admin/users/:id': { tag: 'admin', summary: 'Change display name, roles or disabled state (sessions revoked on privilege change)', body: obj({ display_name: str(), roles: arr(ROLES), disabled: bool, reason: str({ minLength: 3 }) }, ['reason']) },
  'POST /api/v1/admin/users/:id/reset-credentials': { tag: 'admin', summary: 'Issue a new one-time password, optionally resetting MFA', body: obj({ reset_mfa: bool, reason: str({ minLength: 3 }) }, ['reason']) },

  // ---- Cases
  'GET /api/v1/cases': { tag: 'cases', summary: 'Cases visible to me (admins see all with masked references)', query: [['q', 'Reference or title search'], ['status', 'open or closed'], ['limit', 'Page size'], ['cursor', 'Opaque cursor']] },
  'POST /api/v1/cases': { tag: 'cases', summary: 'Open a case (the creator becomes owner)', body: obj({ case_ref: str({ pattern: '^[A-Za-z0-9/_.:-]+$', maxLength: 120 }), title: str(), category: enm('financial_fraud', 'phishing', 'impersonation', 'investment_scam', 'loan_app', 'job_task_scam', 'sextortion', 'other'), sensitivity: enm('restricted', 'confidential', 'secret'), owner_unit: str(), description: str(), ncrp_refs: arr(str()), fir_refs: arr(str()) }, ['case_ref', 'title']) },
  'GET /api/v1/cases/:id': { tag: 'cases', summary: 'Case detail: members, holds, job states' },
  'PATCH /api/v1/cases/:id': { tag: 'cases', summary: 'Edit, close or reopen a case (owner)', body: obj({ expected_version: int(), title: str(), description: str(), status: enm('open', 'closed'), ncrp_refs: arr(str()), fir_refs: arr(str()), reason: str() }) },
  'POST /api/v1/cases/:id/members': { tag: 'cases', summary: 'Add or change a member (owner)', body: obj({ username: str(), case_role: enm('owner', 'investigator', 'viewer'), reason: str({ minLength: 3 }) }, ['username', 'case_role', 'reason']) },
  'DELETE /api/v1/cases/:id/members/:userId': { tag: 'cases', summary: 'Remove a member (owner)' },
  'POST /api/v1/cases/:id/hold': { tag: 'cases', summary: 'Place a legal hold (blocks retention deletion)', body: obj({ reason, authority_ref: str() }, ['reason']) },
  'POST /api/v1/cases/:id/hold/release': { tag: 'cases', summary: 'Release a legal hold', body: obj({ reason }, ['reason']) },
  'POST /api/v1/cases/:id/uploads': { tag: 'cases', summary: 'Upload a proof document (signed certificate, dispatch or receipt proof)', description: 'Raw body; the content must match its declared type. Stored read-only and hashed.', query: [['purpose', 'signed_certificate | dispatch_proof | receipt_proof | provider_acknowledgement | legal_authority | other', true], ['filename', 'Original file name'], ['note', 'Free-text note']], rawTypes: ['application/pdf', 'image/png', 'image/jpeg', 'text/plain'] },
  'GET /api/v1/uploads/:id/content': { tag: 'cases', summary: 'Download an upload after re-verifying its hash', download: 'application/octet-stream' },

  // ---- Intake and jobs
  'POST /api/v1/intake-batches': { tag: 'jobs', summary: 'Submit URLs (CSV, JSONL, XLSX or text) to a case', description: 'Requires an Idempotency-Key header unless dry_run=true. Each line gets an accepted/duplicate/rejected result.', query: [['case_id', 'Target case (UUID)', true], ['dry_run', 'Validate without creating jobs'], ['profile', 'browser_evidence | data_triage'], ['format', 'csv | jsonl | xlsx | text (else from Content-Type)'], ['urgent', 'Urgent priority (true/false)'], ['priority', 'Default priority for rows without one'], ['capture_variant', 'desktop | mobile | both'], ['retention_class', 'Default retention class (defaults to case_evidence)'], ['window', 'Duplicate-suppression window key (defaults to today)'], ['filename', 'Original file name'], ['lawful_basis', 'Recorded lawful basis'], ['authorisation_ref', 'Authorisation reference']], rawTypes: ['text/csv', 'application/x-ndjson', 'text/plain', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'] },
  'GET /api/v1/intake-batches/:id': { tag: 'jobs', summary: 'Intake batch with per-line results' },
  'GET /api/v1/jobs': { tag: 'jobs', summary: 'Jobs in my cases with the three separate status fields', query: [['case_ref', 'Filter by case reference'], ['state', 'Processing state'], ['outcome', 'Acquisition outcome'], ['verdict', 'Analyst verdict'], ['q', 'URL search'], ['top_level', 'Only top-level jobs'], ['limit', 'Page size'], ['cursor', 'Opaque cursor']] },
  'GET /api/v1/jobs/events': { tag: 'jobs', summary: 'Server-sent events: job progress and first-image availability', query: [['since', 'Resume after this event time']], download: 'text/event-stream' },
  'GET /api/v1/jobs/:id': { tag: 'jobs', summary: 'Job detail: attempts, progress stage, children' },
  'POST /api/v1/jobs/:id/control': { tag: 'jobs', summary: 'Pause, resume or cancel a queued job', body: obj({ action: enm('pause', 'resume', 'cancel'), reason: str({ minLength: 3 }), confirm: { const: true } }, ['action', 'reason', 'confirm']) },
  'POST /api/v1/jobs/:id/recapture': { tag: 'jobs', summary: 'Create a new capture job for the same target (earlier evidence unchanged)', body: obj({ reason: str({ minLength: 3 }), capture_variant: enm('desktop', 'mobile'), urgent: bool }, ['reason']) },
  'GET /api/v1/attempts/:id/first-image': { tag: 'evidence', summary: 'First validated viewport image of an attempt (served from the committed or staging copy, labelled)', download: 'image/png' },

  // ---- Evidence
  'GET /api/v1/captures/:id/manifest': { tag: 'evidence', summary: 'Manifest with ledger comparison and artifact ledger rows' },
  'GET /api/v1/captures/:id/artifacts': { tag: 'evidence', summary: 'Artifact ledger rows of an attempt', query: [['type', 'Artifact type filter']] },
  'GET /api/v1/artifacts/:id/content': { tag: 'evidence', summary: 'Download an artifact after hash re-verification', description: 'Restricted artifacts (cookies, session data) need an X-Purpose header and the evidence or admin role; access is audited.', download: 'application/octet-stream' },
  'POST /api/v1/captures/:id/verify': { tag: 'evidence', summary: 'Verify Evidence for one attempt (hash every file, write a hashed report)' },
  'POST /api/v1/cases/:id/verify': { tag: 'evidence', summary: 'Verify Evidence for every attempt in a case' },
  'GET /api/v1/verification-runs/:id/report': { tag: 'evidence', summary: 'Download a verification report', download: 'application/json' },
  'POST /api/v1/packages': { tag: 'evidence', summary: 'Prepare an evidence package (originals copied, index hashed)', description: 'The job or attempts must be linked to the given case.', body: obj({ case_id: uuid, job_id: int(), attempt_ids: arr(uuid, { maxItems: 200 }), purpose: str({ minLength: 5 }), include_restricted: bool }, ['case_id', 'purpose']) },
  'GET /api/v1/packages/:id/archive': { tag: 'evidence', summary: 'Download a package as a ustar archive', download: 'application/x-tar' },
  'GET /api/v1/audit-events': { tag: 'evidence', summary: 'Custody/audit events (auditors: all; others: per case)', query: [['case_id', 'Case scope (required unless auditor/admin)'], ['object_type', 'Object type'], ['object_id', 'Object id'], ['limit', 'Page size'], ['cursor', 'Opaque cursor']] },
  'GET /api/v1/custody/verify': { tag: 'evidence', summary: 'Recompute the hash chain of sealed audit events' },

  // ---- Investigation
  'GET /api/v1/targets/:id/investigation': { tag: 'investigation', summary: 'Everything about one target: evidence, typed leads with provenance, risk, decisions, notices, monitoring' },
  'GET /api/v1/targets/:id/related': { tag: 'investigation', summary: 'Related targets sharing strong identifiers, within my scope, with contradictions' },
  'GET /api/v1/targets/:id/addressees': { tag: 'investigation', summary: 'Suggested registrar/hosting/CDN contacts with source and confidence' },
  'POST /api/v1/targets/:id/enrich': { tag: 'investigation', summary: 'Queue a DNS/TLS/RDAP enrichment refresh (through the gateway)' },
  'GET /api/v1/targets/:id/lookalikes': { tag: 'investigation', summary: 'Brand lookalike check against the configured official domains' },
  'POST /api/v1/decisions': { tag: 'investigation', summary: 'Record an append-only analyst decision', description: 'Uses expected_last_decision_id for concurrency. A false-positive/benign decision suppresses external actions until an approver overrides on newer evidence.', body: obj({ target_id: int(), decision: enm('retain', 'investigate', 'false_positive', 'benign', 'inconclusive', 'recapture', 'escalate_for_approval', 'confirm_suspicious', 'likely_malicious', 'override_suppression'), reason_code: str(), reason: str({ minLength: 5 }), evidence_refs: arr({ type: 'object' }), new_evidence_attempt: uuid, expected_last_decision_id: { type: ['integer', 'null'] }, case_id: uuid }, ['target_id', 'decision', 'reason_code', 'reason', 'expected_last_decision_id']) },
  'POST /api/v1/decisions/bulk': { tag: 'investigation', summary: 'Bulk triage: one attributed decision per target (preview first)', body: obj({ target_ids: arr(int(), { minItems: 1, maxItems: 200 }), decision: enm('retain', 'investigate', 'inconclusive', 'recapture', 'false_positive', 'benign'), reason_code: str(), reason: str({ minLength: 5 }), confirm: { const: true }, preview: bool }, ['target_ids', 'decision', 'reason_code', 'reason', 'confirm']) },
  'GET /api/v1/review-queue': { tag: 'investigation', summary: 'Review queues', query: [['queue', 'unreviewed | high_risk_unreviewed | manual_review | escalated | inconclusive'], ['limit', 'Page size']] },
  'POST /api/v1/identifier-reviews': { tag: 'investigation', summary: 'Review one extracted identifier (append-only)', body: obj({ target_id: int(), field_type: str(), value_key: str(), state: enm('unverified', 'candidate', 'corroborated', 'rejected'), corrected_value: str(), reason_code: str(), reason: str({ minLength: 5 }), evidence_refs: arr({ type: 'object' }) }, ['target_id', 'field_type', 'value_key', 'state', 'reason_code', 'reason']) },
  'POST /api/v1/annotations': { tag: 'investigation', summary: 'Add a note (never changes evidence)', description: 'The note is visible only to members of its case. Give case_id when the object is in several of your cases.', body: obj({ object_type: enm('target', 'attempt', 'artifact', 'identifier', 'case'), object_id: str(), body: str({ maxLength: 10000 }), supersedes: int(), case_id: uuid }, ['object_type', 'object_id', 'body']) },
  'GET /api/v1/entities': { tag: 'investigation', summary: 'Targets sharing an identifier value, within my scope', query: [['type', 'Identifier field type', true], ['value', 'Value, 3-500 characters', true], ['mode', 'exact (default) or contains'], ['case_ref', 'Restrict to one case']] },

  // ---- Actions
  'GET /api/v1/legal-routes': { tag: 'actions', summary: 'Legal routes, their required particulars and guardrails, and s.69A grounds' },
  'POST /api/v1/notices': { tag: 'actions', summary: 'Create a notice draft', body: obj({ case_id: uuid, route: str(), recipient: RECIPIENT, targets: NOTICE_TARGETS, ...NOTICE_FIELDS }, ['case_id', 'route', 'recipient', 'targets']) },
  'GET /api/v1/notices': { tag: 'actions', summary: 'Notices in my cases', query: [...CASE_LIST, ['state', 'Notice state']] },
  'GET /api/v1/notices/:id': { tag: 'actions', summary: 'Notice detail with eligibility checks, allowed transitions, events and report packs' },
  'PATCH /api/v1/notices/:id': { tag: 'actions', summary: 'Edit a draft', body: obj({ expected_version: int(), recipient: RECIPIENT, targets: NOTICE_TARGETS, ...NOTICE_FIELDS }, ['expected_version']) },
  'POST /api/v1/notices/:id/transition': { tag: 'actions', summary: 'Move a notice through its workflow', description: 'submit, review_ok (not the author), return_to_draft, approve (approver, not the author), generate, record_issued (needs dispatch proof), record_acknowledged (needs receipt proof), record_outcome, close (verified_closed needs a fresh capture), withdraw, dispute. Nothing is ever sent by the system.', body: obj({ action: str(), note: str(), issued_at: str({ format: 'date-time' }), issue_channel: str(), dispatch_upload_id: uuid, received_at: str({ format: 'date-time' }), receipt_upload_id: uuid, outcome: enm('complied', 'partially_complied', 'rejected', 'no_response'), target_statuses: arr({ type: 'object' }), close_as: enm('verified_closed', 'escalated') }, ['action']) },
  'POST /api/v1/actions/:id/approve': { tag: 'actions', summary: 'Checker approval (blueprint path); freezes an approval snapshot hash', body: obj({ note: str() }) },
  'POST /api/v1/reports/:type/preview': { tag: 'actions', summary: 'Preview a notice report (not saved, not sent)', body: obj({ notice_id: uuid, format: enm('markdown', 'html', 'json') }, ['notice_id']) },
  'POST /api/v1/reports/:id/generate': { tag: 'actions', summary: 'Generate the report pack of an approved notice (fails if content changed since approval)' },
  'GET /api/v1/notices/:id/reports/:reportId/:file': { tag: 'actions', summary: 'Download a generated report file after hash re-verification', download: 'application/octet-stream' },
  'GET /api/v1/templates': { tag: 'actions', summary: 'Section 63 Schedule template, fields and verification records' },
  'POST /api/v1/templates/:id/verify': { tag: 'actions', summary: 'Record that the Schedule template was checked against the official text', body: obj({ source_reference: str({ minLength: 10 }), note: str(), confirm_checked_against_official_text: { const: true } }, ['source_reference', 'confirm_checked_against_official_text']) },
  'POST /api/v1/certificates': { tag: 'actions', summary: 'Prepare a Section 63 worksheet over verified records', body: obj({ case_id: uuid, attempt_ids: arr(uuid, { minItems: 1, maxItems: 50 }), part: enm('A', 'B', 'A_and_B') }, ['case_id', 'attempt_ids', 'part']) },
  'GET /api/v1/certificates': { tag: 'actions', summary: 'Worksheets in my cases', query: CASE_LIST },
  'GET /api/v1/certificates/:id': { tag: 'actions', summary: 'Worksheet with fields, gaps and template verification state' },
  'PATCH /api/v1/certificates/:id/worksheet': { tag: 'actions', summary: 'Enter worksheet values or mark them unknown (a person must decide)', body: obj({ expected_version: int(), edits: { type: 'object', additionalProperties: obj({ value: {}, marked_unknown: bool }, ['value']) } }, ['expected_version', 'edits']) },
  'POST /api/v1/certificates/:id/transition': { tag: 'actions', summary: 'complete, reopen, record_signed (upload), record_submission, withdraw', body: obj({ action: enm('complete', 'reopen', 'record_signed', 'record_submission', 'withdraw'), upload_id: uuid, submission: obj({ authority: str(), reference: str(), submitted_at: str({ format: 'date-time' }), note: str() }, ['authority', 'reference', 'submitted_at']), note: str() }, ['action']) },
  'GET /api/v1/certificates/:id/files/:kind': { tag: 'actions', summary: 'Download fact-sheet, hash-report or the draft worksheet', download: 'application/octet-stream' },

  // ---- Monitoring
  'POST /api/v1/monitoring/rules': { tag: 'monitoring', summary: 'Schedule proportionate revisits of a target', body: obj({ target_id: int(), case_id: uuid, interval_hours: { type: 'number' }, duration_days: int(), capture_variant: enm('desktop', 'mobile'), notice_id: uuid, reason }, ['target_id', 'case_id', 'reason']) },
  'GET /api/v1/monitoring/rules': { tag: 'monitoring', summary: 'Revisit schedules with latest outcome', query: CASE_LIST },
  'POST /api/v1/monitoring/rules/:id/stop': { tag: 'monitoring', summary: 'Stop revisits', body: obj({ reason }, ['reason']) },
  'POST /api/v1/monitoring/rules/:id/observations': { tag: 'monitoring', summary: 'Record a reported removal or provider-confirmed suspension (with acknowledgement upload)', body: obj({ outcome_class: enm('reported_removal', 'provider_confirmed_suspension'), note: str({ minLength: 5 }), upload_id: uuid }, ['outcome_class', 'note']) },
  'GET /api/v1/monitoring/alerts': { tag: 'monitoring', summary: 'Reappearance alerts (leads, not attribution)' },
  'POST /api/v1/monitoring/alerts/:id/acknowledge': { tag: 'monitoring', summary: 'Acknowledge a reappearance alert' },

  // ---- Operations
  'GET /api/v1/analytics': { tag: 'ops', summary: 'Observed, inferred, confirmed and actioned figures with definitions and denominators', query: [['days', 'Window, 1-90 days'], ['case_ref', 'Restrict to one case']] },
  'GET /api/v1/metrics': { tag: 'ops', summary: 'Prometheus metrics (bearer token or admin/auditor session)', download: 'text/plain' },
};

/** Build the OpenAPI 3.1 document from the live route table plus ROUTE_DOCS. */
export function buildOpenApi(routes: { method: string; path: string; auth: string; roles: string[]; body: 'json' | 'raw' | 'none'; csrf: boolean; rateBucket: string }[], version: string): Record<string, unknown> {
  const paths: Record<string, Record<string, unknown>> = {};
  const errors = {
    400: { $ref: '#/components/responses/Error' }, 401: { $ref: '#/components/responses/Error' }, 403: { $ref: '#/components/responses/Error' },
    404: { $ref: '#/components/responses/Error' }, 409: { $ref: '#/components/responses/Error' }, 429: { $ref: '#/components/responses/Error' },
  };
  for (const r of [...routes].sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method))) {
    const key = `${r.method} ${r.path}`;
    const doc = ROUTE_DOCS[key];
    if (!doc) throw new Error(`undocumented route: ${key}`);
    const oaPath = r.path.replace(/:([A-Za-z]+)/g, '{$1}');
    const params = [
      ...[...r.path.matchAll(/:([A-Za-z]+)/g)].map((m) => ({ name: m[1], in: 'path', required: true, schema: { type: 'string' } })),
      ...(doc.query ?? []).map(([name, description, required]) => ({ name, in: 'query', required: Boolean(required), description, schema: { type: 'string' } })),
      ...(r.csrf ? [{ $ref: '#/components/parameters/Csrf' }] : []),
    ];
    const op: Record<string, unknown> = {
      operationId: `${r.method.toLowerCase()}${oaPath.replace(/\/api\/v1/, '').replace(/[{}]/g, '').split(/[/-]/).filter(Boolean).map((p) => p[0]!.toUpperCase() + p.slice(1)).join('')}`,
      tags: [doc.tag], summary: doc.summary, ...(doc.description ? { description: doc.description } : {}),
      security: r.auth === 'none' ? [] : [{ session: [] }],
      'x-auth-level': r.auth, 'x-roles': r.roles, 'x-rate-bucket': r.rateBucket,
      ...(params.length ? { parameters: params } : {}),
      responses: { 200: doc.download ? { description: 'Download', content: { [doc.download]: { schema: { type: 'string', format: 'binary' } } } } : { description: 'OK', content: { 'application/json': { schema: { type: 'object' } } } }, ...errors },
    };
    if (r.body === 'json' && doc.body) op.requestBody = { required: true, content: { 'application/json': { schema: doc.body } } };
    if (r.body === 'raw') op.requestBody = { required: true, content: Object.fromEntries((doc.rawTypes ?? ['application/octet-stream']).map((t) => [t, { schema: { type: 'string', format: 'binary' } }])) };
    (paths[oaPath] ??= {})[r.method.toLowerCase()] = op;
  }
  return {
    openapi: '3.1.0',
    info: {
      title: 'Cyber Web Collector analyst API', version,
      description: 'Loopback-only analyst API (reach it through an SSH tunnel). Session cookie plus X-CSRF-Token on every mutation; MFA and case-membership authorisation. Objects outside your cases return 404. Generated from the live route table by `npm run openapi`.',
    },
    servers: [{ url: 'http://localhost:8080', description: 'SSH tunnel to the collector VM' }],
    tags: ['auth', 'admin', 'cases', 'jobs', 'evidence', 'investigation', 'actions', 'monitoring', 'ops'].map((name) => ({ name })),
    paths,
    components: {
      securitySchemes: { session: { type: 'apiKey', in: 'cookie', name: 'cwc_session', description: 'HttpOnly, SameSite=Strict session cookie set by the sign-in steps.' } },
      parameters: { Csrf: { name: 'X-CSRF-Token', in: 'header', required: true, description: 'Token returned by sign-in and /auth/me.', schema: { type: 'string' } } },
      responses: { Error: { description: 'Error', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } } },
      schemas: { Error: obj({ error: obj({ code: str(), message: str(), request_id: str(), details: {} }, ['code', 'message']) }, ['error']) },
    },
  };
}
