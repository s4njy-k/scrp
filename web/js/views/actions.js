// Legally routed notices, report drafts and Section 63 worksheets (blueprint v4
// §22.1 /reports, §24.3, §26). Nothing here sends anything: issuance is an
// authorised human act recorded afterwards with proof.
import { api, chip, clear, dialogForm, download, errorText, field, get, guard, h, hasRole, kv, patch, post, shortHash, skeleton, state, toast, when } from '../lib.js';

const RECIPIENT_KINDS = ['government_nodal', 'intermediary', 'registrar', 'registry', 'hosting_provider', 'cdn', 'app_distributor', 'record_holder', 'bank_or_psp', 'investigating_officer'];
const NOTICE_TEXT_FIELDS = [
  ['reference_no', 'Reference number', 'text'], ['legal_basis', 'Legal basis (statute, rule, policy clause)', 'textarea'], ['authority_ref', 'Authority / authorisation reference', 'text'],
  ['issuing_authority', 'Issuing authority', 'text'], ['signatory_name', 'Signatory name', 'text'], ['signatory_designation', 'Signatory designation', 'text'], ['jurisdiction', 'Jurisdiction', 'text'],
  ['facts_summary', 'Facts observed (observations, not unproven allegations)', 'textarea'], ['requested_action', 'Requested action (precise and bounded)', 'textarea'],
  ['necessity_note', 'Necessity', 'textarea'], ['proportionality_note', 'Proportionality', 'textarea'], ['lawful_deadline', 'Lawful deadline, if any (as stated in law or order)', 'text'],
];
const BOOL_ROUTE_FIELDS = new Set(['current_rules_verified', 'cross_border']);
const label = (s) => s.replace(/_/g, ' ');
const query = () => new URLSearchParams(location.hash.split('?')[1] ?? '');

/** Upload a proof document to the case and return its id (null if cancelled). */
async function uploadDialog(caseId, purpose, title) {
  const dlg = document.getElementById('dialog');
  return new Promise((resolve) => {
    const file = h('input', { type: 'file', accept: 'application/pdf,image/png,image/jpeg,text/plain', required: true });
    const note = h('input', { type: 'text', maxlength: 1000 });
    const msg = h('p', { role: 'alert', class: 'muted small' });
    const form = h('form', { class: 'stack', onsubmit: async (ev) => {
      ev.preventDefault();
      const f = file.files?.[0];
      if (!f) return;
      try {
        const p = new URLSearchParams({ purpose, filename: f.name });
        if (note.value) p.set('note', note.value);
        const r = await api('POST', `/api/v1/cases/${caseId}/uploads?${p}`, undefined, { raw: f, contentType: f.type || 'application/octet-stream' });
        toast(`Stored · SHA-256 ${shortHash(r.sha256)}`);
        dlg.close();
        resolve(r.id);
      } catch (e) { msg.textContent = errorText(e); }
    } },
    h('h2', { id: 'dialog-title' }, title), h('p', { class: 'muted small' }, `Purpose: ${label(purpose)}. PDF, PNG, JPEG or plain text; the file is hashed and stored read-only.`),
    field('File', file), field('Note (optional)', note), msg,
    h('div', { class: 'row' }, h('button', { type: 'submit', class: 'primary' }, 'Upload'), h('button', { type: 'button', onclick: () => { dlg.close(); resolve(null); } }, 'Cancel')));
    clear(dlg, form);
    dlg.addEventListener('cancel', () => resolve(null), { once: true });
    dlg.showModal();
  });
}

const toIso = (local) => (local ? new Date(local).toISOString() : undefined);

// ---------------------------------------------------------------- Reports list

export async function noticesView(main) {
  clear(main, skeleton(4));
  const stateSel = h('select', {}, h('option', { value: '' }, 'All states'), ...['draft', 'analyst_review', 'legal_check', 'approved', 'generated', 'issued', 'acknowledged', 'complied', 'partially_complied', 'rejected', 'no_response', 'verified_closed', 'escalated', 'withdrawn', 'disputed'].map((s) => h('option', { value: s }, label(s))));
  const body = h('tbody');
  const load = async () => {
    const r = await get(`/api/v1/notices${stateSel.value ? `?state=${stateSel.value}` : ''}`);
    clear(body, ...(r.items.length ? r.items.map((n) => h('tr', { tabindex: 0, onclick: () => { location.hash = `#/notices/${n.id}`; }, onkeydown: (e) => { if (e.key === 'Enter') location.hash = `#/notices/${n.id}`; } },
      h('td', { class: 'mono small' }, n.case_ref), h('td', {}, label(n.route)), h('td', {}, chip(n.state)), h('td', {}, n.recipient?.name ?? '—', h('div', { class: 'small muted' }, label(n.recipient?.kind ?? ''))),
      h('td', { class: 'right' }, n.target_count), h('td', { class: 'small' }, when(n.created_at), h('div', { class: 'muted' }, n.created_by)),
      h('td', { class: 'small' }, n.internal_followup_at ? [when(n.internal_followup_at), h('div', { class: 'muted' }, 'internal follow-up, not a legal deadline')] : '—'))) : [h('tr', {}, h('td', { colspan: 7, class: 'muted' }, 'No notices.'))]));
  };
  stateSel.addEventListener('change', () => void load());

  const [certs, templates, routes] = await Promise.all([get('/api/v1/certificates'), get('/api/v1/templates'), get('/api/v1/legal-routes')]);
  const tpl = templates.templates[0];
  clear(main,
    h('div', { class: 'row' }, h('h1', { class: 'grow' }, 'Reports and notices'), hasRole('analyst', 'approver') ? h('a', { class: 'btn primary', href: '#/reports/new' }, 'Draft a notice') : null),
    h('div', { class: 'banner info small' }, 'Drafts are prepared here and approved by a different person. The system never sends, signs or takes down anything.'),
    h('div', { class: 'panel row' }, h('div', { class: 'grow' }, field('State', stateSel))),
    h('div', { class: 'panel tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, ...['Case', 'Route', 'State', 'Recipient', 'Targets', 'Created', 'Follow-up'].map((t) => h('th', {}, t)))), body)),
    h('div', { class: 'panel' }, h('div', { class: 'row' }, h('h2', { class: 'grow' }, 'Section 63 certificate worksheets'),
      hasRole('analyst', 'evidence', 'approver') ? h('button', { type: 'button', onclick: () => newCertificate() }, 'Prepare worksheet') : null),
      h('p', { class: 'small muted' }, `Template ${tpl.id} · source version ${tpl.version} · `, tpl.verifications.length ? `checked against the official text by ${tpl.verifications[0].verified_by} on ` : 'NOT yet checked against the official text', tpl.verifications.length ? when(tpl.verifications[0].verified_at) : null),
      !tpl.verifications.length && hasRole('approver', 'admin') ? h('button', { type: 'button', onclick: async () => {
        const r = await dialogForm('Record template verification', [
          { name: 'source_reference', label: 'Official source checked (gazette / India Code reference and date)', required: true },
          { name: 'note', label: 'Note', type: 'textarea' },
          { name: 'confirm', label: 'I compared every Part A and Part B field with the official Schedule text', type: 'checkbox', required: true },
        ], 'Record');
        if (r) { await guard(() => post(`/api/v1/templates/${tpl.id}/verify`, { source_reference: r.source_reference, ...(r.note ? { note: r.note } : {}), confirm_checked_against_official_text: true }), 'Verification recorded'); void noticesView(main); }
      } }, 'Record template verification') : null,
      certs.items.length ? h('table', {}, h('thead', {}, h('tr', {}, ...['Case', 'Part', 'State', 'Records', 'Prepared'].map((t) => h('th', {}, t)))),
        h('tbody', {}, ...certs.items.map((c) => h('tr', { tabindex: 0, onclick: () => { location.hash = `#/certificates/${c.id}`; } }, h('td', { class: 'mono small' }, c.case_ref), h('td', {}, label(c.part)), h('td', {}, chip(c.state === 'completed' || c.state === 'signed' ? 'approved' : c.state === 'attached_to_submission' ? 'complied' : c.state === 'withdrawn' ? 'withdrawn' : 'draft', label(c.state))),
          h('td', { class: 'right' }, c.attempt_count), h('td', { class: 'small' }, when(c.created_at), h('div', { class: 'muted' }, c.prepared_by))))))
        : h('p', { class: 'muted' }, 'No worksheets.')),
    h('details', { class: 'panel' }, h('summary', {}, 'Legal routes reference'), h('p', { class: 'small muted' }, routes.disclaimer),
      ...routes.routes.map((r) => h('div', { class: 'routecard' }, h('h3', {}, r.title), h('p', { class: 'small' }, r.nature), h('p', { class: 'small' }, h('strong', {}, 'Guardrail: '), r.guardrail),
        r.timing_note ? h('p', { class: 'small muted' }, r.timing_note) : null, h('p', { class: 'small muted' }, `Recipients: ${r.recipientKinds.map(label).join(', ')}`)))));
  await load();
}

async function newCertificate(prefill = {}) {
  const cases = (await get('/api/v1/cases?limit=200&status=open')).items;
  if (!cases.length) { toast('No open case available', 'bad'); return; }
  const r = await dialogForm('Prepare a Section 63 worksheet', [
    { name: 'case_id', label: 'Case', type: 'select', options: cases.map((c) => ({ value: c.id, label: c.case_ref })), value: prefill.case_id },
    { name: 'part', label: 'Part', type: 'select', options: [{ value: 'A', label: 'Part A (party producing the record)' }, { value: 'B', label: 'Part B (expert)' }, { value: 'A_and_B', label: 'Parts A and B' }] },
    { name: 'attempts', label: 'Capture (attempt) IDs, one per line', type: 'textarea', required: true, value: (prefill.attempt_ids ?? []).join('\n') },
  ], 'Verify evidence and prepare', { intro: 'The cited records are hash-verified first. The worksheet pre-fills only computed facts (hashes); every personal particular and declaration is left for the signatory.' });
  if (!r) return;
  const ids = r.attempts.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
  const c = await guard(() => post('/api/v1/certificates', { case_id: r.case_id, attempt_ids: ids, part: r.part }), 'Worksheet prepared');
  if (c) location.hash = `#/certificates/${c.id}`;
}

// ---------------------------------------------------------------- New notice

export async function newNoticeView(main) {
  clear(main, skeleton(4));
  const q = query();
  const [routes, casesR] = await Promise.all([get('/api/v1/legal-routes'), get('/api/v1/cases?limit=200&status=open')]);
  let cases = casesR.items.filter((c) => c.my_role !== 'viewer');
  const preTarget = q.get('target') ? Number(q.get('target')) : null;
  if (preTarget) {
    const inv = await get(`/api/v1/targets/${preTarget}/investigation`).catch(() => null);
    if (inv) cases = cases.filter((c) => inv.case_refs.includes(c.case_ref));
  }
  if (!cases.length) {
    clear(main, h('div', { class: 'banner warn' }, 'No open case you investigate contains this target. Link the target to a case first.'));
    return;
  }
  const caseSel = h('select', {}, ...cases.map((c) => h('option', { value: c.id, selected: c.id === q.get('case') }, `${c.case_ref} — ${c.title}`)));
  const routeSel = h('select', {}, ...routes.routes.map((r) => h('option', { value: r.id }, r.title)));
  const routeInfo = h('div');
  const routeFieldsBox = h('div', { class: 'stack' });
  const targetsBox = h('div', { class: 'stack' });
  const recipientName = h('input', { type: 'text', required: true, maxlength: 300 });
  const recipientKind = h('select');
  const recipientContact = h('input', { type: 'text', maxlength: 300 });
  const recipientJur = h('input', { type: 'text', maxlength: 300 });
  const language = h('select', {}, h('option', { value: 'en' }, 'English'), h('option', { value: 'hi' }, 'Hindi'), h('option', { value: 'en_hi' }, 'English and Hindi'));
  const followup = h('input', { type: 'datetime-local' });
  const inputs = Object.fromEntries(NOTICE_TEXT_FIELDS.map(([k, , t]) => [k, t === 'textarea' ? h('textarea', { rows: 3 }) : h('input', { type: 'text' })]));
  const routeInputs = {};
  const targetChecks = new Map();
  const msg = h('div', { role: 'alert' });

  const renderRoute = () => {
    const r = routes.routes.find((x) => x.id === routeSel.value);
    clear(routeInfo, h('div', { class: 'banner info small' }, h('strong', {}, r.nature), h('div', {}, `Guardrail: ${r.guardrail}`), r.timing_note ? h('div', { class: 'muted' }, r.timing_note) : null));
    clear(recipientKind, ...r.recipientKinds.map((k) => h('option', { value: k }, label(k))));
    for (const [k] of NOTICE_TEXT_FIELDS) inputs[k].closest?.('div')?.classList.toggle('required', ['facts_summary', 'requested_action', ...r.requiredFields].includes(k));
    for (const key of Object.keys(routeInputs)) delete routeInputs[key];
    const extra = [...r.requiredRouteFields, ...(r.id === 'bnss_94_production' ? ['lawful_channel_note'] : [])];
    clear(routeFieldsBox, ...extra.map((k) => {
      let el;
      if (k === 'ground_69a') el = h('select', {}, h('option', { value: '' }, '— select the prescribed ground —'), ...Object.entries(routes.section_69a_grounds).map(([v, l]) => h('option', { value: v }, l)));
      else if (BOOL_ROUTE_FIELDS.has(k)) el = h('input', { type: 'checkbox' });
      else el = h('textarea', { rows: 2 });
      routeInputs[k] = el;
      if (BOOL_ROUTE_FIELDS.has(k)) return h('label', { class: 'checkline' }, el, label(k));
      const wrap = field(label(k), el);
      if (r.requiredRouteFields.includes(k)) wrap.classList.add('required');
      return wrap;
    }));
  };
  const loadTargets = async () => {
    const c = cases.find((x) => x.id === caseSel.value);
    clear(targetsBox, skeleton(2));
    targetChecks.clear();
    const jobs = await get(`/api/v1/jobs?case_ref=${encodeURIComponent(c.case_ref)}&top_level=true&limit=200`);
    const seen = new Set();
    clear(targetsBox, ...(jobs.items.length ? jobs.items.filter((j) => !seen.has(j.target_id) && seen.add(j.target_id)).map((j) => {
      const box = h('input', { type: 'checkbox', checked: j.target_id === preTarget });
      const ground = h('input', { type: 'text', placeholder: 'Legal ground for this target (optional)', maxlength: 1000 });
      targetChecks.set(j.target_id, { box, ground });
      return h('div', { class: 'targetpick' }, h('label', { class: 'checkline' }, box, h('span', { class: 'url' }, j.url)), h('span', {}, h('span', { class: 'small muted' }, 'verdict '), chip(j.verdict ?? 'unreviewed')), ground);
    }) : [h('p', { class: 'muted' }, 'This case has no targets yet.')]));
  };
  routeSel.addEventListener('change', renderRoute);
  caseSel.addEventListener('change', () => void loadTargets());

  const submit = async (ev) => {
    ev.preventDefault();
    clear(msg);
    const targets = [...targetChecks.entries()].filter(([, v]) => v.box.checked).map(([id, v]) => ({ target_id: id, ...(v.ground.value.trim() ? { legal_ground: v.ground.value.trim() } : {}) }));
    if (!targets.length) { clear(msg, h('div', { class: 'banner bad' }, 'Select at least one target.')); return; }
    const route_fields = {};
    for (const [k, el] of Object.entries(routeInputs)) {
      if (el.type === 'checkbox') route_fields[k] = el.checked;
      else if (el.value.trim()) route_fields[k] = el.value.trim();
    }
    const body = { case_id: caseSel.value, route: routeSel.value, language: language.value, recipient: { name: recipientName.value.trim(), kind: recipientKind.value, ...(recipientContact.value.trim() ? { contact: recipientContact.value.trim() } : {}), ...(recipientJur.value.trim() ? { jurisdiction: recipientJur.value.trim() } : {}) }, targets, route_fields };
    for (const [k] of NOTICE_TEXT_FIELDS) if (inputs[k].value.trim()) body[k] = inputs[k].value.trim();
    if (followup.value) body.internal_followup_at = toIso(followup.value);
    try {
      const r = await post('/api/v1/notices', body);
      toast('Draft created');
      location.hash = `#/notices/${r.id}`;
    } catch (e) { clear(msg, h('div', { class: 'banner bad' }, errorText(e))); }
  };

  clear(main, h('h1', {}, 'Draft a notice'),
    h('form', { class: 'stack', onsubmit: submit },
      h('div', { class: 'panel stack' }, h('h2', {}, '1. Case and legal route'), field('Case', caseSel), field('Route', routeSel), routeInfo),
      h('div', { class: 'panel stack' }, h('h2', {}, '2. Targets'), h('p', { class: 'small muted' }, 'Each target cites its latest committed browser capture unless you change it later. Targets marked false positive or benign cannot be included.'), targetsBox),
      h('div', { class: 'panel stack' }, h('h2', {}, '3. Recipient'), h('div', { class: 'grid2' }, field('Recipient name', recipientName), field('Recipient kind', recipientKind), field('Contact (address or channel)', recipientContact), field('Recipient jurisdiction', recipientJur))),
      h('div', { class: 'panel stack' }, h('h2', {}, '4. Content'), h('div', { class: 'grid2' }, field('Language', language), field('Internal follow-up (not a legal deadline)', followup)),
        ...NOTICE_TEXT_FIELDS.map(([k, l]) => field(l, inputs[k])), h('h3', {}, 'Route-specific particulars'), routeFieldsBox),
      msg, h('div', { class: 'row' }, h('button', { type: 'submit', class: 'primary' }, 'Save draft'), h('a', { class: 'btn', href: '#/reports' }, 'Cancel'))));
  void RECIPIENT_KINDS;
  renderRoute();
  await loadTargets();
}

// ---------------------------------------------------------------- Notice detail

export async function noticeView(main, noticeId) {
  clear(main, skeleton(5));
  const d = await get(`/api/v1/notices/${noticeId}`);
  const n = d.notice;
  const reload = () => noticeView(main, noticeId);
  const preview = h('div');
  const isAuthor = n.created_by_id === state.user?.id;

  const act = async (action, fields = [], extra = {}, opts = {}) => {
    const r = fields.length || opts.confirm ? await dialogForm(opts.title ?? label(action), fields, opts.submit ?? 'Confirm', { intro: opts.intro, danger: opts.danger }) : {};
    if (r === null) return;
    const body = { action, ...extra };
    if (r.note) body.note = r.note;
    if (opts.map) Object.assign(body, opts.map(r));
    const out = await guard(() => post(`/api/v1/notices/${noticeId}/transition`, body), `Notice: ${label(action)}`);
    if (out) void reload();
  };
  const NOTE = { name: 'note', label: 'Note', type: 'textarea' };
  const REASON = { name: 'note', label: 'Reason (recorded)', type: 'textarea', required: true };
  const buttons = {
    submit: () => act('submit', [NOTE], {}, { title: 'Submit for analyst review' }),
    review_ok: () => act('review_ok', [NOTE], {}, { title: 'Analyst review complete — send to legal check', intro: 'A second analyst confirms the facts and evidence.' }),
    return_to_draft: () => act('return_to_draft', [REASON], {}, { title: 'Return to draft', intro: 'Any approval is cleared and must be given again.' }),
    approve: () => act('approve', [NOTE], {}, { title: 'Approve (checker)', intro: 'Approval freezes a hash of the content and cited evidence. Generation fails if anything changes afterwards.' }),
    generate: () => act('generate', [], {}, { confirm: true, title: 'Generate report pack', intro: 'Produces Markdown, HTML, JSON and CSV files with an evidence package. Nothing is sent.' }),
    record_issued: async () => {
      const r = await dialogForm('Record issuance', [{ name: 'issued_at', label: 'Issued at (local time)', type: 'datetime-local', required: true }, { name: 'channel', label: 'Channel used (portal, email, post …)', required: true }, NOTE], 'Next: upload dispatch proof', { intro: 'Issuance is done by an authorised person outside this system. Record it with proof of dispatch.' });
      if (!r) return;
      const up = await uploadDialog(n.case_id, 'dispatch_proof', 'Proof of dispatch');
      if (!up) return;
      if (await guard(() => post(`/api/v1/notices/${noticeId}/transition`, { action: 'record_issued', issued_at: toIso(r.issued_at), issue_channel: r.channel, dispatch_upload_id: up, ...(r.note ? { note: r.note } : {}) }), 'Issuance recorded')) void reload();
    },
    record_acknowledged: async () => {
      const r = await dialogForm('Record documented receipt', [{ name: 'received_at', label: 'Received at (local time)', type: 'datetime-local', required: true }, { name: 'purpose', label: 'Proof type', type: 'select', options: ['receipt_proof', 'provider_acknowledgement'] }, NOTE], 'Next: upload proof', { intro: 'Legal response periods run only from documented receipt.' });
      if (!r) return;
      const up = await uploadDialog(n.case_id, r.purpose, 'Receipt or acknowledgement');
      if (!up) return;
      if (await guard(() => post(`/api/v1/notices/${noticeId}/transition`, { action: 'record_acknowledged', received_at: toIso(r.received_at), receipt_upload_id: up, ...(r.note ? { note: r.note } : {}) }), 'Receipt recorded')) void reload();
    },
    record_outcome: () => act('record_outcome', [{ name: 'outcome', label: 'Outcome reported', type: 'select', options: ['complied', 'partially_complied', 'rejected', 'no_response'] },
      ...d.targets.map((t) => ({ name: `t_${t.target_id}`, label: `Status of ${t.url}`, type: 'select', options: ['', 'acted_upon', 'not_acted', 'disputed', 'withdrawn', 'still_live'], value: '' })), NOTE], {},
    { title: 'Record outcome', intro: 'A reported outcome is not verified removal. Use a monitoring revisit to verify before closing.', map: (r) => ({ outcome: r.outcome, target_statuses: d.targets.filter((t) => r[`t_${t.target_id}`]).map((t) => ({ target_id: t.target_id, status: r[`t_${t.target_id}`] })) }) }),
    close: () => act('close', [{ name: 'close_as', label: 'Close as', type: 'select', options: ['verified_closed', 'escalated'] }, NOTE], {}, { title: 'Close notice', intro: 'Verified closure needs a fresh capture taken after issuance.', map: (r) => ({ close_as: r.close_as }) }),
    withdraw: () => act('withdraw', [REASON], {}, { title: 'Withdraw notice', danger: true, submit: 'Withdraw' }),
    dispute: () => act('dispute', [REASON], {}, { title: 'Record a dispute', danger: true }),
  };
  const BUTTON_LABEL = { submit: 'Submit for review', review_ok: 'Review complete', return_to_draft: 'Return to draft', approve: 'Approve', generate: 'Generate report pack', record_issued: 'Record issuance', record_acknowledged: 'Record receipt', record_outcome: 'Record outcome', close: 'Close', withdraw: 'Withdraw', dispute: 'Record dispute' };
  const ROLE_FOR = { submit: ['analyst', 'approver', 'admin'], review_ok: ['analyst', 'approver', 'admin'], return_to_draft: ['analyst', 'approver', 'admin'], approve: ['approver'], generate: ['approver', 'report'], record_issued: ['approver', 'report'], record_acknowledged: ['approver', 'report', 'analyst'], record_outcome: ['approver', 'report', 'analyst'], close: ['approver', 'admin'], withdraw: ['analyst', 'approver', 'admin'], dispute: ['approver', 'admin'] };
  const makerChecker = new Set(['review_ok', 'approve']);

  const edit = async () => {
    const r = await dialogForm('Edit draft', [
      ...NOTICE_TEXT_FIELDS.map(([k, l, t]) => ({ name: k, label: l, type: t === 'textarea' ? 'textarea' : 'text', value: n[k] ?? '' })),
      { name: 'recipient_name', label: 'Recipient name', value: n.recipient?.name ?? '', required: true },
      { name: 'recipient_contact', label: 'Recipient contact', value: n.recipient?.contact ?? '' },
      ...d.route.requiredRouteFields.map((k) => (BOOL_ROUTE_FIELDS.has(k) ? { name: `rf_${k}`, label: label(k), type: 'checkbox', value: n.route_fields?.[k] === true } : { name: `rf_${k}`, label: label(k), type: 'textarea', value: n.route_fields?.[k] ?? '' })),
    ], 'Save');
    if (!r) return;
    const body = { expected_version: n.version, recipient: { ...n.recipient, name: r.recipient_name, ...(r.recipient_contact ? { contact: r.recipient_contact } : {}) }, route_fields: { ...n.route_fields } };
    if (!r.recipient_contact) delete body.recipient.contact;
    for (const [k] of NOTICE_TEXT_FIELDS) if (r[k] !== (n[k] ?? '')) body[k] = r[k];
    for (const k of d.route.requiredRouteFields) body.route_fields[k] = BOOL_ROUTE_FIELDS.has(k) ? r[`rf_${k}`] : r[`rf_${k}`].trim();
    if (await guard(() => patch(`/api/v1/notices/${noticeId}`, body), 'Draft saved')) void reload();
  };

  const failing = d.eligibility.filter((c) => !c.ok);
  clear(main,
    h('div', { class: 'panel' },
      h('div', { class: 'row' }, h('h1', { class: 'grow' }, d.route.title), chip(n.state)),
      h('p', { class: 'small muted' }, h('a', { href: `#/cases/${n.case_id}` }, d.case_ref), ` · drafted by ${n.created_by}`, n.approved_by ? ` · approved by ${n.approved_by}` : '', n.approved_snapshot_sha256 ? ` · approval snapshot ${shortHash(n.approved_snapshot_sha256)}` : ''),
      h('div', { class: 'banner info small' }, `Guardrail: ${d.route.guardrail}`),
      kv([['Recipient', `${n.recipient?.name ?? '—'} (${label(n.recipient?.kind ?? '')})${n.recipient?.contact ? ` · ${n.recipient.contact}` : ''}`], ['Reference', n.reference_no], ['Legal basis', n.legal_basis], ['Authority', n.authority_ref],
        ['Issuing authority', n.issuing_authority], ['Signatory', n.signatory_name ? `${n.signatory_name}, ${n.signatory_designation ?? ''}` : null], ['Jurisdiction', n.jurisdiction], ['Facts observed', n.facts_summary], ['Requested action', n.requested_action],
        ['Necessity', n.necessity_note], ['Proportionality', n.proportionality_note], ['Lawful deadline', n.lawful_deadline],
        ...Object.entries(n.route_fields ?? {}).map(([k, v]) => [label(k), typeof v === 'boolean' ? (v ? 'yes' : 'no') : Array.isArray(v) ? v.join(', ') : String(v)]),
        ['Issued', n.issued_at ? when(n.issued_at) : null], ['Documented receipt', n.received_at ? when(n.received_at) : null],
        ['Internal follow-up', n.internal_followup_at ? [when(n.internal_followup_at), ' (internal target, not a legal deadline)'] : null]]),
      h('div', { class: 'row wrap' },
        n.state === 'draft' && hasRole('analyst', 'approver', 'admin') ? h('button', { type: 'button', onclick: edit }, 'Edit draft') : null,
        ...d.transitions.filter((t) => hasRole(...ROLE_FOR[t])).map((t) => {
          const blockedByMc = makerChecker.has(t) && isAuthor;
          return h('button', { type: 'button', class: ['approve', 'generate', 'submit'].includes(t) ? 'primary' : ['withdraw', 'dispute'].includes(t) ? 'danger' : '', disabled: blockedByMc, title: blockedByMc ? 'Maker-checker: the author cannot review or approve their own notice' : '', onclick: buttons[t] }, BUTTON_LABEL[t]);
        }),
        h('button', { type: 'button', onclick: async () => {
          const r = await guard(() => post('/api/v1/reports/notice/preview', { notice_id: noticeId, format: 'markdown' }));
          if (r) clear(preview, h('div', { class: 'panel' }, h('h2', {}, 'Preview (not saved, not sent)'), h('pre', { class: 'preview' }, r.content)));
        } }, 'Preview'),
        hasRole('analyst', 'evidence', 'approver') ? h('button', { type: 'button', onclick: () => newCertificate({ case_id: n.case_id, attempt_ids: [...new Set(d.targets.flatMap((t) => t.evidence_attempts))] }) }, 'Prepare s.63 worksheet') : null)),
    h('div', { class: 'panel' }, h('h2', {}, 'Eligibility checks'),
      failing.length ? h('p', { class: 'small' }, `${d.blocking.length} blocking issue(s).`) : h('p', { class: 'small' }, 'All checks pass for the current stage.'),
      h('ul', { class: 'checks' }, ...d.eligibility.map((c) => h('li', { class: c.ok ? 'ok' : c.blocking ? 'bad' : 'warn' }, h('span', { class: 'mark', 'aria-hidden': 'true' }, c.ok ? '✓' : c.blocking ? '✕' : '!'), ' ', c.message)))),
    h('div', { class: 'panel tablewrap' }, h('h2', {}, 'Targets and cited evidence'),
      h('table', {}, h('thead', {}, h('tr', {}, ...['Target', 'Verdict', 'Evidence', 'Status', 'Legal ground'].map((t) => h('th', {}, t)))),
        h('tbody', {}, ...d.targets.map((t) => h('tr', {}, h('td', { class: 'url' }, h('a', { href: `#/investigate/${t.target_id}` }, t.url), t.suppressed ? h('span', { class: 'chip bad' }, 'suppressed') : null),
          h('td', {}, chip(t.verdict ?? 'unreviewed')), h('td', {}, chip(t.evidence_ok ? 'verified' : 'mismatch', t.evidence_ok ? 'verifies' : 'problem'), ...t.evidence_attempts.map((a) => h('div', {}, h('a', { class: 'mono small', href: `#/evidence/${a}` }, a.slice(0, 8))))),
          h('td', {}, label(t.target_status ?? 'pending')), h('td', { class: 'small' }, t.legal_ground ?? '—')))))),
    d.reports.length ? h('div', { class: 'panel' }, h('h2', {}, 'Generated report packs'), ...d.reports.map((rep) => h('div', { class: 'stack' },
      h('p', { class: 'small' }, `Generated by ${rep.generated_by} `, when(rep.generated_at), ` · index SHA-256 ${shortHash(rep.index_sha256)} · approval snapshot ${shortHash(rep.snapshot_sha256)}`),
      h('div', { class: 'row wrap' }, ...rep.files.map((f) => h('button', { type: 'button', title: `SHA-256 ${f.sha256}`, onclick: () => download(`/api/v1/notices/${noticeId}/reports/${rep.id}/${f.path}`, `notice-${noticeId.slice(0, 8)}-${f.path}`) }, f.path)),
        rep.evidence_package_id && hasRole('evidence', 'admin') ? h('button', { type: 'button', onclick: () => download(`/api/v1/packages/${rep.evidence_package_id}/archive`, `evidence-package-${rep.evidence_package_id}.tar`) }, 'Evidence package (.tar)') : null)))) : null,
    preview,
    h('div', { class: 'panel' }, h('h2', {}, 'History'), h('ul', { class: 'timeline' }, ...d.events.map((e) => h('li', { class: 'small' }, when(e.at), ` ${e.from_state ? `${label(e.from_state)} → ` : ''}${label(e.to_state)} by ${e.actor}`, e.note ? h('div', { class: 'muted' }, e.note) : null)))));
}

// ---------------------------------------------------------------- Certificate worksheet

export async function certificateView(main, certId) {
  clear(main, skeleton(5));
  const d = await get(`/api/v1/certificates/${certId}`);
  const c = d.certificate;
  const reload = () => certificateView(main, certId);
  const editable = c.state === 'draft' && hasRole('analyst', 'evidence', 'approver');
  const edits = {};
  const gapSet = new Set(d.gaps);

  const fieldRow = (f) => {
    const cur = c.worksheet[f.key] ?? { value: null, source: 'blank' };
    const unknownBox = h('input', { type: 'checkbox', checked: cur.marked_unknown, disabled: !editable });
    let input;
    if (f.kind === 'choice') input = h('select', { disabled: !editable }, h('option', { value: '' }, '—'), ...f.options.map((o) => h('option', { value: o, selected: cur.value === o }, o)));
    else if (f.kind === 'multi') input = h('div', { class: 'row wrap' }, ...f.options.map((o) => h('label', { class: 'checkline' }, h('input', { type: 'checkbox', value: o, checked: Array.isArray(cur.value) && cur.value.includes(o), disabled: !editable }), o)));
    else if (f.kind === 'declaration') input = h('select', { disabled: !editable }, h('option', { value: '' }, '— to be affirmed by the signatory —'), h('option', { value: 'true', selected: cur.value === true }, 'Affirmed'), h('option', { value: 'false', selected: cur.value === false }, 'Not affirmed'));
    else input = h('input', { type: 'text', value: Array.isArray(cur.value) ? cur.value.join(', ') : cur.value ?? '', disabled: !editable, placeholder: f.kind === 'date' ? 'DD/MM/YYYY' : f.kind === 'time' ? 'hh:mm (IST)' : '' });
    const read = () => {
      if (unknownBox.checked) return { value: null, marked_unknown: true };
      if (f.kind === 'multi') { const v = [...input.querySelectorAll('input:checked')].map((x) => x.value); return { value: v.length ? v : null }; }
      if (f.kind === 'declaration') return { value: input.value === '' ? null : input.value === 'true' };
      return { value: input.value.trim() === '' ? null : input.value.trim() };
    };
    const mark = () => { edits[f.key] = read(); };
    input.addEventListener('change', mark);
    unknownBox.addEventListener('change', mark);
    return h('div', { class: `wsfield${gapSet.has(f.key) ? ' gap' : ''}` },
      h('div', { class: 'wslabel' }, f.label, f.personal ? h('span', { class: 'chip warn' }, 'signatory only') : null, cur.source === 'system_proposed' ? h('span', { class: 'chip info' }, 'system proposal — confirm') : null),
      input, h('label', { class: 'checkline small' }, unknownBox, 'Unknown / not applicable (a person must decide)'),
      cur.entered_by ? h('div', { class: 'small muted' }, `entered by ${cur.entered_by} `, when(cur.entered_at)) : null);
  };

  const save = async () => {
    if (!Object.keys(edits).length) { toast('Nothing changed'); return; }
    const r = await guard(() => patch(`/api/v1/certificates/${certId}/worksheet`, { expected_version: c.version, edits }), 'Worksheet saved');
    if (r) void reload();
  };
  const transition = async (action, body = {}) => {
    const r = await guard(() => post(`/api/v1/certificates/${certId}/transition`, { action, ...body }), `Worksheet: ${label(action)}`);
    if (r) void reload();
  };
  const parts = c.part === 'A_and_B' ? ['A', 'B'] : [c.part];
  clear(main,
    h('div', { class: 'panel' },
      h('div', { class: 'row' }, h('h1', { class: 'grow' }, `Section 63(4)(c) worksheet — ${c.part === 'A_and_B' ? 'Parts A and B' : `Part ${c.part}`}`), chip(c.state === 'draft' ? 'draft' : c.state === 'withdrawn' ? 'withdrawn' : 'approved', label(c.state))),
      h('div', { class: 'banner warn small' }, d.notice),
      !d.template_verified ? h('div', { class: 'banner bad small' }, 'The Schedule template has not been checked against the official text for this version. Completion is blocked until an approver records that check (Reports page).') : null,
      kv([['Template source', d.template_source], ['Records cited', `${c.attempt_ids.length} capture(s)`], ['Fact sheet SHA-256', h('span', { class: 'mono' }, c.fact_sheet_sha256)], ['Hash report SHA-256', h('span', { class: 'mono' }, c.hash_report_sha256)],
        ['Prepared by', c.prepared_by], ['Completed', c.completed_at ? [c.completed_by, ' · ', when(c.completed_at)] : null], ['Signed copy recorded', c.signed_recorded_at ? when(c.signed_recorded_at) : null],
        ['Submissions', (c.submissions ?? []).map((s) => `${s.authority} · ${s.reference} · ${s.submitted_at_ist}`).join('\n') || null]]),
      h('div', { class: 'row wrap' },
        h('button', { type: 'button', onclick: () => download(`/api/v1/certificates/${certId}/files/fact-sheet`, `certificate-${certId.slice(0, 8)}-fact-sheet.md`) }, 'Fact sheet'),
        h('button', { type: 'button', onclick: () => download(`/api/v1/certificates/${certId}/files/hash-report`, `certificate-${certId.slice(0, 8)}-hash-report.json`) }, 'Hash report'),
        h('button', { type: 'button', onclick: () => download(`/api/v1/certificates/${certId}/files/worksheet`, `certificate-${certId.slice(0, 8)}-worksheet.md`) }, 'Worksheet (draft)'),
        editable ? h('button', { type: 'button', class: 'primary', onclick: save }, 'Save changes') : null,
        c.state === 'draft' && hasRole('analyst', 'evidence', 'approver') ? h('button', { type: 'button', disabled: d.gaps.length > 0 || !d.template_verified, title: d.gaps.length ? `${d.gaps.length} field(s) still need a person's entry or an explicit unknown` : '', onclick: () => transition('complete') }, 'Mark completed') : null,
        c.state === 'completed' ? h('button', { type: 'button', onclick: () => transition('reopen') }, 'Reopen') : null,
        c.state === 'completed' ? h('button', { type: 'button', class: 'primary', onclick: async () => {
          const up = await uploadDialog(c.case_id, 'signed_certificate', 'Signed certificate (as signed by the responsible persons)');
          if (up) await transition('record_signed', { upload_id: up });
        } }, 'Record signed copy') : null,
        c.state === 'signed' || c.state === 'attached_to_submission' ? h('button', { type: 'button', onclick: async () => {
          const r = await dialogForm('Record submission', [{ name: 'authority', label: 'Court / authority', required: true }, { name: 'reference', label: 'Reference', required: true }, { name: 'submitted_at', label: 'Submitted at (local time)', type: 'datetime-local', required: true }, { name: 'note', label: 'Note' }], 'Record');
          if (r) await transition('record_submission', { submission: { authority: r.authority, reference: r.reference, submitted_at: toIso(r.submitted_at), ...(r.note ? { note: r.note } : {}) } });
        } }, 'Record submission') : null,
        c.state !== 'attached_to_submission' && c.state !== 'withdrawn' ? h('button', { type: 'button', class: 'danger', onclick: async () => {
          const r = await dialogForm('Withdraw worksheet', [{ name: 'note', label: 'Reason', type: 'textarea', required: true }], 'Withdraw', { danger: true });
          if (r) await transition('withdraw', { note: r.note });
        } }, 'Withdraw') : null)),
    d.gaps.length ? h('div', { class: 'banner warn' }, `${d.gaps.length} field(s) still need a person's entry or an explicit unknown before completion.`) : null,
    ...parts.map((p) => h('div', { class: 'panel stack' }, h('h2', {}, p === 'A' ? 'Part A — party producing the record' : 'Part B — expert'), ...d.fields.filter((f) => f.key.startsWith(`${p.toLowerCase()}_`)).map(fieldRow))),
    h('div', { class: 'panel' }, h('h2', {}, 'History'), h('ul', { class: 'timeline' }, ...d.events.map((e) => h('li', { class: 'small' }, when(e.at), ` ${e.from_state ? `${label(e.from_state)} → ` : ''}${label(e.to_state)} by ${e.actor}`, e.note ? h('div', { class: 'muted' }, e.note) : null)))),
    h('p', { class: 'small muted' }, `Case ${c.case_id}.`, ' ', h('a', { href: `#/cases/${c.case_id}` }, 'Open case')));
  void errorText;
}
