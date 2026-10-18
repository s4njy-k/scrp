// Live job queue and intake (blueprint v4 §22.1 /jobs and /intake).
import { api, authImage, chip, clear, dialogForm, errorText, field, get, guard, h, hasRole, pager, post, skeleton, statusChips, toast, when } from '../lib.js';

const STAGE_LABEL = { queued: 'queued', capturing: 'capturing', first_image_ready: 'first image ready', finishing_evidence: 'finishing evidence', extracting: 'extracting', ready_for_review: 'ready for review', deferred: 'deferred', failed: 'failed' };

export async function myCases() {
  return (await get('/api/v1/cases?limit=200&status=open')).items;
}

function caseSelect(cases, selected, allowAll = true) {
  return h('select', {}, allowAll ? h('option', { value: '' }, 'All my cases') : null,
    ...cases.map((c) => h('option', { value: c.case_ref, selected: c.case_ref === selected, dataset: { id: c.id } }, `${c.case_ref} — ${c.title}`)));
}

export async function jobsView(main) {
  const params = new URLSearchParams(location.hash.split('?')[1] ?? '');
  const cases = await myCases();
  const caseSel = caseSelect(cases, params.get('case_ref'));
  const stateSel = h('select', {}, h('option', { value: '' }, 'Any state'), ...['QUEUED', 'DEFERRED', 'CAPTURING', 'COMPLETE', 'PARTIAL', 'MANUAL_REVIEW', 'FAILED_FINAL'].map((s) => h('option', { value: s }, s.toLowerCase().replace('_', ' '))));
  const verdictSel = h('select', {}, h('option', { value: '' }, 'Any verdict'), ...['unreviewed', 'suspicious', 'likely_malicious', 'benign', 'false_positive', 'inconclusive'].map((s) => h('option', { value: s }, s.replace('_', ' '))));
  const q = h('input', { type: 'search', placeholder: 'URL or domain contains…' });
  const urgent = h('input', { type: 'checkbox' });
  const live = h('span', { class: 'muted small', 'aria-live': 'polite' }, '');
  const body = h('tbody');
  const pagerSlot = h('div');
  const rows = new Map();
  let es = null;

  const rowFor = (j) => {
    const tr = h('tr', { tabindex: 0, onclick: () => { location.hash = `#/investigate/${j.target_id}`; }, onkeydown: (e) => { if (e.key === 'Enter') location.hash = `#/investigate/${j.target_id}`; } },
      h('td', {}, j.first_image_attempt_id ? authImage(`/api/v1/attempts/${j.first_image_attempt_id}/first-image`, `First image of job ${j.id}`, 'thumb') : h('div', { class: 'thumb' })),
      h('td', { class: 'url' }, h('div', {}, j.url), h('div', { class: 'muted small' }, `${j.profile.replace('_', ' ')} · ${j.capture_variant}${j.urgent ? ' · urgent' : ''} · job ${j.id}`)),
      h('td', {}, statusChips(j), h('div', { class: 'small muted' }, j.outcome_reason ?? '')),
      h('td', {}, chip(STAGE_LABEL[j.live_stage] ?? j.live_stage), j.first_image_provisional ? h('div', { class: 'small muted' }, 'provisional image') : null),
      h('td', { class: 'small' }, `HTTP ${j.budget_remaining.http_attempts} · browser ${j.budget_remaining.browser_attempts} · ${j.budget_remaining.seconds}s`),
      h('td', { class: 'small' }, (j.case_refs ?? []).join(', ')),
      h('td', { class: 'small' }, when(j.updated_at)),
      h('td', {}, rowActions(j)));
    return tr;
  };

  const rowActions = (j) => {
    if (!hasRole('analyst', 'admin')) return null;
    const stop = (e) => e.stopPropagation();
    const control = async (action) => {
      const r = await dialogForm(`${action[0].toUpperCase()}${action.slice(1)} job ${j.id}`, [{ name: 'reason', label: 'Reason (recorded in the audit log)', type: 'textarea', required: true }], action, { danger: action === 'cancel' });
      if (!r) return;
      await guard(() => post(`/api/v1/jobs/${j.id}/control`, { action, reason: r.reason, confirm: true }), `Job ${action}d`);
      void load();
    };
    const canPause = ['QUEUED', 'DEFERRED'].includes(j.state);
    return h('div', { class: 'row', onclick: stop },
      canPause ? h('button', { type: 'button', onclick: () => control(j.paused ? 'resume' : 'pause') }, j.paused ? 'Resume' : 'Pause') : null,
      canPause ? h('button', { type: 'button', onclick: () => control('cancel') }, 'Cancel') : null,
      !canPause && !['LEASED', 'CAPTURING', 'FINALISING'].includes(j.state) ? h('button', { type: 'button', onclick: async () => {
        const r = await dialogForm(`Recapture ${j.url}`, [
          { name: 'reason', label: 'Reason', type: 'textarea', required: true },
          { name: 'variant', label: 'Profile', type: 'select', options: [{ value: '', label: 'Same as before' }, { value: 'desktop', label: 'Desktop' }, { value: 'mobile', label: 'Mobile' }] },
          { name: 'urgent', label: 'Urgent (skip triage)', type: 'checkbox' },
        ], 'Create new capture');
        if (!r) return;
        await guard(() => post(`/api/v1/jobs/${j.id}/recapture`, { reason: r.reason, urgent: r.urgent, ...(r.variant ? { capture_variant: r.variant } : {}) }), 'A new capture was queued; earlier evidence is unchanged');
      } }, 'Recapture') : null);
  };

  const query = () => {
    const p = new URLSearchParams({ limit: '50' });
    if (caseSel.value) p.set('case_ref', caseSel.value);
    if (stateSel.value) p.set('state', stateSel.value);
    if (verdictSel.value) p.set('verdict', verdictSel.value);
    if (q.value.trim()) p.set('q', q.value.trim());
    if (urgent.checked) p.set('urgent', 'true');
    return p;
  };

  async function load(cursor) {
    clear(body, h('tr', {}, h('td', { colspan: 8 }, skeleton(3))));
    const p = query();
    if (cursor) p.set('cursor', cursor);
    try {
      const r = await get(`/api/v1/jobs?${p}`);
      rows.clear();
      clear(body, ...(r.items.length ? r.items.map((j) => { const tr = rowFor(j); rows.set(j.id, tr); return tr; }) : [h('tr', {}, h('td', { colspan: 8, class: 'muted' }, 'No jobs match.'))]));
      clear(pagerSlot, pager(r.next_cursor, (c) => load(c), cursor ? () => load() : null));
    } catch (e) {
      clear(body, h('tr', {}, h('td', { colspan: 8 }, errorText(e))));
    }
  }

  function connect() {
    es?.close();
    const p = new URLSearchParams();
    if (caseSel.value) p.set('case_ref', caseSel.value);
    es = new EventSource(`/api/v1/jobs/events?${p}`);
    es.addEventListener('job', (ev) => {
      const j = JSON.parse(ev.data);
      live.textContent = `Live · updated ${new Date().toLocaleTimeString()}`;
      const tr = rows.get(j.id);
      if (tr) { const n = rowFor(j); tr.replaceWith(n); rows.set(j.id, n); }
    });
    es.onerror = () => { live.textContent = 'Live updates reconnecting…'; };
    window.addEventListener('hashchange', () => es?.close(), { once: true });
  }

  for (const el of [caseSel, stateSel, verdictSel, urgent]) el.addEventListener('change', () => { void load(); connect(); });
  q.addEventListener('keydown', (e) => { if (e.key === 'Enter') void load(); });

  clear(main,
    h('div', { class: 'row' }, h('h1', { class: 'grow' }, 'Jobs'), live, hasRole('intake', 'admin') ? h('a', { class: 'btn primary', href: '#/intake' }, 'New intake') : null),
    h('div', { class: 'panel row' }, field('Case', caseSel), field('State', stateSel), field('Verdict', verdictSel), h('div', { class: 'grow' }, field('Search', q)), h('label', { class: 'checkline' }, urgent, 'Urgent only')),
    h('div', { class: 'panel tablewrap' }, h('table', {},
      h('thead', {}, h('tr', {}, ...['Image', 'Target', 'Status', 'Stage', 'Budget left', 'Cases', 'Updated', ''].map((t) => h('th', { scope: 'col' }, t)))), body), pagerSlot));
  await load();
  connect();
}

export async function intakeView(main) {
  const cases = await myCases();
  if (!hasRole('intake', 'admin')) {
    clear(main, h('div', { class: 'banner warn' }, 'Intake requires the intake role.'));
    return;
  }
  const caseSel = h('select', { required: true }, ...cases.map((c) => h('option', { value: c.id }, `${c.case_ref} — ${c.title}`)));
  const text = h('textarea', { placeholder: 'One URL or domain per line (exact paths, queries and #fragments are preserved), or paste CSV/JSONL.', rows: 8 });
  const file = h('input', { type: 'file', accept: '.csv,.jsonl,.ndjson,.txt,.xlsx' });
  const format = h('select', {}, ...[['text', 'One per line'], ['csv', 'CSV'], ['jsonl', 'JSONL'], ['xlsx', 'XLSX (upload)']].map(([v, l]) => h('option', { value: v }, l)));
  const profile = h('select', {}, h('option', { value: 'browser_evidence' }, 'Browser evidence'), h('option', { value: 'data_triage' }, 'Data triage (no screenshots)'));
  const variant = h('select', {}, h('option', { value: 'desktop' }, 'Desktop'), h('option', { value: 'mobile' }, 'Mobile'), h('option', { value: 'both' }, 'Desktop + mobile (two attempts)'));
  const urgent = h('input', { type: 'checkbox' });
  const priority = h('input', { type: 'number', value: '0', min: '-1000', max: '1000' });
  const lawful = h('input', { type: 'text', placeholder: 'e.g. complaint registered, investigation under …' });
  const authRef = h('input', { type: 'text', placeholder: 'authorisation / reference number' });
  const out = h('div');
  file.addEventListener('change', () => {
    const n = file.files?.[0]?.name.toLowerCase() ?? '';
    format.value = n.endsWith('.xlsx') ? 'xlsx' : n.endsWith('.csv') ? 'csv' : n.endsWith('.jsonl') || n.endsWith('.ndjson') ? 'jsonl' : 'text';
  });

  const submit = async (dryRun) => {
    if (!caseSel.value) return toast('Create or join a case first', 'bad');
    const raw = file.files?.[0] ? new Uint8Array(await file.files[0].arrayBuffer()) : text.value;
    if (!raw || (typeof raw === 'string' && !raw.trim())) return toast('Nothing to submit', 'bad');
    const p = new URLSearchParams({ case_id: caseSel.value, format: format.value, profile: profile.value, capture_variant: variant.value, priority: priority.value || '0', urgent: String(urgent.checked) });
    if (dryRun) p.set('dry_run', 'true');
    if (lawful.value) p.set('lawful_basis', lawful.value);
    if (authRef.value) p.set('authorisation_ref', authRef.value);
    if (file.files?.[0]) p.set('filename', file.files[0].name);
    const headers = dryRun ? {} : { 'Idempotency-Key': crypto.randomUUID() };
    try {
      const r = await api('POST', `/api/v1/intake-batches?${p}`, undefined, { raw, contentType: format.value === 'xlsx' ? 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' : 'text/plain', headers });
      clear(out, h('div', { class: 'panel' },
        h('h2', {}, dryRun ? 'Preview (nothing queued yet)' : 'Accepted'),
        h('p', {}, `${r.accepted} accepted · ${r.duplicate} merged into existing jobs · ${r.rejected} rejected${r.formula_cells_ignored ? ` · ${r.formula_cells_ignored} spreadsheet formulas ignored (cached values used)` : ''}`),
        r.batch_id ? h('p', {}, 'Batch ', h('span', { class: 'mono' }, r.batch_id), '. ', h('a', { href: '#/jobs' }, 'Follow progress on Jobs')) : null,
        h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Line'), h('th', {}, 'Input'), h('th', {}, 'Result'), h('th', {}, 'Reason / jobs'))),
          h('tbody', {}, ...r.line_results.map((l) => h('tr', {}, h('td', {}, l.line), h('td', { class: 'url mono' }, l.target ?? ''), h('td', {}, chip(l.status === 'accepted' ? 'content_captured' : l.status === 'merged' ? 'partial' : 'failed', l.status), ' ', l.status),
            h('td', { class: 'small' }, l.reason ?? (l.job_ids ?? []).join(', ')))))))));
      if (!dryRun) text.value = '';
    } catch (e) {
      clear(out, h('div', { class: 'banner bad' }, errorText(e)));
    }
    return undefined;
  };

  clear(main, h('h1', {}, 'Intake'),
    cases.length ? null : h('div', { class: 'banner warn' }, 'You are not a member of any open case. Open one under Cases first.'),
    h('div', { class: 'panel stack' },
      h('div', { class: 'row' }, h('div', { class: 'grow' }, field('Case', caseSel)), field('Profile', profile), field('Capture profile', variant), field('Priority', priority), h('label', { class: 'checkline' }, urgent, 'Urgent (direct to browser evidence)')),
      field('Targets', text, 'Exact URLs are captured as given; tracking-looking parameters are kept because they can select the victim-specific view.'),
      h('div', { class: 'row' }, field('Or upload a file', file), field('Format', format)),
      h('div', { class: 'row' }, h('div', { class: 'grow' }, field('Lawful basis / scope', lawful)), h('div', { class: 'grow' }, field('Authorisation reference', authRef))),
      h('div', { class: 'row' }, h('button', { type: 'button', onclick: () => submit(true) }, 'Preview'), h('button', { type: 'button', class: 'primary', onclick: () => submit(false) }, 'Submit'))),
    out);
}
