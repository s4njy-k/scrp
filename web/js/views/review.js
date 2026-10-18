// Review queue with accountable bulk triage (blueprint v4 §22.1 /review, §22.4).
import { authImage, chip, clear, dialogForm, field, get, guard, h, hasRole, post, skeleton, statusChips, when } from '../lib.js';

const QUEUES = [['unreviewed', 'Unreviewed'], ['high_risk_unreviewed', 'High triage score, unreviewed'], ['manual_review', 'Needs operator attention'], ['escalated', 'Escalated for approval'], ['inconclusive', 'Inconclusive']];

export async function reviewView(main) {
  const queue = h('select', {}, ...QUEUES.map(([v, l]) => h('option', { value: v }, l)));
  const body = h('tbody');
  const selected = new Set();
  const load = async () => {
    selected.clear();
    clear(body, h('tr', {}, h('td', { colspan: 5 }, skeleton(3))));
    const r = await get(`/api/v1/review-queue?queue=${queue.value}&limit=100`);
    clear(body, ...(r.items.length ? r.items.map((j) => {
      const box = h('input', { type: 'checkbox', 'aria-label': `Select ${j.url}`, onchange: () => (box.checked ? selected.add(j.target_id) : selected.delete(j.target_id)) });
      return h('tr', {}, h('td', {}, box),
        h('td', {}, j.first_image_attempt_id ? authImage(`/api/v1/attempts/${j.first_image_attempt_id}/first-image`, `First image ${j.id}`, 'thumb') : null),
        h('td', { class: 'url' }, h('a', { href: `#/investigate/${j.target_id}` }, j.url), h('div', { class: 'small muted' }, (j.case_refs ?? []).join(', '))),
        h('td', {}, statusChips(j)), h('td', { class: 'small' }, when(j.updated_at)));
    }) : [h('tr', {}, h('td', { colspan: 5, class: 'muted' }, 'Queue is empty.'))]));
  };
  queue.addEventListener('change', () => void load());
  const bulk = async () => {
    if (selected.size === 0) return;
    const r = await dialogForm(`Bulk triage: ${selected.size} target(s)`, [
      { name: 'decision', label: 'Decision', type: 'select', options: ['retain', 'investigate', 'inconclusive', 'recapture', 'false_positive', 'benign'] },
      { name: 'reason_code', label: 'Reason code', type: 'select', options: ['insufficient_evidence', 'needs_recapture', 'deceptive_claims', 'payment_redirection', 'legitimate_official', 'parked_or_expired', 'crawler_error', 'other'] },
      { name: 'reason', label: 'Reason (recorded per target)', type: 'textarea', required: true },
    ], 'Preview');
    if (!r) return;
    const body = { target_ids: [...selected], decision: r.decision, reason_code: r.reason_code, reason: r.reason, confirm: true };
    const preview = await guard(() => post('/api/v1/decisions/bulk', { ...body, preview: true }));
    if (!preview) return;
    const ok = await dialogForm('Confirm bulk decision', [], `Record ${preview.would_record} decision(s)`, { intro: `Each target gets its own attributed, append-only decision (${preview.verdict}). External actions are never taken in bulk.` });
    if (ok === null) return;
    await guard(() => post('/api/v1/decisions/bulk', body), 'Decisions recorded');
    void load();
  };
  clear(main, h('h1', {}, 'Review'),
    h('div', { class: 'panel row' }, h('div', { class: 'grow' }, field('Queue', queue)), hasRole('analyst', 'admin') ? h('button', { type: 'button', onclick: bulk }, 'Bulk triage selected') : null),
    h('div', { class: 'panel tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, ''), h('th', {}, 'Image'), h('th', {}, 'Target'), h('th', {}, 'Status'), h('th', {}, 'Updated'))), body)));
  await load();
  void chip;
}
