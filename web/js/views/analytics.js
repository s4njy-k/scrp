// Trustworthy analytics (blueprint v4 §16, §22.1 /analytics; checklist §10):
// every figure shows its numerator/denominator, scope, definition and refresh
// time, and observed, inferred, confirmed and actioned figures stay apart.
import { chip, clear, field, get, h, ist, skeleton } from '../lib.js';

const label = (s) => String(s ?? 'none').replace(/_/g, ' ');
const secs = (v) => (v === null || v === undefined ? '—' : v < 90 ? `${v.toFixed(1)} s` : `${(v / 60).toFixed(1)} min`);
const pct = (v) => (v === null || v === undefined ? '—' : `${(v * 100).toFixed(1)}%`);

function metric(title, value, sub, definition) {
  return h('div', { class: 'metric' }, h('div', { class: 'metric-title' }, title), h('div', { class: 'metric-value' }, value), sub ? h('div', { class: 'small' }, sub) : null, h('div', { class: 'small muted' }, definition));
}

function widthBar(fraction) {
  const el = h('span', { class: 'bar' });
  el.style.width = `${Math.round(fraction * 100)}%`; // CSSOM, permitted under style-src 'self'
  return el;
}

/** Horizontal bars drawn with CSS widths; the table of values is the accessible source of truth. */
function bars(title, items, key, definition) {
  const total = items.reduce((s, x) => s + x.n, 0);
  const max = Math.max(1, ...items.map((x) => x.n));
  return h('div', { class: 'panel' }, h('h3', {}, title), h('p', { class: 'small muted' }, `${definition} Total: ${total}.`),
    items.length ? h('table', { class: 'bars' }, h('thead', {}, h('tr', {}, h('th', {}, label(key)), h('th', { class: 'right' }, 'Count'), h('th', { class: 'right' }, 'Share'), h('th', { 'aria-hidden': 'true' }, ''))),
      h('tbody', {}, ...items.map((x) => h('tr', {}, h('td', {}, chip(x[key] ?? 'none')), h('td', { class: 'right' }, x.n), h('td', { class: 'right small' }, pct(total ? x.n / total : null)),
        h('td', { class: 'barcell', 'aria-hidden': 'true' }, widthBar(x.n / max))))))
      : h('p', { class: 'muted' }, 'No data in this window.'));
}

export async function analyticsView(main) {
  const days = h('select', {}, ...[1, 7, 30, 90].map((d) => h('option', { value: d, selected: d === 7 }, `${d} day${d > 1 ? 's' : ''}`)));
  const caseRef = h('input', { type: 'text', placeholder: 'All cases in my scope' });
  const out = h('div');
  const load = async () => {
    clear(out, skeleton(6));
    const p = new URLSearchParams({ days: days.value });
    if (caseRef.value.trim()) p.set('case_ref', caseRef.value.trim());
    const a = await get(`/api/v1/analytics?${p}`);
    const o = a.observed;
    clear(out,
      h('p', { class: 'small muted' }, `Scope: ${a.scope} · window: last ${a.window_days} day(s) · generated ${ist(a.generated_at)} · refreshed at most every ${a.cache_seconds} s.`),
      h('h2', {}, 'Observed (what the collector saw)'),
      h('div', { class: 'metrics' },
        metric('Jobs', o.jobs.total ?? 0, `${o.jobs.complete ?? 0} complete · ${o.jobs.partial ?? 0} partial · ${o.jobs.failed ?? 0} failed · ${o.jobs.manual ?? 0} manual review · ${o.jobs.open ?? 0} open`, o.jobs.definition),
        metric('Usable evidence rate', pct(o.usable_evidence_rate.value), `${o.usable_evidence_rate.numerator} of ${o.usable_evidence_rate.denominator} finished jobs`, o.usable_evidence_rate.definition),
        metric('First image (per attempt)', `p50 ${secs(o.first_image_seconds.p50)}`, `p95 ${secs(o.first_image_seconds.p95)} · n=${o.first_image_seconds.n}`, o.first_image_seconds.definition),
        metric('First capture (incl. queue)', `p50 ${secs(o.first_capture_seconds.p50)}`, `p95 ${secs(o.first_capture_seconds.p95)} · n=${o.first_capture_seconds.n}`, o.first_capture_seconds.definition),
        metric('Evidence verification failures', o.evidence_verification.failures, `of ${o.evidence_verification.artifacts_checked} artifacts verified at least once`, o.evidence_verification.definition)),
      bars('Acquisition outcomes', o.outcomes.items, 'outcome', o.outcomes.definition),
      h('h2', {}, 'Inferred'), h('p', { class: 'muted' }, a.inferred.note),
      h('h2', {}, 'Confirmed (analyst decisions)'),
      bars('Verdicts by target', a.confirmed.verdicts.items, 'verdict', a.confirmed.verdicts.definition),
      h('div', { class: 'metrics' }, metric('False-positive overrides', a.confirmed.false_positive_overrides.n, null, a.confirmed.false_positive_overrides.definition)),
      h('h2', {}, 'Actioned (human-taken external steps)'),
      bars('Notices by state', a.actioned.notices.items, 'state', a.actioned.notices.definition),
      h('div', { class: 'metrics' }, metric('Issuance → documented receipt', a.actioned.acknowledgement_hours.median_hours === null || a.actioned.acknowledgement_hours.median_hours === undefined ? '—' : `${a.actioned.acknowledgement_hours.median_hours.toFixed(1)} h median`, `n=${a.actioned.acknowledgement_hours.n}`, a.actioned.acknowledgement_hours.definition)),
      bars('Revisit outcomes', a.actioned.monitoring.items, 'outcome_class', a.actioned.monitoring.definition));
  };
  days.addEventListener('change', () => void load().catch((e) => clear(out, h('div', { class: 'banner bad' }, String(e.message ?? e)))));
  caseRef.addEventListener('keydown', (e) => { if (e.key === 'Enter') void load().catch((err) => clear(out, h('div', { class: 'banner bad' }, String(err.message ?? err)))); });
  clear(main, h('h1', {}, 'Analytics'), h('div', { class: 'panel row' }, field('Window', days), h('div', { class: 'grow' }, field('Case reference (Enter to apply)', caseRef))), out);
  await load();
}
