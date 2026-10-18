// Evidence record of one capture (blueprint v4 §22.1 /evidence/:captureId):
// manifest with integrity status, artifact ledger, verification and custody trail.
import { chip, clear, download, get, guard, h, hasRole, kv, post, shortHash, skeleton, when } from '../lib.js';

export async function evidenceView(main, attemptId) {
  clear(main, skeleton(5));
  const r = await get(`/api/v1/captures/${attemptId}/manifest`);
  const m = r.manifest;
  const events = await get(`/api/v1/audit-events?object_type=attempt&object_id=${attemptId}`).catch(() => ({ items: [] }));
  const verifyOut = h('div');
  const ledger = new Map(r.ledger_artifacts.map((a) => [a.relative_path, a]));
  clear(main,
    h('div', { class: 'panel' }, h('h1', {}, 'Evidence record'),
      r.integrity.matches ? h('div', { class: 'banner info' }, 'Manifest bytes match the hash recorded in the ledger at commit.') : h('div', { class: 'banner bad' }, 'The manifest does NOT match the ledger hash. Treat this record as compromised and run Verify Evidence.'),
      kv([['Attempt', h('span', { class: 'mono' }, m.attemptId)], ['Requested URL', h('span', { class: 'mono' }, m.requestedUrl)], ['Original input(s)', (m.originalInputs ?? []).join('\n') || '—'],
        ['Final URL', h('span', { class: 'mono' }, m.finalUrl ?? '—')], ['Observed', `${m.observedAtIst ?? ''} (${m.observedAtUtc ?? m.startedAt} UTC)`], ['Outcome', chip(m.outcome?.toLowerCase())],
        ['Classification', m.classification], ['Engine', `${m.engineInfo?.name ?? m.engine} ${m.engineInfo?.version ?? ''}`], ['Profile', `${m.profile?.name ?? ''} · ${m.profile?.captureVariant ?? ''}`],
        ['Vantage', `${m.networkVantage?.id ?? m.vantage} · public IP ${m.networkVantage?.publicIp ?? 'not observed'} (${m.networkVantage?.publicIpSource ?? ''})`],
        ['Clock', m.clock ? `${m.clock.source} · ${m.clock.sync_verified ? 'synchronised' : 'not verified'}${m.clock.note ? ` · ${m.clock.note}` : ''}` : '—'],
        ['Required artifacts', `${m.requiredSatisfied ? 'satisfied' : `missing: ${(m.missingRequired ?? []).join(', ')}`}`], ['Manifest SHA-256', h('span', { class: 'mono' }, r.integrity.ledger_sha256)],
        ['Software', m.software ? `${m.software.collector_version} · node ${m.software.node_version}` : '—']]),
      m.limitations?.length ? h('div', { class: 'banner warn small' }, `Limitations: ${m.limitations.join('; ')}`) : null,
      h('div', { class: 'row' },
        hasRole('analyst', 'evidence', 'admin') ? h('button', { type: 'button', class: 'primary', onclick: async () => {
          const v = await guard(() => post(`/api/v1/captures/${attemptId}/verify`));
          if (!v) return;
          clear(verifyOut, h('div', { class: `banner ${v.result === 'pass' ? 'info' : 'bad'}` }, `Verify Evidence: ${v.result.toUpperCase()} — ${v.counts.ok}/${v.counts.artifacts_checked} artifacts match · report SHA-256 ${shortHash(v.report_sha256)} · ${v.finished_at_ist}`),
            h('button', { type: 'button', onclick: () => download(`/api/v1/verification-runs/${v.run_id}/report`, `verification-${v.run_id}.json`) }, 'Download verification report'));
        } }, 'Verify Evidence') : null),
      verifyOut),
    h('div', { class: 'panel tablewrap' }, h('h2', {}, 'Artifacts'),
      h('table', {}, h('thead', {}, h('tr', {}, ...['Type', 'Path', 'Size', 'SHA-256', 'Observed', 'Completeness', 'Verification', ''].map((t) => h('th', {}, t)))),
        h('tbody', {}, ...m.artifacts.map((a) => {
          const row = a.path ? ledger.get(a.path) : null;
          return h('tr', {}, h('td', {}, a.type), h('td', { class: 'mono small' }, a.path ?? '(not saved)'), h('td', { class: 'small right' }, a.sizeBytes ?? '—'),
            h('td', { class: 'mono small' }, shortHash(a.sha256)), h('td', { class: 'small' }, a.observedStart ? when(a.observedStart) : '—'),
            h('td', {}, chip(a.completeness === 'complete' ? 'content_captured' : a.completeness === 'failed' ? 'failed' : 'partial', a.completeness), a.restricted ? h('span', { class: 'chip warn' }, 'restricted') : null,
              a.error ? h('div', { class: 'small muted' }, a.error) : null, a.limitations?.length ? h('div', { class: 'small muted' }, a.limitations.join('; ')) : null),
            h('td', {}, row ? chip(row.verification_state) : '—'),
            h('td', {}, row && hasRole('evidence', 'admin') ? h('button', { type: 'button', class: 'link', onclick: () => download(`/api/v1/artifacts/${row.id}/content`, `artifact-${row.id}.bin`, a.restricted ? { 'X-Purpose': prompt('Purpose for accessing this restricted artifact (recorded):') ?? '' } : {}) }, 'Download') : null));
        }))),
      r.derivatives.length ? h('p', { class: 'muted small' }, `${r.derivatives.length} derivative(s) (thumbnails, extraction output) are stored separately and reference these originals.`) : null),
    h('div', { class: 'panel' }, h('h2', {}, 'Custody events'), events.items?.length ? h('ul', { class: 'timeline' }, ...events.items.map((e) => h('li', { class: 'small' }, when(e.at), ` ${e.event_type} by ${e.actor}`, e.chain_pos ? h('span', { class: 'muted mono' }, ` · chain #${e.chain_pos} ${shortHash(e.event_hash)}`) : h('span', { class: 'muted' }, ' · sealing…')))) : h('p', { class: 'muted small' }, 'Custody events are visible to auditors and through the case audit view.')));
}
