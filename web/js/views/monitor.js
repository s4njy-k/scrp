// Revisit schedules, outcomes and reappearance alerts (blueprint v4 §22.1 /monitor; checklist §8).
import { api, chip, clear, dialogForm, errorText, get, guard, h, hasRole, post, skeleton, toast, when } from '../lib.js';

const label = (s) => String(s ?? '').replace(/_/g, ' ');

export async function monitorView(main) {
  clear(main, skeleton(4));
  const [rules, alerts] = await Promise.all([get('/api/v1/monitoring/rules'), get('/api/v1/monitoring/alerts')]);
  const reload = () => monitorView(main);
  const active = rules.items.filter((r) => r.active);
  const can = hasRole('analyst', 'approver', 'admin');

  const record = async (r) => {
    const f = await dialogForm('Record a reported outcome', [
      { name: 'outcome_class', label: 'Outcome', type: 'select', options: [{ value: 'reported_removal', label: 'Removal reported (not yet verified)' }, { value: 'provider_confirmed_suspension', label: 'Provider confirmed suspension (needs their acknowledgement)' }] },
      { name: 'note', label: 'Note (who reported what, when)', type: 'textarea', required: true },
    ], 'Continue');
    if (!f) return;
    let upload;
    if (f.outcome_class === 'provider_confirmed_suspension') {
      upload = await pickUpload(r.case_id);
      if (!upload) return;
    }
    if (await guard(() => post(`/api/v1/monitoring/rules/${r.id}/observations`, { outcome_class: f.outcome_class, note: f.note, ...(upload ? { upload_id: upload } : {}) }), 'Observation recorded')) void reload();
  };

  clear(main, h('h1', {}, 'Monitor'),
    h('div', { class: 'banner info small' }, 'Each revisit is a new capture; earlier evidence never changes. Outcomes are what this vantage observed: "blocked at tested vantage" or "DNS not resolving" is not proof of removal everywhere.'),
    h('div', { class: 'panel tablewrap' }, h('h2', {}, `Revisit schedules (${active.length} active)`),
      rules.items.length ? h('table', {}, h('thead', {}, h('tr', {}, ...['Target', 'Case', 'Schedule', 'Latest outcome', 'Next due', ''].map((t) => h('th', {}, t)))),
        h('tbody', {}, ...rules.items.map((r) => h('tr', { class: r.active ? '' : 'muted' },
          h('td', { class: 'url' }, h('a', { href: `#/investigate/${r.target_id}` }, r.url), h('div', { class: 'small muted' }, r.reason)),
          h('td', { class: 'mono small' }, h('a', { href: `#/cases/${r.case_id}` }, r.case_ref)),
          h('td', { class: 'small' }, chip(r.active ? 'capturing' : 'none', r.active ? 'active' : 'stopped'), ` every ${r.interval_hours} h · ${label(r.capture_variant)} · ${r.observations} observation(s)`, h('div', { class: 'muted' }, 'ends ', when(r.ends_at))),
          h('td', {}, r.latest_observation ? [chip(r.latest_observation.outcome_class), h('div', { class: 'small muted' }, when(r.latest_observation.created_at)),
            r.latest_observation.attempt_id ? h('a', { class: 'small', href: `#/evidence/${r.latest_observation.attempt_id}` }, 'evidence') : null] : h('span', { class: 'muted small' }, 'none yet')),
          h('td', { class: 'small' }, r.active ? when(r.next_due_at) : '—'),
          h('td', {}, can && r.active ? h('div', { class: 'row' },
            h('button', { type: 'button', class: 'link', onclick: () => record(r) }, 'Record outcome'),
            h('button', { type: 'button', class: 'link', onclick: async () => {
              const f = await dialogForm('Stop revisits', [{ name: 'reason', label: 'Reason', type: 'textarea', required: true }], 'Stop', { danger: true });
              if (f && await guard(() => post(`/api/v1/monitoring/rules/${r.id}/stop`, { reason: f.reason }), 'Revisits stopped')) void reload();
            } }, 'Stop')) : null)))))
        : h('p', { class: 'muted' }, 'No revisit schedules. Schedule one from a target\'s investigation page.')),
    h('div', { class: 'panel' }, h('h2', {}, 'Reappearance alerts'), h('p', { class: 'small muted' }, alerts.note),
      alerts.items.length ? h('ul', { class: 'timeline' }, ...alerts.items.map((a) => h('li', { class: a.acknowledged_at ? 'muted' : '' },
        h('div', {}, h('a', { href: `#/investigate/${a.new_target_id}` }, a.new_url), ' shares identifiers with ', h('a', { href: `#/investigate/${a.source_target_id}` }, a.source_url)),
        h('div', { class: 'small' }, chip(a.strength === 'strong_possible' ? 'suspicious' : 'none', label(a.strength)), ' ', h('span', { class: 'mono' }, (a.shared ?? []).map((s) => String(s).replace(':', ': ')).join(' · '))),
        h('div', { class: 'small muted' }, when(a.created_at), a.acknowledged_at ? ` · acknowledged by ${a.acknowledged_by}` : ''),
        !a.acknowledged_at && can ? h('button', { type: 'button', class: 'link', onclick: async () => { if (await guard(() => post(`/api/v1/monitoring/alerts/${a.id}/acknowledge`), 'Acknowledged')) void reload(); } }, 'Acknowledge') : null)))
        : h('p', { class: 'muted' }, 'No alerts.')));
}

/** Upload a provider acknowledgement to the case; returns the upload id. */
async function pickUpload(caseId) {
  const dlg = document.getElementById('dialog');
  return new Promise((resolve) => {
    const file = h('input', { type: 'file', accept: 'application/pdf,image/png,image/jpeg,text/plain', required: true });
    const msg = h('p', { role: 'alert', class: 'muted small' });
    clear(dlg, h('form', { class: 'stack', onsubmit: async (ev) => {
      ev.preventDefault();
      const f = file.files?.[0];
      if (!f) return;
      try {
        const r = await api('POST', `/api/v1/cases/${caseId}/uploads?${new URLSearchParams({ purpose: 'provider_acknowledgement', filename: f.name })}`, undefined, { raw: f, contentType: f.type || 'application/octet-stream' });
        toast('Acknowledgement stored');
        dlg.close();
        resolve(r.id);
      } catch (e) { msg.textContent = errorText(e); }
    } }, h('h2', { id: 'dialog-title' }, 'Provider acknowledgement'), h('p', { class: 'small muted' }, 'Confirmation of suspension must rest on the provider\'s own acknowledgement.'),
    file, msg, h('div', { class: 'row' }, h('button', { type: 'submit', class: 'primary' }, 'Upload'), h('button', { type: 'button', onclick: () => { dlg.close(); resolve(null); } }, 'Cancel'))));
    dlg.addEventListener('cancel', () => resolve(null), { once: true });
    dlg.showModal();
  });
}
