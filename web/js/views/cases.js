// Cases: membership, holds, evidence verification and packages (blueprint v4 §22.1 /cases).
import { chip, clear, dialogForm, download, errorText, field, get, guard, h, hasRole, kv, patch, post, skeleton, statusChips, when } from '../lib.js';

export async function casesView(main) {
  const list = h('tbody');
  const q = h('input', { type: 'search', placeholder: 'Case reference or title' });
  const status = h('select', {}, h('option', { value: 'open' }, 'Open'), h('option', { value: 'closed' }, 'Closed'), h('option', { value: '' }, 'All'));
  const load = async () => {
    clear(list, h('tr', {}, h('td', { colspan: 6 }, skeleton(2))));
    const p = new URLSearchParams({ limit: '200' });
    if (q.value) p.set('q', q.value);
    if (status.value) p.set('status', status.value);
    const r = await get(`/api/v1/cases?${p}`);
    clear(list, ...(r.items.length ? r.items.map((c) => h('tr', { tabindex: 0, onclick: () => { location.hash = `#/cases/${c.id}`; }, onkeydown: (e) => { if (e.key === 'Enter') location.hash = `#/cases/${c.id}`; } },
      h('td', { class: 'mono' }, c.case_ref), h('td', {}, c.title), h('td', {}, c.category.replace(/_/g, ' ')), h('td', {}, chip(c.status === 'open' ? 'capturing' : 'none', c.status), c.on_hold ? h('span', { class: 'chip warn' }, 'legal hold') : null),
      h('td', {}, c.my_role ?? 'admin view'), h('td', { class: 'right' }, c.job_count))) : [h('tr', {}, h('td', { colspan: 6, class: 'muted' }, 'No cases.'))]));
  };
  q.addEventListener('keydown', (e) => { if (e.key === 'Enter') void load(); });
  status.addEventListener('change', () => void load());
  clear(main, h('div', { class: 'row' }, h('h1', { class: 'grow' }, 'Cases'),
    hasRole('analyst', 'intake', 'admin') ? h('button', { type: 'button', class: 'primary', onclick: async () => {
      const r = await dialogForm('Open a case', [
        { name: 'case_ref', label: 'Case reference', required: true, help: 'Letters, digits and / _ . : -' },
        { name: 'title', label: 'Title', required: true },
        { name: 'category', label: 'Category', type: 'select', options: ['financial_fraud', 'phishing', 'impersonation', 'investment_scam', 'loan_app', 'job_task_scam', 'sextortion', 'other'] },
        { name: 'sensitivity', label: 'Sensitivity', type: 'select', options: ['restricted', 'confidential', 'secret'] },
        { name: 'ncrp', label: 'NCRP acknowledgement numbers (comma-separated, restricted)' },
        { name: 'fir', label: 'FIR references (comma-separated, restricted)' },
      ], 'Open case');
      if (!r) return;
      const split = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
      const c = await guard(() => post('/api/v1/cases', { case_ref: r.case_ref, title: r.title, category: r.category, sensitivity: r.sensitivity, ncrp_refs: split(r.ncrp), fir_refs: split(r.fir) }), 'Case opened');
      if (c) location.hash = `#/cases/${c.id}`;
    } }, 'Open case') : null),
  h('div', { class: 'panel row' }, h('div', { class: 'grow' }, field('Search', q)), field('Status', status)),
  h('div', { class: 'panel tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, ...['Reference', 'Title', 'Category', 'Status', 'My role', 'Jobs'].map((t) => h('th', {}, t)))), list)));
  await load();
}

export async function caseView(main, caseId) {
  clear(main, skeleton(5));
  const c = await get(`/api/v1/cases/${caseId}`);
  const owner = c.my_role === 'owner' || hasRole('admin');
  const jobs = await get(`/api/v1/jobs?case_ref=${encodeURIComponent(c.case_ref)}&top_level=true&limit=100`);
  const notices = await get(`/api/v1/notices?case_id=${caseId}`);
  const activeHold = c.holds.find((x) => !x.released_at);
  const reload = () => caseView(main, caseId);

  clear(main,
    h('div', { class: 'panel' }, h('div', { class: 'row' }, h('h1', { class: 'grow' }, `${c.case_ref} — ${c.title}`), chip(c.status === 'open' ? 'capturing' : 'none', c.status), activeHold ? h('span', { class: 'chip warn' }, 'legal hold') : null),
      kv([['Category', c.category.replace(/_/g, ' ')], ['Sensitivity', c.sensitivity], ['Opened', when(c.opened_at)], ['Opened by', c.opened_by],
        ['NCRP references', c.ncrp_refs.join(', ') || '—'], ['FIR references', c.fir_refs.join(', ') || '—'], c.refs_masked ? ['Note', 'Reference numbers are masked: you are not a member of this case.'] : null,
        ['Job states', Object.entries(c.job_states).map(([k, v]) => `${k.toLowerCase()}: ${v}`).join(' · ') || '—']]),
      h('div', { class: 'row' },
        hasRole('intake', 'admin') && c.status === 'open' ? h('a', { class: 'btn primary', href: '#/intake' }, 'Add targets') : null,
        hasRole('analyst', 'evidence', 'admin') ? h('button', { type: 'button', onclick: async () => {
          const r = await guard(() => post(`/api/v1/cases/${caseId}/verify`));
          if (r) {
            const dlg = document.getElementById('dialog');
            clear(dlg, h('h2', { id: 'dialog-title' }, `Verify Evidence: ${r.result}`), kv([['Artifacts checked', r.counts.artifacts_checked], ['OK', r.counts.ok], ['Missing', r.counts.missing], ['Modified', r.counts.mismatch], ['Report SHA-256', h('span', { class: 'mono' }, r.report_sha256)], ['Finished', r.finished_at_ist]]),
              r.failures.length ? h('ul', {}, ...r.failures.map((f) => h('li', { class: 'mono small' }, `${f.status}: ${f.path}`))) : null, h('p', { class: 'muted small' }, r.statement),
              h('div', { class: 'row' }, h('button', { type: 'button', onclick: () => download(`/api/v1/verification-runs/${r.run_id}/report`, `verification-${r.run_id}.json`) }, 'Download report'), h('button', { type: 'button', onclick: () => dlg.close() }, 'Close')));
            dlg.showModal();
          }
        } }, 'Verify case evidence') : null,
        hasRole('evidence', 'admin') ? h('button', { type: 'button', onclick: async () => {
          const r = await dialogForm('Prepare evidence package', [{ name: 'purpose', label: 'Purpose (recorded)', type: 'textarea', required: true }, { name: 'restricted', label: 'Include restricted artifacts (cookies/session data) — only with a documented need', type: 'checkbox' }], 'Prepare');
          if (!r) return;
          const p = await guard(() => post('/api/v1/packages', { case_id: caseId, purpose: r.purpose, include_restricted: r.restricted }));
          if (p) download(`/api/v1/packages/${p.package_id}/archive`, `evidence-package-${p.package_id}.tar`);
        } }, 'Evidence package') : null,
        owner ? h('button', { type: 'button', onclick: async () => {
          const r = await dialogForm(c.status === 'open' ? 'Close case' : 'Reopen case', [{ name: 'reason', label: 'Reason', type: 'textarea', required: true }], c.status === 'open' ? 'Close' : 'Reopen');
          if (r) { await guard(() => patch(`/api/v1/cases/${caseId}`, { expected_version: c.version, status: c.status === 'open' ? 'closed' : 'open', reason: r.reason }), 'Case updated'); void reload(); }
        } }, c.status === 'open' ? 'Close case' : 'Reopen case') : null)),
    h('div', { class: 'grid2' },
      h('div', { class: 'panel' }, h('h2', {}, 'Members'), h('table', {}, h('tbody', {}, ...c.members.map((m) => h('tr', {}, h('td', {}, `${m.display_name} (${m.username})`), h('td', {}, m.case_role),
        h('td', {}, owner ? h('button', { type: 'button', class: 'link', onclick: async () => { if (await dialogForm(`Remove ${m.username}?`, [], 'Remove', { danger: true })) { await guard(() => api_del(`/api/v1/cases/${caseId}/members/${m.user_id}`), 'Removed'); void reload(); } } }, 'Remove') : null))))),
        owner ? h('button', { type: 'button', onclick: async () => {
          const r = await dialogForm('Add member', [{ name: 'username', label: 'Username', required: true }, { name: 'role', label: 'Case role', type: 'select', options: ['investigator', 'viewer', 'owner'] }, { name: 'reason', label: 'Reason', required: true }], 'Add');
          if (r) { await guard(() => post(`/api/v1/cases/${caseId}/members`, { username: r.username, case_role: r.role, reason: r.reason }), 'Member added'); void reload(); }
        } }, 'Add member') : null),
      h('div', { class: 'panel' }, h('h2', {}, 'Legal hold'),
        activeHold ? h('div', { class: 'banner warn' }, `On hold since ${new Date(activeHold.placed_at).toLocaleString()} by ${activeHold.placed_by}: ${activeHold.reason}`) : h('p', { class: 'muted' }, 'No active hold. Evidence cited by notices, certificates or an open case is protected from routine expiry anyway.'),
        hasRole('analyst', 'approver', 'admin') && !activeHold ? h('button', { type: 'button', onclick: async () => {
          const r = await dialogForm('Place legal hold', [{ name: 'reason', label: 'Reason', type: 'textarea', required: true }, { name: 'authority', label: 'Authority reference' }], 'Place hold');
          if (r) { await guard(() => post(`/api/v1/cases/${caseId}/hold`, { reason: r.reason, ...(r.authority ? { authority_ref: r.authority } : {}) }), 'Hold placed'); void reload(); }
        } }, 'Place hold') : null,
        hasRole('approver', 'admin') && activeHold ? h('button', { type: 'button', onclick: async () => {
          const r = await dialogForm('Release legal hold', [{ name: 'reason', label: 'Reason', type: 'textarea', required: true }], 'Release', { danger: true });
          if (r) { await guard(() => post(`/api/v1/cases/${caseId}/hold/release`, { reason: r.reason }), 'Hold released'); void reload(); }
        } }, 'Release hold') : null)),
    h('div', { class: 'panel tablewrap' }, h('h2', {}, `Targets (${jobs.items.length}${jobs.next_cursor ? '+' : ''})`),
      h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Target'), h('th', {}, 'Status'), h('th', {}, 'Updated'))),
        h('tbody', {}, ...jobs.items.map((j) => h('tr', { tabindex: 0, onclick: () => { location.hash = `#/investigate/${j.target_id}`; } }, h('td', { class: 'url' }, j.url), h('td', {}, statusChips(j)), h('td', { class: 'small' }, when(j.updated_at))))))),
    h('div', { class: 'panel' }, h('h2', {}, 'Notices'), notices.items.length ? h('ul', { class: 'timeline' }, ...notices.items.map((n) => h('li', {}, h('a', { href: `#/notices/${n.id}` }, n.route.replace(/_/g, ' ')), ' ', chip(n.state), ` · ${n.target_count} target(s) · ${n.recipient?.name ?? ''}`))) : h('p', { class: 'muted' }, 'No notices yet.'),
      hasRole('analyst', 'approver') ? h('a', { class: 'btn', href: `#/reports/new?case=${caseId}` }, 'Draft a notice') : null));
  void errorText;
}

async function api_del(path) {
  const { del } = await import('../lib.js');
  return del(path);
}
