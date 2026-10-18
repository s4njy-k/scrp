// Administration and audit (blueprint v4 §22.1 /admin, §20): accounts and roles,
// custody-chain verification, the audit log and operator metrics.
import { api, chip, clear, dialogForm, get, guard, h, hasRole, kv, pager, patch, post, shortHash, skeleton, state, when } from '../lib.js';

const ROLES = ['admin', 'intake', 'analyst', 'approver', 'evidence', 'auditor', 'report'];

function showSecret(title, secret, note) {
  const dlg = document.getElementById('dialog');
  clear(dlg, h('h2', { id: 'dialog-title' }, title), h('p', { class: 'mono big' }, secret), h('p', { class: 'small muted' }, note),
    h('div', { class: 'row' }, h('button', { type: 'button', class: 'primary', onclick: () => dlg.close() }, 'I have passed it on securely')));
  dlg.showModal();
}

async function usersPanel() {
  const panel = h('div', { class: 'panel tablewrap' }, skeleton(3));
  const load = async () => {
    const r = await get('/api/v1/admin/users');
    clear(panel, h('div', { class: 'row' }, h('h2', { class: 'grow' }, 'Accounts'),
      h('button', { type: 'button', class: 'primary', onclick: async () => {
        const f = await dialogForm('Create account', [
          { name: 'username', label: 'Username (lowercase letters, digits, . _ -)', required: true },
          { name: 'display_name', label: 'Display name', required: true },
          ...ROLES.map((x) => ({ name: `role_${x}`, label: x, type: 'checkbox' })),
        ], 'Create');
        if (!f) return;
        const u = await guard(() => post('/api/v1/admin/users', { username: f.username.trim(), display_name: f.display_name.trim(), roles: ROLES.filter((x) => f[`role_${x}`]) }), 'Account created');
        if (u) { showSecret(`One-time password for ${u.username}`, u.temporary_password, u.note); void load(); }
      } }, 'Create account')),
    h('table', {}, h('thead', {}, h('tr', {}, ...['User', 'Roles', 'MFA', 'Status', 'Last seen', ''].map((t) => h('th', {}, t)))),
      h('tbody', {}, ...r.users.map((u) => h('tr', { class: u.disabled_at ? 'muted' : '' },
        h('td', {}, u.display_name, h('div', { class: 'mono small' }, u.username)),
        h('td', { class: 'small' }, u.roles.join(', ') || '—'),
        h('td', {}, chip(u.totp_enabled ? 'verified' : 'unverified', u.totp_enabled ? 'enrolled' : 'not enrolled')),
        h('td', { class: 'small' }, u.disabled_at ? 'disabled' : u.locked_until && new Date(u.locked_until) > new Date() ? 'locked' : 'active', u.must_change_password ? h('div', { class: 'muted' }, 'must change password') : null, u.failed_logins ? h('div', { class: 'muted' }, `${u.failed_logins} failed sign-in(s)`) : null),
        h('td', { class: 'small' }, u.last_seen_at ? when(u.last_seen_at) : 'never'),
        h('td', {}, h('div', { class: 'row wrap' },
          h('button', { type: 'button', class: 'link', onclick: async () => {
            const f = await dialogForm(`Roles for ${u.username}`, [...ROLES.map((x) => ({ name: `role_${x}`, label: x, type: 'checkbox', value: u.roles.includes(x) })), { name: 'reason', label: 'Reason (recorded)', required: true }], 'Save', { intro: 'Changing roles signs the user out of every session immediately.' });
            if (f && await guard(() => patch(`/api/v1/admin/users/${u.id}`, { roles: ROLES.filter((x) => f[`role_${x}`]), reason: f.reason }), 'Roles updated')) void load();
          } }, 'Roles'),
          u.id !== state.user.id ? h('button', { type: 'button', class: 'link', onclick: async () => {
            const f = await dialogForm(u.disabled_at ? `Enable ${u.username}` : `Disable ${u.username}`, [{ name: 'reason', label: 'Reason (recorded)', required: true }], u.disabled_at ? 'Enable' : 'Disable', { danger: !u.disabled_at });
            if (f && await guard(() => patch(`/api/v1/admin/users/${u.id}`, { disabled: !u.disabled_at, reason: f.reason }), 'Account updated')) void load();
          } }, u.disabled_at ? 'Enable' : 'Disable') : null,
          h('button', { type: 'button', class: 'link', onclick: async () => {
            const f = await dialogForm(`Reset credentials for ${u.username}`, [{ name: 'reset_mfa', label: 'Also reset MFA (user re-enrols)', type: 'checkbox' }, { name: 'reason', label: 'Reason (recorded)', required: true }], 'Reset', { danger: true });
            if (!f) return;
            const r2 = await guard(() => post(`/api/v1/admin/users/${u.id}/reset-credentials`, { reset_mfa: f.reset_mfa, reason: f.reason }), 'Credentials reset');
            if (r2) { showSecret(`One-time password for ${u.username}`, r2.temporary_password, `${r2.sessions_revoked} session(s) were signed out. The user must change this password at next sign-in.`); void load(); }
          } }, 'Reset'))))))));
  };
  await load();
  return panel;
}

function custodyPanel() {
  const out = h('div');
  return h('div', { class: 'panel' }, h('h2', {}, 'Custody chain'),
    h('p', { class: 'small muted' }, 'Audit events are hash-chained and sealed every few seconds. Verification recomputes every link.'),
    h('button', { type: 'button', onclick: async () => {
      clear(out, skeleton(2));
      const r = await guard(() => get('/api/v1/custody/verify'));
      if (!r) { clear(out); return; }
      clear(out, h('div', { class: `banner ${r.ok ? 'info' : 'bad'}` }, r.ok ? 'Chain verified: every sealed event links to its predecessor.' : 'Chain verification FAILED.'),
        kv([['Sealed events', r.sealed_events], ['Awaiting seal', `${r.unsealed_events}${r.oldest_unsealed_seconds ? ` (oldest ${Math.round(r.oldest_unsealed_seconds)} s)` : ''}`], ['Head', r.head ? h('span', { class: 'mono' }, `#${r.head.chain_pos} ${r.head.event_hash}`) : '—']]),
        r.problems.length ? h('ul', {}, ...r.problems.map((p) => h('li', { class: 'mono small' }, p))) : null, h('p', { class: 'small muted' }, r.statement));
    } }, 'Verify custody chain'), out);
}

function auditPanel() {
  const body = h('tbody');
  const objectType = h('input', { type: 'text', placeholder: 'object type, e.g. notice' });
  const objectId = h('input', { type: 'text', placeholder: 'object id' });
  const pagerBox = h('div');
  const load = async (cursor) => {
    clear(body, h('tr', {}, h('td', { colspan: 6 }, skeleton(3))));
    const p = new URLSearchParams({ limit: '100' });
    if (objectType.value.trim()) p.set('object_type', objectType.value.trim());
    if (objectId.value.trim()) p.set('object_id', objectId.value.trim());
    if (cursor) p.set('cursor', cursor);
    const r = await get(`/api/v1/audit-events?${p}`);
    clear(body, ...r.items.map((e) => h('tr', {}, h('td', { class: 'small' }, when(e.at)), h('td', { class: 'small' }, e.actor, h('div', { class: 'muted' }, e.actor_kind)),
      h('td', { class: 'small' }, e.event_type), h('td', { class: 'small mono' }, e.object_type ? `${e.object_type}:${String(e.object_id ?? '').slice(0, 12)}` : '—', e.case_ref ? h('div', {}, e.case_ref) : null),
      h('td', { class: 'small' }, e.outcome ?? '—'), h('td', { class: 'small mono' }, e.chain_pos ? `#${e.chain_pos} ${shortHash(e.event_hash)}` : 'sealing…'))));
    clear(pagerBox, pager(r.next_cursor, (c) => void load(c), cursor ? () => void load() : null));
  };
  const apply = (e) => { if (e.key === 'Enter') void load(); };
  objectType.addEventListener('keydown', apply);
  objectId.addEventListener('keydown', apply);
  const panel = h('div', { class: 'panel tablewrap' }, h('h2', {}, 'Audit log'), h('div', { class: 'row' }, objectType, objectId, h('button', { type: 'button', onclick: () => void load() }, 'Filter')),
    h('table', {}, h('thead', {}, h('tr', {}, ...['When', 'Actor', 'Event', 'Object', 'Outcome', 'Chain'].map((t) => h('th', {}, t)))), body), pagerBox);
  void load();
  return panel;
}

function metricsPanel() {
  const out = h('pre', { class: 'preview small' });
  return h('details', { class: 'panel' }, h('summary', {}, 'Operator metrics (Prometheus text)'),
    h('p', { class: 'small muted' }, 'Scrapers use a bearer token (METRICS_BEARER_TOKEN). Viewing here is recorded.'),
    h('button', { type: 'button', onclick: async () => {
      const r = await guard(() => api('GET', '/api/v1/metrics', undefined, { blob: true }));
      if (r) out.textContent = await r.blob.text();
    } }, 'Load metrics'), out);
}

export async function adminView(main) {
  if (!hasRole('admin', 'auditor')) {
    clear(main, h('div', { class: 'banner bad' }, 'Administration requires the admin or auditor role.'));
    return;
  }
  clear(main, skeleton(4));
  const parts = [h('h1', {}, 'Administration and audit')];
  if (hasRole('admin')) parts.push(await usersPanel());
  parts.push(custodyPanel(), auditPanel(), metricsPanel());
  clear(main, ...parts);
}
