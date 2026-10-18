// Analyst console entry point: session bootstrap, sign-in steps and hash routing.
import { api, clear, errorText, field, get, h, hasRole, post, state, toast } from './js/lib.js';
import { jobsView, intakeView } from './js/views/jobs.js';
import { investigateView } from './js/views/investigate.js';
import { casesView, caseView } from './js/views/cases.js';
import { reviewView } from './js/views/review.js';
import { evidenceView } from './js/views/evidence.js';
import { noticesView, noticeView, newNoticeView, certificateView } from './js/views/actions.js';
import { monitorView } from './js/views/monitor.js';
import { analyticsView } from './js/views/analytics.js';
import { adminView } from './js/views/admin.js';

const main = document.getElementById('main');

const NAV = [
  ['#/jobs', 'Jobs'], ['#/intake', 'Intake'], ['#/review', 'Review'], ['#/cases', 'Cases'], ['#/reports', 'Reports'],
  ['#/monitor', 'Monitor'], ['#/analytics', 'Analytics'], ['#/admin', 'Admin', ['admin', 'auditor']],
];

const ROUTES = [
  [/^#\/jobs$/, jobsView], [/^#\/intake$/, intakeView], [/^#\/investigate\/(\d+)$/, investigateView], [/^#\/cases$/, casesView],
  [/^#\/cases\/([0-9a-f-]{36})$/, caseView], [/^#\/review$/, reviewView], [/^#\/evidence\/([0-9a-f-]{36})$/, evidenceView],
  [/^#\/reports$/, noticesView], [/^#\/reports\/new$/, newNoticeView], [/^#\/notices\/([0-9a-f-]{36})$/, noticeView],
  [/^#\/certificates\/([0-9a-f-]{36})$/, certificateView], [/^#\/monitor$/, monitorView], [/^#\/analytics$/, analyticsView], [/^#\/admin$/, adminView],
];

function renderChrome() {
  const bar = document.getElementById('topbar');
  bar.hidden = !state.user;
  if (!state.user) return;
  const nav = clear(document.getElementById('nav'), ...NAV.filter(([, , roles]) => !roles || hasRole(...roles)).map(([href, label]) =>
    h('a', { href, ...(location.hash.startsWith(href) ? { 'aria-current': 'page' } : {}) }, label)));
  void nav;
  clear(document.getElementById('who'),
    h('span', { class: 'muted small', title: `Roles: ${state.user.roles.join(', ')}` }, `${state.user.display_name} (${state.user.username})`),
    h('button', { type: 'button', onclick: logout }, 'Sign out'));
}

async function logout() {
  await api('POST', '/api/v1/auth/logout', {}).catch(() => undefined);
  state.user = null;
  state.csrf = null;
  location.hash = '#/login';
}

async function refreshMe() {
  try {
    const me = await api('GET', '/api/v1/auth/me', undefined, { allow401: true });
    state.user = me.user;
    state.policy = me.policy;
    return me.next;
  } catch {
    state.user = null;
    return 'login';
  }
}

function loginView() {
  const user = h('input', { type: 'text', autocomplete: 'username', required: true });
  const pass = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const msg = h('p', { class: 'muted', role: 'alert' });
  const form = h('form', { class: 'panel login stack', onsubmit: async (ev) => {
    ev.preventDefault();
    msg.textContent = '';
    try {
      const r = await post('/api/v1/auth/login', { username: user.value, password: pass.value });
      pass.value = '';
      state.user = r.user;
      await continueAfter(r.next);
    } catch (e) {
      msg.textContent = errorText(e);
    }
  } },
  h('h1', {}, 'Sign in'),
  h('p', { class: 'muted small' }, 'Restricted system. Every access to evidence is recorded in the custody log.'),
  field('Username', user), field('Password', pass), h('button', { class: 'primary', type: 'submit' }, 'Continue'), msg);
  clear(main, form);
  user.focus();
}

function mfaView() {
  const code = h('input', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', pattern: '\\d{6}', maxlength: 6, required: true });
  const msg = h('p', { role: 'alert', class: 'muted' });
  clear(main, h('form', { class: 'panel login stack', onsubmit: async (ev) => {
    ev.preventDefault();
    try {
      const r = await post('/api/v1/auth/mfa/verify', { code: code.value });
      await continueAfter(r.next);
    } catch (e) { msg.textContent = errorText(e); }
  } }, h('h1', {}, 'Authenticator code'), field('6-digit code', code), h('button', { class: 'primary', type: 'submit' }, 'Verify'), msg));
  code.focus();
}

async function enrolView() {
  const msg = h('p', { role: 'alert', class: 'muted' });
  let enrol;
  try {
    enrol = await post('/api/v1/auth/mfa/enrol');
  } catch (e) {
    clear(main, h('div', { class: 'panel login' }, errorText(e)));
    return;
  }
  const code = h('input', { type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 6, required: true });
  clear(main, h('form', { class: 'panel login stack', onsubmit: async (ev) => {
    ev.preventDefault();
    try {
      const r = await post('/api/v1/auth/mfa/confirm', { code: code.value });
      await continueAfter(r.next);
    } catch (e) { msg.textContent = errorText(e); }
  } },
  h('h1', {}, 'Set up multi-factor authentication'),
  h('p', {}, 'Add this account to an authenticator app (TOTP, 6 digits, 30 seconds) using the secret below, then enter a code.'),
  h('p', { class: 'mono' }, enrol.secret),
  h('details', {}, h('summary', {}, 'otpauth URI'), h('p', { class: 'mono small' }, enrol.otpauth_uri)),
  field('Code from the app', code), h('button', { class: 'primary', type: 'submit' }, 'Confirm'), msg));
  code.focus();
}

function passwordView() {
  const cur = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const next = h('input', { type: 'password', autocomplete: 'new-password', required: true, minlength: 12 });
  const msg = h('p', { role: 'alert', class: 'muted' });
  clear(main, h('form', { class: 'panel login stack', onsubmit: async (ev) => {
    ev.preventDefault();
    try {
      await post('/api/v1/auth/password', { current_password: cur.value, new_password: next.value });
      toast('Password changed; other sessions were signed out');
      await continueAfter(null);
    } catch (e) { msg.textContent = errorText(e); }
  } }, h('h1', {}, 'Choose a new password'), h('p', { class: 'muted small' }, 'At least 12 characters. A passphrase is fine.'),
  field('Current (one-time) password', cur), field('New password', next), h('button', { class: 'primary', type: 'submit' }, 'Save'), msg));
}

async function continueAfter(next) {
  if (next === 'mfa') return mfaView();
  if (next === 'enrol_mfa') return enrolView();
  if (next === 'change_password') return passwordView();
  await refreshMe();
  if (location.hash === '#/login' || !location.hash) location.hash = '#/jobs';
  else await route();
}

async function route() {
  const hash = location.hash || '#/jobs';
  if (!state.user) {
    const next = await refreshMe();
    if (!state.user) return loginView();
    if (next) return continueAfter(next);
  }
  if (hash === '#/login') {
    location.hash = '#/jobs';
    return undefined;
  }
  renderChrome();
  // Views read their own query (e.g. #/reports/new?target=12) from location.hash.
  const path = hash.split('?')[0];
  for (const [re, view] of ROUTES) {
    const m = re.exec(path);
    if (m) {
      clear(main);
      try {
        await view(main, ...m.slice(1));
      } catch (e) {
        clear(main, h('div', { class: 'banner bad' }, errorText(e)));
      }
      main.focus({ preventScroll: true });
      return undefined;
    }
  }
  clear(main, h('p', { class: 'pad' }, 'Not found. ', h('a', { href: '#/jobs' }, 'Go to jobs')));
  return undefined;
}

window.addEventListener('hashchange', () => void route());
void route();
export { get };
