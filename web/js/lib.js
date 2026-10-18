// Shared helpers for the analyst console. DOM is built with createElement and
// textContent only: page-derived text (titles, identifiers, URLs) is never
// interpreted as HTML.

export const state = { user: null, csrf: null, policy: null };

/** h('div', {class: 'x', onclick: fn}, child, 'text', [more]) */
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = Boolean(v);
    else if (k === 'html') throw new Error('raw HTML is not allowed');
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

export function clear(el, ...children) {
  el.replaceChildren();
  append(el, children);
  return el;
}

export class ApiError extends Error {
  constructor(status, body) {
    super(body?.error?.message ?? `HTTP ${status}`);
    this.status = status;
    this.code = body?.error?.code ?? 'error';
    this.details = body?.error?.details;
    this.requestId = body?.error?.request_id;
  }
}

/** Fetch wrapper: same-origin cookies, CSRF header on mutations, JSON in/out, typed errors. */
export async function api(method, path, body, opts = {}) {
  const headers = { ...(opts.headers ?? {}) };
  if (method !== 'GET' && state.csrf) headers['X-CSRF-Token'] = state.csrf;
  let payload;
  if (opts.raw !== undefined) {
    payload = opts.raw;
    headers['Content-Type'] = opts.contentType ?? 'application/octet-stream';
  } else if (body !== undefined) {
    payload = JSON.stringify(body);
    headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(path, { method, headers, body: payload, credentials: 'same-origin', cache: 'no-store' });
  if (opts.blob) {
    if (!res.ok) throw new ApiError(res.status, await res.json().catch(() => null));
    return { blob: await res.blob(), headers: res.headers };
  }
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (data && typeof data.csrf_token === 'string') state.csrf = data.csrf_token;
  if (!res.ok) {
    const err = new ApiError(res.status, data);
    if (res.status === 401 && !opts.allow401) {
      state.user = null;
      location.hash = '#/login';
    }
    throw err;
  }
  return data;
}

export const get = (p, o) => api('GET', p, undefined, o);
export const post = (p, b, o) => api('POST', p, b ?? {}, o);
export const patch = (p, b) => api('PATCH', p, b);
export const del = (p) => api('DELETE', p);

export function toast(message, kind = '') {
  const t = h('div', { class: `toast ${kind}` }, message);
  document.getElementById('toasts').append(t);
  setTimeout(() => t.remove(), kind === 'bad' ? 9000 : 4500);
}

export function errorText(e) {
  if (e instanceof ApiError) {
    const extra = e.details?.failures ? ` — ${e.details.failures.map((f) => f.message).join(' ')}` : e.details?.gaps ? ` — fields: ${e.details.gaps.join(', ')}` : '';
    return `${e.message}${extra}${e.requestId ? ` (request ${e.requestId.slice(0, 8)})` : ''}`;
  }
  return String(e?.message ?? e);
}

export async function guard(fn, okMessage) {
  try {
    const r = await fn();
    if (okMessage) toast(okMessage);
    return r;
  } catch (e) {
    toast(errorText(e), 'bad');
    return undefined;
  }
}

const IST_OFFSET = 5.5 * 3600 * 1000;
export function ist(v) {
  if (!v) return '—';
  const d = new Date(new Date(v).getTime() + IST_OFFSET);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} IST`;
}
export function utc(v) {
  return v ? `${new Date(v).toISOString().replace('T', ' ').slice(0, 19)} UTC` : '—';
}
/** Both times, as the blueprint requires: IST for display, UTC as the stored truth. */
export function when(v) {
  return h('span', { title: utc(v) }, ist(v));
}

const CHIP_KIND = {
  content_captured: 'ok', partial: 'warn', challenge: 'warn', blocked: 'bad', auth_required: 'warn', timed_out: 'warn', dns_failure: 'bad', tls_failure: 'bad',
  not_found: 'bad', parked: 'info', suspended: 'info', unavailable: 'bad', infrastructure_deferred: 'warn', egress_denied: 'bad', manual_review: 'warn', failed: 'bad',
  queued: '', capturing: 'info',
  unreviewed: '', suspicious: 'warn', likely_malicious: 'bad', benign: 'ok', false_positive: 'ok', inconclusive: '',
  none: '', draft: '', analyst_review: 'info', legal_check: 'info', approved: 'info', generated: 'info', issued: 'warn', acknowledged: 'warn',
  complied: 'ok', partially_complied: 'warn', rejected: 'bad', no_response: 'bad', verified_closed: 'ok', escalated: 'bad', withdrawn: '', disputed: 'bad',
  high: 'bad', medium: 'warn', low: 'ok', insufficient_evidence: '',
  verified: 'ok', verified_at_commit: 'ok', mismatch: 'bad', missing: 'bad', unverified: '', candidate: 'info', corroborated: 'ok',
  pass: 'ok', fail: 'bad', still_live: 'bad', observed_changed_content: 'warn', temporarily_unreachable: 'warn', challenged: 'warn',
  blocked_at_tested_vantage: 'info', dns_not_resolving: 'info', parked_or_suspended_page: 'info', redirected_elsewhere: 'warn', provider_confirmed_suspension: 'ok', reported_removal: 'ok',
};
export function chip(value, label) {
  const v = value ?? 'none';
  return h('span', { class: `chip ${CHIP_KIND[v] ?? ''}`, title: label ? `${label}: ${v}` : v }, String(v).replace(/_/g, ' '));
}
/** The three status fields, always shown together and never merged. */
export function statusChips(o) {
  return h('span', { class: 'chips' },
    h('span', { class: 'chiplabel' }, 'Acquisition'), chip(o.acquisition, 'Acquisition result'),
    h('span', { class: 'chiplabel' }, 'Verdict'), chip(o.verdict ?? 'unreviewed', 'Investigative verdict'),
    h('span', { class: 'chiplabel' }, 'Action'), chip(o.action ?? 'none', 'External action status'));
}

/** Modal form. fields: [{name, label, type: text|textarea|select|checkbox|number, options, required, value, help}] */
export function dialogForm(title, fields, submitLabel = 'Confirm', { danger = false, intro = null } = {}) {
  const dlg = document.getElementById('dialog');
  return new Promise((resolve) => {
    const inputs = {};
    const form = h('form', { method: 'dialog', class: 'stack' },
      h('h2', { id: 'dialog-title' }, title),
      intro ? h('p', { class: 'muted' }, intro) : null,
      ...fields.map((f) => {
        const id = `f-${f.name}`;
        let input;
        if (f.type === 'textarea') input = h('textarea', { id, name: f.name, required: f.required, rows: 4 }, f.value ?? '');
        else if (f.type === 'select') input = h('select', { id, name: f.name, required: f.required }, ...(f.options ?? []).map((o) => h('option', { value: o.value ?? o, selected: (o.value ?? o) === f.value }, o.label ?? o)));
        else if (f.type === 'checkbox') input = h('input', { id, name: f.name, type: 'checkbox', checked: f.value, required: f.required });
        else input = h('input', { id, name: f.name, type: f.type ?? 'text', required: f.required, value: f.value ?? '', ...(f.min !== undefined ? { min: f.min } : {}) });
        inputs[f.name] = input;
        return f.type === 'checkbox'
          ? h('label', { class: 'checkline', for: id }, input, f.label)
          : h('div', {}, h('label', { for: id }, f.label), input, f.help ? h('div', { class: 'muted small' }, f.help) : null);
      }),
      h('div', { class: 'row' },
        h('button', { type: 'submit', class: danger ? 'danger' : 'primary', value: 'ok' }, submitLabel),
        h('button', { type: 'button', onclick: () => { dlg.close(); resolve(null); } }, 'Cancel')));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      const out = {};
      for (const [k, el] of Object.entries(inputs)) out[k] = el.type === 'checkbox' ? el.checked : el.value;
      dlg.close();
      resolve(out);
    });
    clear(dlg, form);
    dlg.addEventListener('cancel', () => resolve(null), { once: true });
    dlg.showModal();
    form.querySelector('input,select,textarea')?.focus();
  });
}

export function confirmDialog(title, text) {
  return dialogForm(title, [], 'Confirm', { intro: text }).then((r) => r !== null);
}

/** Copy a value together with its source citation (checklist §10 "copy with source"). */
export async function copyWithSource(value, source) {
  const text = `${value}\n— source: ${source}`;
  try {
    await navigator.clipboard.writeText(text);
    toast('Copied with source citation');
  } catch {
    toast('Clipboard unavailable; select and copy manually', 'bad');
  }
}

/** Download an authenticated binary response under a safe name. */
export async function download(path, filename, headers = {}) {
  const r = await guard(() => api('GET', path, undefined, { blob: true, headers }));
  if (!r) return;
  const url = URL.createObjectURL(r.blob);
  const a = h('a', { href: url, download: filename });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** An <img> loaded through fetch so failures are explained and nothing is cached in the browser. */
export function authImage(path, alt, cls = '') {
  const img = h('img', { alt, class: cls, loading: 'lazy', decoding: 'async' });
  const io = new IntersectionObserver(async (entries) => {
    if (!entries.some((e) => e.isIntersecting)) return;
    io.disconnect();
    try {
      const r = await api('GET', path, undefined, { blob: true });
      img.src = URL.createObjectURL(r.blob);
      img.title = `${alt}${r.headers.get('x-evidence-status') ? ` (${r.headers.get('x-evidence-status')})` : ''} — SHA-256 ${r.headers.get('x-evidence-sha256') ?? ''}`;
    } catch (e) {
      img.alt = `${alt}: ${errorText(e)}`;
    }
  });
  io.observe(img);
  return img;
}

export function field(labelText, input, help) {
  const id = input.id || `i-${Math.random().toString(36).slice(2, 9)}`;
  input.id = id;
  return h('div', {}, h('label', { for: id }, labelText), input, help ? h('div', { class: 'muted small' }, help) : null);
}

export function hasRole(...roles) {
  return Boolean(state.user?.roles?.some((r) => roles.includes(r)));
}

export function kv(pairs) {
  return h('dl', { class: 'kv' }, ...pairs.filter(Boolean).flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v ?? '—')]));
}

export function skeleton(lines = 3) {
  return h('div', { class: 'stack', 'aria-busy': 'true' }, ...Array.from({ length: lines }, () => h('div', { class: 'skeleton' })));
}

export function pager(nextCursor, onNext, onFirst) {
  return h('div', { class: 'pager' },
    onFirst ? h('button', { type: 'button', onclick: onFirst }, 'First page') : null,
    h('button', { type: 'button', disabled: !nextCursor, onclick: () => onNext(nextCursor) }, 'Next page'));
}

export function shortHash(s) {
  return s ? `${s.slice(0, 12)}…` : '—';
}
