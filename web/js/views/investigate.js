// Single-target investigation view (blueprint v4 §22.1 /investigate, §22.4):
// left — screenshots and observed-page timeline; centre — verified leads with
// provenance; right — risk rationale, decisions, actions and context.
import { api, authImage, chip, clear, copyWithSource, dialogForm, errorText, field, get, guard, h, hasRole, kv, post, shortHash, skeleton, statusChips, toast, when } from '../lib.js';

const FIELD_LABEL = {
  upi_vpa: 'UPI ID', upi_uri: 'UPI payment link', qr_payload: 'QR payload', phone: 'Phone', whatsapp: 'WhatsApp', telegram: 'Telegram', email: 'Email',
  bank_account: 'Bank account (candidate)', ifsc: 'IFSC', crypto_btc: 'Bitcoin', crypto_eth: 'EVM address', crypto_tron: 'TRON', social_profile: 'Social profile',
  form_action: 'Form destination', api_endpoint: 'API endpoint', analytics_id: 'Analytics ID (signal)', adsense_id: 'AdSense ID (signal)', chat_widget_id: 'Chat widget (signal)',
  app_store_link: 'App store link', apk_link: 'APK download link', brand_claim: 'Brand claim (signal)', sensitive_form: 'Sensitive form field', dom_template_hash: 'Template hash (signal)',
  business_identity: 'Claimed identity', gstin: 'GSTIN (format only)', cin: 'CIN (format only)', fraud_claim_text: 'Lure phrase (signal)',
};

export async function investigateView(main, targetId) {
  clear(main, skeleton(6));
  const d = await get(`/api/v1/targets/${targetId}/investigation`);
  const latestJob = d.jobs[0] ?? {};
  const header = h('div', { class: 'panel' },
    h('div', { class: 'row' }, h('h1', { class: 'grow mono' }, d.target.url)),
    h('div', { class: 'row' }, statusChips({ acquisition: latestJob.acquisition, verdict: d.verdict, action: d.action }),
      h('span', { class: 'muted small' }, `Cases: ${d.case_refs.join(', ') || '—'} · registrable domain ${d.target.registrable_domain}`)),
    d.suppression.suppressed ? h('div', { class: 'banner warn' }, `Marked ${d.suppression.verdict?.replace('_', ' ')} on ${new Date(d.suppression.decided_at).toLocaleString()}: external actions are blocked unless an approver overrides on newer evidence.`) : null,
    h('p', { class: 'muted small' }, d.disclaimer));

  const left = h('section', { 'aria-label': 'Screenshots and timeline' });
  const centre = h('section', { 'aria-label': 'Extracted leads' });
  const right = h('section', { 'aria-label': 'Assessment and actions' });
  clear(main, header, h('div', { class: 'grid3' }, left, centre, right));

  // ---- Left: viewer + timeline
  const viewer = h('div', { class: 'viewer' });
  const overlay = { box: null };
  const meta = h('div', { class: 'small muted' });
  let currentImage = null;
  const showImage = (img) => {
    currentImage = img;
    const el = authImage(`/api/v1/artifacts/${img.id}/content?disposition=inline`, `${img.artifact_type} observed ${img.observed_start ?? ''}`);
    clear(viewer, el);
    overlay.box = null;
    clear(meta, `${img.artifact_type.replace(/_/g, ' ')} · observed `, when(img.observed_start), ' · ', chip(img.verification_state), ' · SHA-256 ', h('span', { class: 'mono' }, shortHash(img.sha256)),
      img.limitations?.length ? h('div', {}, `Limitations: ${img.limitations.join('; ')}`) : null);
    for (const b of thumbs.querySelectorAll('button')) b.setAttribute('aria-pressed', String(b.dataset.id === String(img.id)));
  };
  /** Outline the region a lead came from (bbox recorded at capture, scaled to the displayed size). */
  const highlight = (bbox, artifactId) => {
    const target = d.images.find((i) => i.id === artifactId) ?? currentImage;
    if (target && target !== currentImage) showImage(target);
    const imgEl = viewer.querySelector('img');
    if (!imgEl || !bbox) return;
    const place = () => {
      const scale = imgEl.clientWidth / (imgEl.naturalWidth || imgEl.clientWidth);
      overlay.box?.remove();
      const box = h('div', { class: 'bbox', role: 'presentation' });
      box.style.left = `${(bbox.x ?? 0) * scale}px`;
      box.style.top = `${(bbox.y ?? 0) * scale}px`;
      box.style.width = `${Math.max(6, (bbox.width ?? 20) * scale)}px`;
      box.style.height = `${Math.max(6, (bbox.height ?? 20) * scale)}px`;
      viewer.append(box);
      overlay.box = box;
      box.scrollIntoView({ block: 'center', behavior: 'smooth' });
    };
    if (imgEl.complete && imgEl.naturalWidth) place(); else imgEl.addEventListener('load', place, { once: true });
  };
  const thumbs = h('div', { class: 'shots' }, ...d.images.map((img) => h('button', { type: 'button', dataset: { id: img.id }, 'aria-pressed': 'false', onclick: () => showImage(img) },
    authImage(img.thumbnail_id ? `/api/v1/artifacts/${img.thumbnail_id}/content?disposition=inline` : `/api/v1/artifacts/${img.id}/content?disposition=inline`, img.artifact_type, 'thumb'),
    h('span', { class: 'small' }, img.artifact_type.replace('screenshot_', '').replace(/_/g, ' ')))));
  clear(left, h('div', { class: 'panel' }, h('h2', {}, 'Observed page'),
    d.images.length ? [thumbs, h('div', { class: 'stack' }, viewer, meta)] : h('p', { class: 'muted' }, 'No screenshot was captured for this target yet.'),
    d.best_capture ? h('p', { class: 'small' }, h('a', { href: `#/evidence/${d.best_capture.attempt_id}` }, 'Evidence record, manifest and hash verification →')) : null),
  h('div', { class: 'panel' }, h('h2', {}, 'Timeline'), h('ul', { class: 'timeline' }, ...d.timeline.map((t) => h('li', {},
    h('div', { class: 'chips' }, when(t.started_at), chip(t.outcome ? t.outcome.toLowerCase() : t.status), h('span', { class: 'small muted' }, `${t.kind} · ${t.engine} · ${t.capture_variant}`)),
    t.final_url && t.final_url !== d.target.url ? h('div', { class: 'small mono' }, `final: ${t.final_url}`) : null,
    t.redirect_chain?.length ? h('div', { class: 'small muted' }, `${t.redirect_chain.length} redirect(s)`) : null,
    h('div', { class: 'small' }, h('a', { href: `#/evidence/${t.id}` }, `attempt ${t.id.slice(0, 8)}`), t.manifest_sha256 ? ` · manifest ${shortHash(t.manifest_sha256)}` : ''))))),
  d.redirects.length ? h('div', { class: 'panel' }, h('h2', {}, 'Navigation and redirects'), h('ul', { class: 'timeline' }, ...d.redirects.map((r) => h('li', { class: 'small mono' }, `${r.edge_type}: ${r.from_url ?? ''} → ${r.to_url}`)))) : null,
  d.contacted_hosts.length ? h('div', { class: 'panel' }, h('h2', {}, 'Hosts contacted by the browser'), h('p', { class: 'muted small' }, 'Requested by this session; not necessarily owned by the target.'),
    h('table', {}, h('tbody', {}, ...d.contacted_hosts.map((c) => h('tr', {}, h('td', { class: 'mono small' }, c.to_host), h('td', { class: 'small right' }, c.requests)))))) : null);
  if (d.images[0]) showImage(d.images.find((i) => i.artifact_type === 'screenshot_settled') ?? d.images[0]);

  // Side-by-side comparison of original viewport images across time, profiles and vantages (sources unaltered).
  const comparable = d.timeline.filter((t) => t.kind === 'browser' && t.manifest_sha256 && !t.deleted_at);
  if (comparable.length >= 2) {
    const labelOf = (t) => `${new Date(t.started_at).toISOString().slice(0, 16).replace('T', ' ')} UTC · ${t.capture_variant} · ${t.vantage ?? ''} · ${(t.outcome ?? t.status).toLowerCase()}`;
    const pick = (i) => h('select', {}, ...comparable.map((t, j) => h('option', { value: t.id, selected: j === i }, labelOf(t))));
    const a = pick(comparable.length - 1);
    const b = pick(0);
    const panes = h('div', { class: 'compare' });
    const render = () => clear(panes, ...[a, b].map((sel) => {
      const t = comparable.find((x) => x.id === sel.value);
      return h('figure', {}, authImage(`/api/v1/attempts/${t.id}/first-image`, `Viewport of attempt ${t.id.slice(0, 8)}`),
        h('figcaption', { class: 'small' }, labelOf(t), t.final_url ? h('div', { class: 'mono' }, t.final_url) : null, h('a', { href: `#/evidence/${t.id}` }, 'evidence record')));
    }));
    a.addEventListener('change', render);
    b.addEventListener('change', render);
    left.append(h('div', { class: 'panel' }, h('h2', {}, 'Compare captures'),
      h('p', { class: 'small muted' }, 'Original viewport images side by side. Differences in time, device profile or vantage are shown, not interpreted; a mobile user agent is not a mobile-network vantage.'),
      h('div', { class: 'row' }, field('Earlier', a), field('Later', b)), panes));
    render();
  }

  // ---- Centre: leads with provenance
  const signalTypes = new Set(['analytics_id', 'adsense_id', 'chat_widget_id', 'dom_template_hash', 'brand_claim', 'business_identity', 'fraud_claim_text', 'api_endpoint']);
  const leads = d.identifiers.filter((i) => !signalTypes.has(i.field_type));
  const signals = d.identifiers.filter((i) => signalTypes.has(i.field_type));
  const leadCard = (i) => {
    const p = i.provenance?.[0] ?? {};
    const source = `${p.source_url ?? d.target.url}, captured ${p.observed_at ?? ''} UTC, attempt ${p.attempt_id ?? ''}, method ${p.method}, artifact SHA-256 ${p.artifact_sha256 ?? 'n/a'}`;
    return h('div', { class: 'lead' },
      h('div', { class: 'row' }, h('div', { class: 'grow' }, h('div', { class: 'small muted' }, FIELD_LABEL[i.field_type] ?? i.field_type), h('div', { class: 'val' }, i.normalised_value ?? i.raw_value)),
        chip(i.review_state), i.other_targets_in_scope ? h('span', { class: 'chip warn', title: 'Seen on other targets in your scope' }, `+${i.other_targets_in_scope} sites`) : null),
      i.raw_value !== i.normalised_value ? h('div', { class: 'small muted mono' }, `raw: ${i.raw_value}`) : null,
      h('div', { class: 'small muted' }, `${i.methods.join(', ')} · ${i.validation_states.join(', ')} · ${i.display_contexts.join(', ')} · confidence ${i.confidence ?? '—'} · ${i.attempts} capture(s)`),
      (i.conflicts ?? []).flat().length ? h('div', { class: 'banner warn small' }, (i.conflicts ?? []).flat().map((c) => c.detail).join('; ')) : null,
      p.context ? h('div', { class: 'small' }, `“${p.context}”`) : null,
      h('div', { class: 'row' },
        p.bbox ? h('button', { type: 'button', class: 'link', onclick: () => highlight(p.bbox, p.artifact_id) }, 'Show on screenshot') : null,
        h('button', { type: 'button', class: 'link', onclick: () => copyWithSource(i.normalised_value ?? i.raw_value, source) }, 'Copy with source'),
        hasRole('analyst', 'approver', 'admin') ? h('button', { type: 'button', class: 'link', onclick: () => reviewLead(i) }, 'Review') : null,
        h('button', { type: 'button', class: 'link', onclick: () => searchEntity(i) }, 'Find elsewhere')),
      i.review ? h('div', { class: 'small muted' }, `${i.review.state} by ${i.review.actor}: ${i.review.reason}`) : null);
  };
  const reviewLead = async (i) => {
    const r = await dialogForm(`Review ${FIELD_LABEL[i.field_type] ?? i.field_type}`, [
      { name: 'state', label: 'Interpretation', type: 'select', options: ['candidate', 'corroborated', 'rejected', 'unverified'], value: i.review_state },
      { name: 'reason_code', label: 'Reason', type: 'select', options: ['confirmed_by_second_source', 'confirmed_by_official_channel', 'ocr_error', 'format_invalid', 'not_displayed', 'third_party_resource', 'duplicate', 'other'] },
      { name: 'reason', label: 'Explanation', type: 'textarea', required: true },
      { name: 'corrected', label: 'Corrected value (optional; the original stays unchanged)', type: 'text' },
      { name: 'evidence', label: 'Evidence reference (required to corroborate)', type: 'text' },
    ], 'Record');
    if (!r) return;
    await guard(() => post('/api/v1/identifier-reviews', { target_id: Number(targetId), field_type: i.field_type, value_key: i.value_key, state: r.state, reason_code: r.reason_code, reason: r.reason,
      ...(r.corrected ? { corrected_value: r.corrected } : {}), evidence_refs: r.evidence ? [{ kind: 'external', id: r.evidence }] : [] }), 'Interpretation recorded');
    void investigateView(main, targetId);
  };
  const searchEntity = async (i) => {
    const r = await dialogForm('Search other captures', [{ name: 'purpose', label: 'Purpose of this search (recorded)', type: 'text', required: true }], 'Search');
    if (!r) return;
    const res = await guard(() => api('GET', `/api/v1/entities?type=${encodeURIComponent(i.field_type)}&value=${encodeURIComponent(i.normalised_value ?? i.raw_value)}`, undefined, { headers: { 'X-Purpose': r.purpose } }));
    if (!res) return;
    const dlg = document.getElementById('dialog');
    clear(dlg, h('h2', { id: 'dialog-title' }, `${res.distinct_targets} site(s) in your scope`), h('p', { class: 'muted small' }, res.note),
      h('ul', {}, ...res.results.slice(0, 50).map((x) => h('li', {}, h('a', { href: `#/investigate/${x.target_id}`, onclick: () => dlg.close() }, x.url), ' ', when(x.observed_at)))),
      h('button', { type: 'button', onclick: () => dlg.close() }, 'Close'));
    dlg.showModal();
  };
  clear(centre, h('div', { class: 'panel' }, h('h2', {}, `Leads (${leads.length})`),
    leads.length ? leads.map(leadCard) : h('p', { class: 'muted' }, 'No payment or contact identifiers were extracted. An absence is not evidence that the page is benign.'),
    h('details', {}, h('summary', {}, 'Field status (observed / not observed / failed)'), h('table', {}, h('tbody', {}, ...d.field_status.map((f) => h('tr', {}, h('td', { class: 'small' }, FIELD_LABEL[f.field_type] ?? f.field_type), h('td', {}, chip(f.status === 'observed' ? 'content_captured' : f.status === 'extraction_failed' ? 'failed' : 'none', f.status), ' ', f.status))))))),
  signals.length ? h('div', { class: 'panel' }, h('h2', {}, 'Signals (not identity)'), h('p', { class: 'muted small' }, 'Shared SDKs, templates and brand mentions are weak signals and never attribution on their own.'), signals.map(leadCard)) : null);

  // ---- Right: risk, decisions, actions, context
  const risk = d.risk;
  const decisionPanel = h('div', { class: 'panel' }, h('h2', {}, 'Analyst decision'),
    h('p', {}, 'Current verdict: ', chip(d.verdict)),
    hasRole('analyst', 'approver', 'admin') ? h('button', { type: 'button', class: 'primary', onclick: async () => {
      const opts = ['retain', 'investigate', 'confirm_suspicious', 'likely_malicious', 'escalate_for_approval', 'false_positive', 'benign', 'inconclusive', 'recapture'];
      if (d.suppression.suppressed && hasRole('approver')) opts.push('override_suppression');
      const r = await dialogForm('Record decision', [
        { name: 'decision', label: 'Decision', type: 'select', options: opts },
        { name: 'reason_code', label: 'Reason code', type: 'select', options: Object.entries(d.reason_codes).map(([value, label]) => ({ value, label })) },
        { name: 'reason', label: 'Reasoning (required; never erased)', type: 'textarea', required: true },
        ...(d.suppression.suppressed ? [{ name: 'attempt', label: 'Newer evidence attempt (required to override)', type: 'select', options: [{ value: '', label: '—' }, ...d.suppression.newer_attempts.map((a) => ({ value: a, label: a }))] }] : []),
      ], 'Record decision');
      if (!r) return;
      await guard(() => post('/api/v1/decisions', { target_id: Number(targetId), decision: r.decision, reason_code: r.reason_code, reason: r.reason,
        expected_last_decision_id: d.decisions[0]?.id ?? null, ...(r.attempt ? { new_evidence_attempt: r.attempt } : {}) }), 'Decision recorded');
      void investigateView(main, targetId);
    } }, 'Record decision') : null,
    d.decisions.length ? h('ul', { class: 'timeline' }, ...d.decisions.slice(0, 10).map((x) => h('li', { class: 'small' }, chip(x.verdict), ` ${x.decision.replace(/_/g, ' ')} by ${x.actor} · `, when(x.created_at), h('div', { class: 'muted' }, `${x.reason_code}: ${x.reason}`)))) : null);

  const riskPanel = h('div', { class: 'panel' }, h('h2', {}, 'Triage score (not a finding)'),
    risk ? [h('p', {}, chip(risk.band), ` score ${risk.score}/100 · capture quality `, chip(risk.capture_quality === 'content_captured' ? 'content_captured' : risk.capture_quality === 'partial' ? 'partial' : 'blocked', risk.capture_quality), h('span', { class: 'small muted' }, ` · ${risk.policy_version}`)),
      ...risk.signals.map((s) => h('div', { class: 'signal small' }, h('span', {}, s.label, h('div', { class: 'muted mono' }, s.evidence.slice(0, 3).join(' · '))), h('span', { class: 'mono' }, s.weight > 0 ? `+${s.weight}` : String(s.weight)))),
      risk.benign_context.length ? h('div', { class: 'banner info small' }, risk.benign_context.map((b) => b.label).join(' ')) : null,
      risk.conflicts.length ? h('div', { class: 'banner warn small' }, risk.conflicts.map((c) => c.label).join(' ')) : null]
      : h('p', { class: 'muted' }, 'No assessment yet (computed after extraction).'));

  const actionPanel = h('div', { class: 'panel' }, h('h2', {}, 'External actions'),
    d.notices.length ? h('ul', { class: 'timeline' }, ...d.notices.map((n) => h('li', {}, h('a', { href: `#/notices/${n.id}` }, n.route.replace(/_/g, ' ')), ' ', chip(n.state), h('div', { class: 'small muted' }, `${n.recipient?.name ?? ''} · target ${n.target_status}`)))) : h('p', { class: 'muted small' }, 'No notices. Nothing is ever sent automatically.'),
    hasRole('analyst', 'approver') && !d.suppression.suppressed ? h('a', { class: 'btn', href: `#/reports/new?target=${targetId}` }, 'Draft a notice') : null);

  const lazyPanel = (title, path, render) => {
    const body = h('div', {}, h('button', { type: 'button', onclick: async () => { clear(body, skeleton(2)); try { clear(body, render(await get(path))); } catch (e) { clear(body, errorText(e)); } } }, `Load ${title.toLowerCase()}`));
    return h('div', { class: 'panel' }, h('h2', {}, title), body);
  };

  clear(right, riskPanel, decisionPanel, actionPanel,
    lazyPanel('Related sites', `/api/v1/targets/${targetId}/related`, (r) => h('div', {}, h('p', { class: 'muted small' }, r.rule),
      r.items.length ? h('ul', { class: 'timeline' }, ...r.items.map((x) => h('li', {}, h('a', { href: `#/investigate/${x.target_id}` }, x.url), ' ', chip(x.relationship === 'possible_relationship' ? 'suspicious' : 'none', x.relationship), h('div', { class: 'small' }, x.explanation), x.contradictions.length ? h('div', { class: 'small muted' }, x.contradictions.join(' ')) : null))) : h('p', { class: 'muted' }, 'No shared identifiers in your scope.'))),
    lazyPanel('Infrastructure and addressees', `/api/v1/targets/${targetId}/addressees`, (r) => h('div', {}, h('p', { class: 'muted small' }, r.note),
      r.addressees.length ? h('ul', { class: 'timeline' }, ...r.addressees.map((a) => h('li', {}, h('strong', {}, a.role.replace('_', ' ')), `: ${a.name ?? 'unknown'}`, a.contact ? h('div', { class: 'mono small' }, a.contact) : null, h('div', { class: 'small muted' }, `${a.confidence} — ${a.note}`)))) : h('p', { class: 'muted' }, 'Enrichment not available yet.'),
      h('div', { class: 'small muted' }, r.sources.map((s) => `${s.source}: ${s.status}`).join(' · ')),
      hasRole('analyst') ? h('button', { type: 'button', onclick: () => guard(() => post(`/api/v1/targets/${targetId}/enrich`), 'Enrichment refresh queued') }, 'Refresh enrichment') : null)),
    lazyPanel('Lookalike check', `/api/v1/targets/${targetId}/lookalikes`, (r) => h('div', {}, r.matches.length ? h('ul', {}, ...r.matches.map((m) => h('li', {}, `${m.kind}: ${m.candidateLabel} resembles ${m.comparedTo} (${m.brandName})`))) : h('p', { class: 'muted' }, 'No lookalike match.'),
      r.context.official ? h('div', { class: 'banner info small' }, `Listed official domain of ${r.context.official.brandName}`) : null, h('p', { class: 'muted small' }, r.note))),
    h('div', { class: 'panel' }, h('h2', {}, 'Monitoring'),
      d.monitoring.length ? h('ul', { class: 'timeline' }, ...d.monitoring.map((m) => h('li', { class: 'small' }, chip(m.active ? 'capturing' : 'none', m.active ? 'active' : 'stopped'), ` every ${m.interval_hours} h · ${m.revisits} revisit(s)`, (m.observations ?? []).slice(0, 3).map((o) => h('div', {}, chip(o.outcome_class), ' ', when(o.created_at)))))) : h('p', { class: 'muted small' }, 'No revisit schedule.'),
      hasRole('analyst', 'approver') && d.case_refs.length ? h('button', { type: 'button', onclick: async () => {
        const cases = (await get('/api/v1/cases?limit=200')).items.filter((c) => d.case_refs.includes(c.case_ref));
        const r = await dialogForm('Schedule revisits', [
          { name: 'case_id', label: 'Case', type: 'select', options: cases.map((c) => ({ value: c.id, label: c.case_ref })) },
          { name: 'interval', label: 'Interval (hours)', type: 'number', value: '24', min: 6 },
          { name: 'days', label: 'For how many days', type: 'number', value: '30', min: 1 },
          { name: 'reason', label: 'Reason (e.g. verify takedown after notice)', type: 'textarea', required: true },
        ], 'Schedule');
        if (!r) return;
        await guard(() => post('/api/v1/monitoring/rules', { target_id: Number(targetId), case_id: r.case_id, interval_hours: Number(r.interval), duration_days: Number(r.days), reason: r.reason }), 'Revisits scheduled (each creates a new capture)');
      } }, 'Schedule revisits') : null),
    h('div', { class: 'panel' }, h('h2', {}, 'Notes'),
      d.annotations.length ? h('ul', { class: 'timeline' }, ...d.annotations.map((a) => h('li', { class: 'small' }, a.body, h('div', { class: 'muted' }, `${a.actor} · `, when(a.created_at))))) : h('p', { class: 'muted small' }, 'No notes. Notes never change evidence.'),
      hasRole('analyst', 'approver') ? h('button', { type: 'button', onclick: async () => {
        const r = await dialogForm('Add note', [{ name: 'body', label: 'Note', type: 'textarea', required: true }], 'Add');
        if (!r) return;
        await guard(() => post('/api/v1/annotations', { object_type: 'target', object_id: String(targetId), body: r.body }), 'Note added');
        void investigateView(main, targetId);
      } }, 'Add note') : null),
    h('div', { class: 'panel' }, h('h2', {}, 'Infrastructure facts'), d.enrichment.length ? kv(d.enrichment.map((e) => [`${e.source} (${e.subject})`, `${e.status} · ${new Date(e.retrieved_at).toLocaleString()}${e.error ? ` · ${e.error}` : ''}`])) : h('p', { class: 'muted small' }, 'Not enriched yet.')));
  void toast;
  void field;
}
