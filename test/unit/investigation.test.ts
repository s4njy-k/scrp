import { domainToASCII } from 'node:url';
import { describe, expect, it } from 'vitest';
import { domainContext, editDistance, findBrandClaims, findLookalikes, skeleton } from '../../src/investigation/brands.js';
import { assessRisk, type RiskInput } from '../../src/investigation/risk.js';
import { confidenceFor, domTemplateHash, extractFromHtmlAttributes, extractFromText, valueKey, type TextSource } from '../../src/extraction/identifiers.js';
import { keccak256 } from '../../src/extraction/validators.js';
import { acquisitionChip, liveStage } from '../../src/web/status.js';

const src = (text: string, over: Partial<TextSource> = {}): TextSource => ({ text, method: 'dom', displayContext: 'displayed', sourceUrl: 'https://x.example/', artifactSha256: 'abc', ...over });

describe('brand claims and lookalike domains (signals, never verdicts)', () => {
  it('matches brand names on word boundaries and acronyms case-sensitively', () => {
    expect(findBrandClaims('Update your State Bank of India KYC today').map((c) => c.brandId)).toEqual(['sbi']);
    expect(findBrandClaims('Login to SBI YONO').map((c) => c.brandId)).toEqual(['sbi']);
    expect(findBrandClaims('the sbiscus flower and absbi')).toEqual([]);
    expect(findBrandClaims('Pay via Paytm or PhonePe').map((c) => c.brandId).sort()).toEqual(['paytm', 'phonepe']);
  });

  it('detects homoglyph, punycode, typosquat and combosquat domains and exempts official/affiliate domains', () => {
    expect(skeleton('paytrn')).toBe(skeleton('paytm'));
    expect(editDistance('hdfcbank', 'hdfcbnak')).toBe(1);
    const kinds = (h: string) => findLookalikes(h).map((m) => `${m.brandId}:${m.kind}`);
    expect(kinds('paytrn.com')).toContain('paytm:homoglyph');
    expect(kinds('hdfcbnak.com')).toContain('hdfc_bank:typosquat');
    expect(kinds('onlinesbi-kyc-update.in')).toContain('sbi:combosquat');
    expect(kinds('sbi.kyc-verify.example')).toContain('sbi:combosquat');
    expect(kinds('hdfcbank.co')).toContain('hdfc_bank:combosquat');
    const cyrillic = domainToASCII('аxisbank.com'); // first letter is Cyrillic U+0430
    expect(cyrillic.startsWith('xn--')).toBe(true);
    expect(kinds(cyrillic)).toContain('axis_bank:punycode_homoglyph');
    expect(findLookalikes('sbi.co.in')).toEqual([]);
    expect(findLookalikes('retail.onlinesbi.sbi')).toEqual([]);
    expect(findLookalikes('sbicard.com')).toEqual([]);
    expect(findLookalikes('weather.example')).toEqual([]);
    expect(domainContext('www.incometax.gov.in')).toMatchObject({ governmentTld: true, official: { brandId: 'income_tax' } });
    expect(domainContext('scam.blogspot.com').userContentPlatform).toBe(true);
  });
});

describe('explainable risk triage (separate from capture quality)', () => {
  const base: RiskInput = { hostname: 'sbi-refund-desk.example', outcome: 'CONTENT_CAPTURED', classification: 'content_captured', requiredSatisfied: true, identifiers: [], sharedWithJudged: [], registeredDaysAgo: null, priorFalsePositive: false };
  const id = (field_type: string, normalised_value: string, method = 'dom', display_context = 'displayed') => ({ field_type, normalised_value, validation_state: 'format_valid', display_context, method, conflicts: [] });

  it('scores a payment lure impersonating a bank as high, with labelled evidence for every signal', () => {
    const r = assessRisk({ ...base, identifiers: [id('upi_vpa', 'refund@ybl'), id('upi_uri', 'upi://pay?pa=refund@ybl', 'qr'), id('fraud_claim_text', 'kyc update'), id('brand_claim', 'sbi'), id('analytics_id', 'G-ABC123')] }, 'risk-rules-1');
    expect(r.band).toBe('high');
    expect(r.signals.map((s) => s.code)).toEqual(expect.arrayContaining(['payment_destination_displayed', 'qr_payment_code', 'deceptive_claims', 'brand_on_unofficial_domain', 'lookalike_domain']));
    expect(r.signals.every((s) => s.evidence.length > 0)).toBe(true);
    expect(r.signals.find((s) => s.code === 'signal_analytics_id')).toMatchObject({ weight: 0, direction: 'context' });
    expect(r.conflicts.map((c) => c.code)).toContain('mention_vs_impersonation');
  });

  it('applies the benign-context checklist and never lets infrastructure-only signals score', () => {
    const official = assessRisk({ ...base, hostname: 'www.onlinesbi.sbi', identifiers: [id('brand_claim', 'sbi'), id('upi_vpa', 'sbi@sbi')] }, 'v');
    expect(official.band).toBe('low');
    expect(official.benignContext.map((b) => b.code)).toContain('legitimate_official');
    const infraOnly = assessRisk({ ...base, hostname: 'plain-site.example', identifiers: [id('analytics_id', 'G-1'), id('dom_template_hash', 'abc', 'dom', 'resource_string')] }, 'v');
    expect(infraOnly.score).toBe(0);
    const challenge = assessRisk({ ...base, hostname: 'plain-site.example', outcome: 'CHALLENGE_PAGE_CAPTURED', classification: 'challenge' }, 'v');
    expect(challenge).toMatchObject({ band: 'insufficient_evidence', captureQuality: 'not_target_content' });
    const parked = assessRisk({ ...base, classification: 'parked_domain' }, 'v');
    expect(parked.benignContext.map((b) => b.code)).toContain('parked_or_expired');
    expect(assessRisk({ ...base, priorFalsePositive: true }, 'v').conflicts.map((c) => c.code)).toContain('prior_false_positive');
  });
});

describe('extended extraction (provenance, signals, network-aware validation)', () => {
  it('normalises internationalised email domains while preserving the raw form', () => {
    const ids = extractFromText(src('Write to सहायता@उदाहरण.भारत or help@acme-refund.example'));
    const emails = ids.filter((i) => i.fieldType === 'email');
    expect(emails.map((e) => e.normalisedValue)).toEqual(expect.arrayContaining(['help@acme-refund.example', `सहायता@${domainToASCII('उदाहरण.भारत')}`]));
    expect(emails.find((e) => e.rawValue.startsWith('सहायता'))?.note).toMatch(/punycode/);
  });

  it('checks EIP-55 and never infers an EVM chain', () => {
    expect(keccak256(Buffer.from('')).toString('hex')).toBe('c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
    const good = extractFromText(src('USDT to 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed now')).find((i) => i.fieldType === 'crypto_eth')!;
    expect(good.validation).toBe('format_valid');
    expect(good.note).toMatch(/NOT inferable.*EIP-55 checksum verified/);
    const bad = extractFromText(src('send to 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD')).find((i) => i.fieldType === 'crypto_eth')!;
    expect(bad.validation).toBe('format_invalid');
    // OCR digits are never promoted, even when they look valid.
    expect(extractFromText(src('call 98765 43210', { method: 'ocr', fromOcr: true })).find((i) => i.fieldType === 'phone')?.validation).toBe('uncertain');
  });

  it('extracts operator signals, app links, APK links and sensitive form fields as signals', () => {
    const html = `<script src="https://embed.tawk.to/64f1a2b3c4d5e6f7a8b9c0d1/1h2j3k4l5"></script>
      <ins class="adsbygoogle" data-ad-client="ca-pub-1234567890123456"></ins>
      <a href="https://play.google.com/store/apps/details?id=com.fake.loanapp&hl=en">Get app</a>
      <a href="/files/kyc-update.apk">Download</a>
      <form action="/collect"><input type="password" name="pw"><input name="upi_pin"><input autocomplete="cc-number"></form>`;
    const text = extractFromText(src(html, { displayContext: 'resource_string', method: 'attribute' }));
    expect(text.find((i) => i.fieldType === 'chat_widget_id')?.normalisedValue).toBe('tawk:64f1a2b3c4d5e6f7a8b9c0d1/1h2j3k4l5');
    expect(text.find((i) => i.fieldType === 'adsense_id')?.normalisedValue).toBe('ca-pub-1234567890123456');
    expect(text.find((i) => i.fieldType === 'app_store_link')?.normalisedValue).toBe('play:com.fake.loanapp');
    const attrs = extractFromHtmlAttributes(html, 'https://x.example/page', { displayContext: 'unknown', sourceUrl: 'https://x.example/page', artifactSha256: 'h' });
    expect(attrs.identifiers.find((i) => i.fieldType === 'apk_link')?.normalisedValue).toBe('https://x.example/files/kyc-update.apk');
    expect(attrs.identifiers.filter((i) => i.fieldType === 'sensitive_form').map((i) => i.normalisedValue).sort()).toEqual(['otp_or_pin_field', 'password_field', 'payment_card_field']);
    expect(domTemplateHash('<p>tiny</p>')).toBeNull();
    expect(domTemplateHash('<div>'.repeat(40))).toMatch(/^[0-9a-f]{64}$/);
    expect(valueKey({ fieldType: 'upi_vpa', normalisedValue: 'A@YBL', rawValue: 'A@YBL' })).toBe('a@ybl');
    expect(confidenceFor({ method: 'qr', validation: 'format_valid', displayContext: 'displayed' })).toBeGreaterThan(confidenceFor({ method: 'ocr', validation: 'uncertain', displayContext: 'displayed' }));
  });
});

describe('status fields stay distinct', () => {
  it('maps processing state and outcome to an explicit acquisition chip', () => {
    expect(acquisitionChip({ state: 'COMPLETE', outcome: 'CONTENT_CAPTURED', classification: 'content_captured' })).toBe('content_captured');
    expect(acquisitionChip({ state: 'PARTIAL', outcome: 'CONTENT_INCOMPLETE', classification: 'navigation_timeout_salvaged' })).toBe('partial');
    expect(acquisitionChip({ state: 'MANUAL_REVIEW', outcome: 'CHALLENGE_PAGE_CAPTURED', classification: 'challenge' })).toBe('challenge');
    expect(acquisitionChip({ state: 'FAILED_FINAL', outcome: 'ORIGIN_UNAVAILABLE', classification: 'timeout: x' })).toBe('timed_out');
    expect(acquisitionChip({ state: 'COMPLETE', outcome: 'CONTENT_CAPTURED', classification: 'parked_domain' })).toBe('parked');
    expect(acquisitionChip({ state: 'FAILED_FINAL', outcome: 'DNS_FAILURE', classification: 'dns_failure' })).toBe('dns_failure');
    expect(acquisitionChip({ state: 'CAPTURING', outcome: null, classification: null })).toBe('capturing');
    expect(liveStage({ state: 'CAPTURING', progress_stage: 'first_image_ready', extraction_state: null, has_first_image: true })).toBe('first_image_ready');
    expect(liveStage({ state: 'COMPLETE', progress_stage: 'committed', extraction_state: 'pending', has_first_image: true })).toBe('extracting');
  });
});
