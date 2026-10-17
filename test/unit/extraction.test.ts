import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { extractFromHtmlAttributes, extractFromText, parseUpiUri, type TextSource } from '../../src/extraction/identifiers.js';
import { btcAddressValid, bech32Valid, normalisePhone, tronAddressValid } from '../../src/extraction/validators.js';
import { decodeQrFromPng } from '../../src/extraction/qr.js';
import { checkPng } from '../../src/capture/imageCheck.js';

const src = (text: string, over: Partial<TextSource> = {}): TextSource => ({ text, method: 'dom', displayContext: 'displayed', sourceUrl: 'https://x.example/', artifactSha256: 'abc', ...over });
const byType = (ids: ReturnType<typeof extractFromText>, t: string) => ids.filter((i) => i.fieldType === t);

describe('identifier extraction (§11)', () => {
  it('extracts and validates Indian payment identifiers', () => {
    const ids = extractFromText(src('Pay to refunds.desk@ybl or helper@unknownpsp. Bank A/C No: 1234 5678 9012 IFSC SBIN0001234. Mail help@acme.example'));
    expect(byType(ids, 'upi_vpa').map((i) => [i.normalisedValue, i.validation])).toEqual([
      ['refunds.desk@ybl', 'format_valid'], ['helper@unknownpsp', 'uncertain'],
    ]);
    expect(byType(ids, 'email').map((i) => i.normalisedValue)).toEqual(['help@acme.example']);
    expect(byType(ids, 'ifsc')[0]?.validation).toBe('format_valid');
    expect(byType(ids, 'bank_account')[0]).toMatchObject({ normalisedValue: '123456789012', validation: 'unvalidated' });
  });

  it('parses UPI URIs and keeps the payee VPA', () => {
    expect(parseUpiUri('upi://pay?pa=a.b@okaxis&pn=Fake%20Name&am=499&cu=INR')).toEqual({ pa: 'a.b@okaxis', pn: 'Fake Name', am: '499', cu: 'INR' });
    const ids = extractFromText(src('upi://pay?pa=a.b@okaxis&pn=X&am=1'));
    expect(byType(ids, 'upi_vpa')[0]?.normalisedValue).toBe('a.b@okaxis');
  });

  it('normalises phones and recognises WhatsApp/Telegram destinations', () => {
    expect(normalisePhone('098765 43210')).toEqual({ normalised: '+919876543210', state: 'format_valid' });
    const ids = extractFromText(src('Call +91 98765 43210, WhatsApp https://wa.me/919876543210, join t.me/scam_support'));
    expect(byType(ids, 'phone')[0]?.normalisedValue).toBe('+919876543210');
    expect(byType(ids, 'whatsapp')[0]?.normalisedValue).toBe('+919876543210');
    expect(byType(ids, 'telegram')[0]?.normalisedValue).toBe('t.me/scam_support');
  });

  it('verifies cryptocurrency checksums', () => {
    expect(btcAddressValid('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2')).toBe(true);
    expect(btcAddressValid('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3')).toBe(false);
    expect(bech32Valid('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq')).toBe(true);
    expect(tronAddressValid('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t')).toBe(true);
    const ids = extractFromText(src('Send BTC to 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'));
    expect(byType(ids, 'crypto_btc')[0]?.validation).toBe('format_valid');
  });

  it('never promotes OCR values to confirmed identifiers', () => {
    const ids = extractFromText(src('UPI: pay.me@ybl A/C No 12345678901', { method: 'ocr', fromOcr: true }));
    expect(byType(ids, 'upi_vpa')[0]?.validation).toBe('uncertain');
    expect(byType(ids, 'bank_account')[0]?.validation).toBe('uncertain');
  });

  it('keeps resource strings separate from displayed values and suppresses noisy matches', () => {
    const ids = extractFromText(src('var demo = "0x52908400098527886E0F7030069857D2E4169EE7"; var n = 9876543210;', { displayContext: 'resource_string' }));
    expect(byType(ids, 'crypto_eth')).toHaveLength(0);
    expect(byType(ids, 'phone')).toHaveLength(0);
  });

  it('does not mistake image asset names for emails', () => {
    expect(byType(extractFromText(src('logo@2x.png icon@3x.webp')), 'email')).toHaveLength(0);
  });

  it('extracts tel/mailto attributes, form actions and discovered links (not contacted)', () => {
    const r = extractFromHtmlAttributes('<a href="tel:+919876543210">c</a><a href="mailto:a@b.example">m</a><form action="/collect"></form><a href="/pay">p</a><title>Acme</title>',
      'https://shop.example/x', { displayContext: 'unknown', sourceUrl: 'https://shop.example/x', artifactSha256: null });
    expect(r.formActions).toEqual(['https://shop.example/collect']);
    expect(r.links).toContain('https://shop.example/pay');
    expect(r.identifiers.find((i) => i.fieldType === 'phone')?.normalisedValue).toBe('+919876543210');
    expect(r.identifiers.find((i) => i.fieldType === 'business_identity')?.normalisedValue).toBe('Acme');
  });
});

describe('QR decoding and image validation', () => {
  const png = readFileSync(new URL('../fixtures/upi-qr.png', import.meta.url));
  it('decodes the UPI QR fixture', () => {
    expect(decodeQrFromPng(png)?.payload).toBe('upi://pay?pa=fraudster.test@okaxis&pn=Fake%20Refund%20Desk&am=499&cu=INR');
  });
  it('validates PNG structure and flags (but does not reject) near-uniform images', () => {
    expect(checkPng(png, 40)).toMatchObject({ valid: true });
    expect(checkPng(Buffer.from('not a png'), 40).valid).toBe(false);
  });
});
