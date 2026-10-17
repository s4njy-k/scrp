/**
 * Element evidence capture (blueprint §9 step 7): logo, login form, contact
 * block, QR/payment details and suspicious claims. Each crop is a separate
 * live observation with its own timestamp, frame URL, locator, bounding box
 * and surrounding context. The page DOM is not modified to locate elements.
 */
import type { Frame, Page } from 'playwright-core';

export interface ElementCandidate {
  kind: 'logo' | 'login_form' | 'contact_block' | 'qr_candidate' | 'payment_details' | 'suspicious_claim' | 'canvas';
  selector: string;
  context: string;
  bbox: { x: number; y: number; width: number; height: number };
  note?: string;
}

/**
 * Runs inside the page. Returns candidates with a structural CSS path
 * (nth-of-type chain) so the element can be re-located without adding
 * attributes to the DOM.
 */
/* c8 ignore start */
function findCandidatesInPage(limit: number): ElementCandidate[] {
  const out: ElementCandidate[] = [];
  const seen = new Set<Element>();
  const cssPath = (el: Element): string => {
    const parts: string[] = [];
    let cur: Element | null = el;
    while (cur && cur.nodeType === 1 && cur !== document.documentElement) {
      const tag = cur.tagName.toLowerCase();
      const parent: Element | null = cur.parentElement;
      if (!parent) { parts.unshift(tag); break; }
      const same = Array.from(parent.children).filter((c) => c.tagName === cur!.tagName);
      parts.unshift(same.length > 1 ? `${tag}:nth-of-type(${same.indexOf(cur) + 1})` : tag);
      cur = parent;
    }
    return `html > ${parts.join(' > ')}`;
  };
  const visible = (el: Element): DOMRect | null => {
    const r = el.getBoundingClientRect();
    if (r.width < 8 || r.height < 8) return null;
    const st = getComputedStyle(el);
    if (st.visibility === 'hidden' || st.display === 'none' || Number(st.opacity) === 0) return null;
    return r;
  };
  const ctx = (el: Element): string => {
    const base = (el.closest('section,article,form,footer,header,div') ?? el).textContent ?? '';
    return base.replace(/\s+/g, ' ').trim().slice(0, 400);
  };
  const add = (kind: ElementCandidate['kind'], el: Element, note?: string) => {
    if (out.length >= limit || seen.has(el)) return;
    const r = visible(el);
    if (!r) return;
    seen.add(el);
    out.push({ kind, selector: cssPath(el), context: ctx(el), bbox: { x: r.x + scrollX, y: r.y + scrollY, width: r.width, height: r.height }, ...(note ? { note } : {}) });
  };

  document.querySelectorAll('img[alt*="logo" i], img[src*="logo" i], img[class*="logo" i], header img, [class*="logo" i] img, [id*="logo" i] img')
    .forEach((el, i) => { if (i < 2) add('logo', el); });
  document.querySelectorAll('form').forEach((f) => { if (f.querySelector('input[type="password"]')) add('login_form', f); });
  document.querySelectorAll('img, canvas, svg').forEach((el) => {
    const r = el.getBoundingClientRect();
    const square = r.width >= 80 && r.height >= 80 && Math.abs(r.width - r.height) / Math.max(r.width, r.height) < 0.15;
    const hint = /qr|upi|scan|pay/i.test(`${el.getAttribute('alt') ?? ''} ${el.getAttribute('src') ?? ''} ${el.getAttribute('class') ?? ''} ${el.id}`);
    if (square && (hint || el.tagName === 'CANVAS' || r.width <= 600)) add('qr_candidate', el, el.tagName === 'CANVAS' ? 'canvas: pixels only, no DOM text' : undefined);
  });
  const textRules: [ElementCandidate['kind'], RegExp][] = [
    ['payment_details', /\b[\w.-]{2,64}@(?:ok)?(?:ybl|paytm|axl|ibl|upi|apl|sbi|icici|hdfcbank|axisbank|okaxis|okhdfcbank|oksbi|okicici|ptyes|ptsbi|ptaxis|pthdfc|yesbank|kotak|freecharge|airtel|jio|waicici|wahdfcbank|wasbi|waaxis)\b|\bIFSC\b|\b[A-Z]{4}0[A-Z0-9]{6}\b|\bupi:\/\/pay|\bA\/?C\s*(?:No|Number)\b|\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,59}\b|\b0x[a-fA-F0-9]{40}\b|\bT[1-9A-HJ-NP-Za-km-z]{33}\b/],
    ['contact_block', /(?:\+?\d[\d\s-]{8,14}\d)|wa\.me\/|api\.whatsapp\.com|t\.me\/|whatsapp|telegram|[\w.+-]+@[\w-]+\.[\w.-]+/i],
    ['suspicious_claim', /\b(kyc|refund|lottery|prize|guaranteed (returns|profit)|double your|customer care|helpline|otp|account (blocked|suspended)|electricity (bill|connection)|task based|part[- ]time job|investment plan)\b/i],
  ];
  const blocks = Array.from(document.querySelectorAll('p, li, td, span, a, div, address, footer, section, h1, h2, h3, h4, label, strong, b'));
  for (const [kind, re] of textRules) {
    for (const el of blocks) {
      if (out.length >= limit) break;
      const text = (el as HTMLElement).innerText ?? '';
      if (text.length < 4 || text.length > 600 || !re.test(text)) continue;
      // Prefer the smallest matching element: skip if a child also matches.
      if (Array.from(el.children).some((c) => re.test((c as HTMLElement).innerText ?? ''))) continue;
      add(kind, el);
    }
  }
  return out;
}
/* c8 ignore stop */

export async function findElementCandidates(frame: Frame | Page, limit: number, timeoutMs: number): Promise<ElementCandidate[]> {
  const target = 'mainFrame' in frame ? frame.mainFrame() : frame;
  const task = target.evaluate(findCandidatesInPage, limit);
  const timeout = new Promise<ElementCandidate[]>((_, rej) => setTimeout(() => rej(new Error('candidate search timeout')), timeoutMs).unref());
  return Promise.race([task, timeout]);
}
