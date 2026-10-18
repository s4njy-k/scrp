/**
 * Brand dictionary, brand-claim matching and lookalike-domain detection
 * (checklist §3 "identify claimed banks, government bodies, brands ... account
 * for legitimate affiliates"; §5 "typosquatting, homoglyph/punycode and
 * brand-lookalike alerts while maintaining explicit exemptions").
 * Every result is a signal for analyst review, never a verdict.
 */
import { readFileSync } from 'node:fs';
import { domainToUnicode } from 'node:url';
import { parse as parseYaml } from 'yaml';
import { getDomain } from 'tldts';
import { z } from 'zod';

const BrandSchema = z.object({
  id: z.string().regex(/^[a-z0-9_]+$/),
  name: z.string().min(1),
  kind: z.enum(['bank', 'payments', 'government', 'ecommerce', 'telecom', 'insurance', 'other']),
  keywords: z.array(z.string().min(3)).default([]),
  keywords_case_sensitive: z.array(z.string().min(2)).default([]),
  official_domains: z.array(z.string().min(3)).min(1),
  affiliate_domains: z.array(z.string().min(3)).default([]),
  lookalike_labels: z.array(z.string().min(3)).optional(),
}).strict();

const BrandFileSchema = z.object({
  schema_version: z.literal(1),
  brands: z.array(BrandSchema),
  user_content_platforms: z.array(z.string()).default([]),
}).strict();

export type Brand = z.infer<typeof BrandSchema>;
export type BrandDictionary = z.infer<typeof BrandFileSchema>;

export const DEFAULT_BRANDS_PATH = new URL('../../config/brands.yaml', import.meta.url);
let cached: BrandDictionary | null = null;

export function loadBrands(path: string | URL = process.env.COLLECTOR_BRANDS_PATH ?? DEFAULT_BRANDS_PATH): BrandDictionary {
  if (cached && path === DEFAULT_BRANDS_PATH) return cached;
  const parsed = BrandFileSchema.parse(parseYaml(readFileSync(path, 'utf8')));
  if (path === DEFAULT_BRANDS_PATH) cached = parsed;
  return parsed;
}

export interface BrandClaim {
  brandId: string;
  brandName: string;
  matched: string;
  index: number;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Brand names/keywords in visible text (word-boundary matches; acronyms case-sensitive). */
export function findBrandClaims(text: string, dict: BrandDictionary = loadBrands()): BrandClaim[] {
  const out: BrandClaim[] = [];
  const t = text.slice(0, 2_000_000);
  for (const b of dict.brands) {
    const seen = new Set<string>();
    for (const k of b.keywords) {
      const re = new RegExp(`(?<![\\p{L}\\p{N}])${escapeRe(k)}(?![\\p{L}\\p{N}])`, 'giu');
      const m = re.exec(t);
      if (m && !seen.has(b.id)) {
        seen.add(b.id);
        out.push({ brandId: b.id, brandName: b.name, matched: m[0], index: m.index });
      }
    }
    for (const k of b.keywords_case_sensitive) {
      if (seen.has(b.id)) break;
      const re = new RegExp(`(?<![\\p{L}\\p{N}])${escapeRe(k)}(?![\\p{L}\\p{N}])`, 'u');
      const m = re.exec(t);
      if (m) {
        seen.add(b.id);
        out.push({ brandId: b.id, brandName: b.name, matched: m[0], index: m.index });
      }
    }
  }
  return out;
}

// Visually confusable characters folded to a canonical "skeleton" (subset of Unicode TR39 confusables
// relevant to Latin-script domains, plus common digit/letter swaps).
const CONFUSABLE: Record<string, string> = {
  '0': 'o', '1': 'l', '3': 'e', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's', '|': 'l', 'i': 'l',
  'а': 'a', 'в': 'b', 'е': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'l', 'ј': 'j', 'ԁ': 'd', 'ɡ': 'g', 'ӏ': 'l',
  'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'τ': 't', 'κ': 'k', 'ι': 'l', 'ε': 'e',
  'á': 'a', 'à': 'a', 'â': 'a', 'ä': 'a', 'ã': 'a', 'å': 'a', 'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e', 'í': 'l', 'ì': 'l', 'ï': 'l', 'î': 'l',
  'ó': 'o', 'ò': 'o', 'ô': 'o', 'ö': 'o', 'õ': 'o', 'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u', 'ñ': 'n', 'ç': 'c', 'ý': 'y',
};

export function skeleton(label: string): string {
  let s = label.toLowerCase();
  s = [...s].map((ch) => CONFUSABLE[ch] ?? ch).join('');
  return s.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/cl/g, 'd').replace(/-/g, '');
}

/** Optimal-string-alignment (restricted Damerau-Levenshtein) distance. */
export function editDistance(a: string, b: string): number {
  const d: number[][] = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array<number>(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j += 1) d[0]![j] = j;
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i]![j] = Math.min(d[i - 1]![j]! + 1, d[i]![j - 1]! + 1, d[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i]![j] = Math.min(d[i]![j]!, d[i - 2]![j - 2]! + 1);
    }
  }
  return d[a.length]![b.length]!;
}

export interface LookalikeMatch {
  brandId: string;
  brandName: string;
  kind: 'homoglyph' | 'typosquat' | 'combosquat' | 'punycode_homoglyph';
  candidateLabel: string;
  comparedTo: string;
  distance: number;
}

export interface DomainContext {
  registrableDomain: string;
  official: { brandId: string; brandName: string } | null;
  affiliate: { brandId: string; brandName: string } | null;
  userContentPlatform: boolean;
  governmentTld: boolean;
}

export function domainContext(hostname: string, dict: BrandDictionary = loadBrands()): DomainContext {
  const reg = (getDomain(hostname, { allowPrivateDomains: false }) ?? hostname).toLowerCase();
  const host = hostname.toLowerCase();
  const matches = (d: string) => reg === d || host === d || host.endsWith(`.${d}`);
  const official = dict.brands.find((b) => b.official_domains.some(matches));
  const affiliate = dict.brands.find((b) => b.affiliate_domains.some(matches));
  return {
    registrableDomain: reg,
    official: official ? { brandId: official.id, brandName: official.name } : null,
    affiliate: affiliate ? { brandId: affiliate.id, brandName: affiliate.name } : null,
    userContentPlatform: dict.user_content_platforms.some(matches),
    governmentTld: /\.(gov\.in|nic\.in)$/.test(reg),
  };
}

/** Lookalike checks of a hostname against every brand's labels; official/affiliate domains are exempt. */
export function findLookalikes(hostname: string, dict: BrandDictionary = loadBrands()): LookalikeMatch[] {
  const ctx = domainContext(hostname, dict);
  if (ctx.official || ctx.affiliate) return [];
  const asciiReg = ctx.registrableDomain;
  const unicodeReg = domainToUnicode(asciiReg) || asciiReg;
  const label = unicodeReg.split('.')[0] ?? unicodeReg;
  const isPunycode = asciiReg.split('.').some((p) => p.startsWith('xn--'));
  const sk = skeleton(label);
  // Subdomain labels can carry the brand too (e.g. sbi.kyc-update.example).
  const hostLabels = hostname.toLowerCase().split('.').slice(0, -2);
  const tokens = new Set([...label.toLowerCase().split(/[-_.]/), ...hostLabels.flatMap((l) => l.split(/[-_]/))]);
  const out: LookalikeMatch[] = [];
  for (const b of dict.brands) {
    const labels = b.lookalike_labels ?? b.official_domains.map((d) => d.split('.')[0]!);
    let best: LookalikeMatch | null = null;
    for (const target of labels) {
      const tsk = skeleton(target);
      if (label === target) continue; // same label, different TLD: handled as combosquat below only if tokens differ
      if (sk === tsk) {
        best = { brandId: b.id, brandName: b.name, kind: isPunycode ? 'punycode_homoglyph' : 'homoglyph', candidateLabel: label, comparedTo: target, distance: 0 };
        break;
      }
      const dist = editDistance(sk, tsk);
      const allowed = tsk.length >= 9 ? 2 : tsk.length >= 5 ? 1 : 0;
      if (allowed > 0 && dist > 0 && dist <= allowed && (!best || dist < best.distance)) {
        best = { brandId: b.id, brandName: b.name, kind: 'typosquat', candidateLabel: label, comparedTo: target, distance: dist };
      }
      if (!best && target.length >= 3 && tokens.has(target) && tokens.size > 1) {
        best = { brandId: b.id, brandName: b.name, kind: 'combosquat', candidateLabel: label, comparedTo: target, distance: 0 };
      }
      if (!best && target.length >= 5 && label.includes(target) && label !== target) {
        best = { brandId: b.id, brandName: b.name, kind: 'combosquat', candidateLabel: label, comparedTo: target, distance: 0 };
      }
    }
    if (!best) {
      // Same label under a different registrable suffix (e.g. hdfcbank.co, hdfcbank-in.online).
      const sameLabel = labels.find((t) => label === t);
      if (sameLabel) best = { brandId: b.id, brandName: b.name, kind: 'combosquat', candidateLabel: label, comparedTo: sameLabel, distance: 0 };
    }
    if (best) out.push(best);
  }
  return out;
}
