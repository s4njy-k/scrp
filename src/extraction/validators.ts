/**
 * Format validators. Format validity does NOT establish ownership,
 * operability or criminal involvement (§11).
 */
import { createHash } from 'node:crypto';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Decode(s: string): Buffer | null {
  let num = 0n;
  for (const ch of s) {
    const v = B58.indexOf(ch);
    if (v < 0) return null;
    num = num * 58n + BigInt(v);
  }
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num /= 256n;
  }
  for (const ch of s) {
    if (ch !== '1') break;
    bytes.unshift(0);
  }
  return Buffer.from(bytes);
}

export function base58CheckValid(s: string): { valid: boolean; version: number | null } {
  const buf = base58Decode(s);
  if (!buf || buf.length < 5) return { valid: false, version: null };
  const payload = buf.subarray(0, -4);
  const checksum = buf.subarray(-4);
  const h = createHash('sha256').update(createHash('sha256').update(payload).digest()).digest();
  return { valid: h.subarray(0, 4).equals(checksum), version: payload[0] ?? null };
}

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i += 1) if ((top >>> i) & 1) chk ^= GEN[i]!;
  }
  return chk >>> 0;
}

/** BIP-173/BIP-350 checksum (bech32 or bech32m) for a segwit address. */
export function bech32Valid(addr: string): boolean {
  if (addr !== addr.toLowerCase() && addr !== addr.toUpperCase()) return false;
  const a = addr.toLowerCase();
  const pos = a.lastIndexOf('1');
  if (pos < 1 || pos + 7 > a.length || a.length > 90) return false;
  const hrp = a.slice(0, pos);
  const data: number[] = [];
  for (const ch of a.slice(pos + 1)) {
    const v = BECH32_CHARSET.indexOf(ch);
    if (v < 0) return false;
    data.push(v);
  }
  const expanded = [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)];
  const pm = bech32Polymod([...expanded, ...data]);
  return pm === 1 || pm === 0x2bc830a3;
}

export function btcAddressValid(addr: string): boolean {
  if (/^(bc1|tb1)/i.test(addr)) return bech32Valid(addr);
  const r = base58CheckValid(addr);
  return r.valid && (r.version === 0x00 || r.version === 0x05);
}

export function tronAddressValid(addr: string): boolean {
  const r = base58CheckValid(addr);
  return r.valid && r.version === 0x41;
}

/** Ethereum: all-lower/all-upper hex is format-valid; mixed case must satisfy EIP-55 (keccak not in node:crypto, so mixed case is 'uncertain'). */
export function ethAddressState(addr: string): 'format_valid' | 'uncertain' {
  const hex = addr.slice(2);
  return hex === hex.toLowerCase() || hex === hex.toUpperCase() ? 'format_valid' : 'uncertain';
}

export function ifscValid(code: string): boolean {
  return /^[A-Z]{4}0[A-Z0-9]{6}$/.test(code);
}

/** Known UPI PSP handles (non-exhaustive). Unknown handles are 'uncertain', not invalid. */
export const UPI_HANDLES = new Set([
  'ybl', 'ibl', 'axl', 'paytm', 'ptyes', 'ptsbi', 'ptaxis', 'pthdfc', 'upi', 'apl', 'yapl', 'okaxis', 'okhdfcbank', 'oksbi', 'okicici',
  'sbi', 'icici', 'hdfcbank', 'axisbank', 'axisb', 'kotak', 'kbl', 'yesbank', 'yesbankltd', 'freecharge', 'airtel', 'airtelpaymentsbank', 'jio',
  'idfcbank', 'idfcfirst', 'indus', 'federal', 'fbl', 'rbl', 'pnb', 'barodampay', 'unionbank', 'uboi', 'cnrb', 'boi', 'mahb', 'cbin',
  'aubank', 'dbs', 'hsbc', 'sc', 'citi', 'citigold', 'abfspay', 'waicici', 'wahdfcbank', 'wasbi', 'waaxis', 'slc', 'timecosmos', 'jupiteraxis',
  'fam', 'superyes', 'naviaxis', 'goaxb', 'tapicici', 'yescred', 'pockets', 'ikwik', 'mbk', 'dlb', 'equitas', 'esaf', 'kvb', 'tjsb', 'nsdl',
]);

export function normalisePhone(raw: string): { normalised: string | null; state: 'format_valid' | 'uncertain' | 'format_invalid' } {
  const digits = raw.replace(/[^\d+]/g, '');
  const plain = digits.replace(/^\+/, '');
  if (digits.startsWith('+')) {
    if (plain.length >= 8 && plain.length <= 15) return { normalised: `+${plain}`, state: plain.startsWith('91') && plain.length !== 12 ? 'format_invalid' : 'format_valid' };
    return { normalised: null, state: 'format_invalid' };
  }
  if (/^0?[6-9]\d{9}$/.test(plain)) return { normalised: `+91${plain.slice(-10)}`, state: 'format_valid' };
  if (/^91[6-9]\d{9}$/.test(plain)) return { normalised: `+${plain}`, state: 'format_valid' };
  if (/^1800\d{6,7}$/.test(plain)) return { normalised: plain, state: 'format_valid' }; // Indian toll-free
  if (plain.length >= 8 && plain.length <= 15) return { normalised: plain, state: 'uncertain' };
  return { normalised: null, state: 'format_invalid' };
}
