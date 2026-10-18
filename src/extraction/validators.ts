/**
 * Format validators. Format validity does NOT establish ownership,
 * operability or criminal involvement (§11).
 */
import { createHash } from 'node:crypto';
import { parsePhoneNumberFromString } from 'libphonenumber-js/max';

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

// ---- Keccak-256 (the pre-standard SHA-3 used by Ethereum; NOT NIST SHA3-256) ----
const KECCAK_RC: bigint[] = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n, 0x000000000000808bn, 0x0000000080000001n,
  0x8000000080008081n, 0x8000000000008009n, 0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n,
  0x000000000000800an, 0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const KECCAK_ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const MASK64 = (1n << 64n) - 1n;
const rotl = (x: bigint, n: number) => (n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & MASK64);

function keccakF(s: bigint[]): void {
  for (let round = 0; round < 24; round += 1) {
    const c = [0, 1, 2, 3, 4].map((x) => s[x]! ^ s[x + 5]! ^ s[x + 10]! ^ s[x + 15]! ^ s[x + 20]!);
    for (let x = 0; x < 5; x += 1) {
      const d = c[(x + 4) % 5]! ^ rotl(c[(x + 1) % 5]!, 1);
      for (let y = 0; y < 25; y += 5) s[y + x] = s[y + x]! ^ d;
    }
    const b = new Array<bigint>(25);
    for (let x = 0; x < 5; x += 1) for (let y = 0; y < 5; y += 1) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(s[x + 5 * y]!, KECCAK_ROT[x + 5 * y]!);
    for (let x = 0; x < 5; x += 1) for (let y = 0; y < 5; y += 1) s[x + 5 * y] = b[x + 5 * y]! ^ (~b[((x + 1) % 5) + 5 * y]! & MASK64 & b[((x + 2) % 5) + 5 * y]!);
    s[0] = s[0]! ^ KECCAK_RC[round]!;
  }
}

export function keccak256(data: Buffer): Buffer {
  const rate = 136;
  const padded = Buffer.alloc(Math.ceil((data.length + 1) / rate) * rate);
  data.copy(padded);
  padded[data.length] = padded[data.length]! ^ 0x01;
  padded[padded.length - 1] = padded[padded.length - 1]! ^ 0x80;
  const s = new Array<bigint>(25).fill(0n);
  for (let off = 0; off < padded.length; off += rate) {
    for (let i = 0; i < rate / 8; i += 1) s[i] = s[i]! ^ padded.readBigUInt64LE(off + i * 8);
    keccakF(s);
  }
  const out = Buffer.alloc(32);
  for (let i = 0; i < 4; i += 1) out.writeBigUInt64LE(s[i]!, i * 8);
  return out;
}

/** EIP-55 mixed-case checksum for an EVM address. */
export function eip55Valid(addr: string): boolean {
  const hex = addr.slice(2);
  const hash = keccak256(Buffer.from(hex.toLowerCase(), 'ascii')).toString('hex');
  for (let i = 0; i < 40; i += 1) {
    const ch = hex[i]!;
    if (/[a-f]/i.test(ch) && (parseInt(hash[i]!, 16) >= 8 ? ch !== ch.toUpperCase() : ch !== ch.toLowerCase())) return false;
  }
  return true;
}

/**
 * EVM address: all-lower/all-upper hex is format-valid (no checksum present);
 * mixed case must satisfy EIP-55. The chain (Ethereum, BSC, Polygon, ...) and
 * any token cannot be inferred from the address format alone.
 */
export function ethAddressState(addr: string): 'format_valid' | 'format_invalid' {
  const hex = addr.slice(2);
  if (hex === hex.toLowerCase() || hex === hex.toUpperCase()) return 'format_valid';
  return eip55Valid(addr) ? 'format_valid' : 'format_invalid';
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

/**
 * Phone numbers: libphonenumber metadata with India as the default region for
 * numbers written without a country code (the collector's deployment context).
 * Valid → E.164 'format_valid'; possible but not valid → 'uncertain'.
 * Region inference and ownership still need corroboration.
 */
export function normalisePhone(raw: string): { normalised: string | null; state: 'format_valid' | 'uncertain' | 'format_invalid'; type?: string | undefined } {
  const cleaned = raw.replace(/^tel:/i, '').trim();
  try {
    const p = parsePhoneNumberFromString(cleaned, 'IN');
    if (p) {
      if (p.isValid()) return { normalised: p.number, state: 'format_valid', type: p.getType() };
      if (p.isPossible()) return { normalised: p.number, state: 'uncertain' };
    }
  } catch { /* fall through to the conservative rules below */ }
  return legacyNormalisePhone(cleaned);
}

function legacyNormalisePhone(raw: string): { normalised: string | null; state: 'format_valid' | 'uncertain' | 'format_invalid' } {
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
