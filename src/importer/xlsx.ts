/**
 * Minimal, defensive XLSX reader for intake (checklist §9 "protect CSV/XLSX
 * import from malformed files, oversized uploads and formula abuse").
 *
 *  - Reads only the ZIP central directory and the few parts needed for the
 *    first worksheet; no other part is decompressed.
 *  - Bounded: entry count, per-part and total inflated size (zlib
 *    maxOutputLength), compression ratio (zip-bomb guard), cell/row counts.
 *  - Never evaluates formulas: a formula cell contributes its cached value as
 *    plain text, and the presence of formulas is reported.
 *  - No external XML parser: worksheet XML is scanned with bounded regexes for
 *    the small, fixed SpreadsheetML vocabulary it needs. Entity expansion is
 *    limited to the five predefined XML entities and numeric references.
 */
import { inflateRawSync } from 'node:zlib';

export interface XlsxLimits {
  maxEntries: number;
  maxPartBytes: number;
  maxTotalInflatedBytes: number;
  maxRatio: number;
  maxRows: number;
  maxColumns: number;
}

export const DEFAULT_XLSX_LIMITS: XlsxLimits = {
  maxEntries: 2000,
  maxPartBytes: 25 * 1024 * 1024,
  maxTotalInflatedBytes: 60 * 1024 * 1024,
  maxRatio: 150,
  maxRows: 20_000,
  maxColumns: 64,
};

export class XlsxError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
  }
}

interface ZipEntry {
  name: string;
  method: number;
  compressedSize: number;
  size: number;
  localOffset: number;
  flags: number;
}

function readCentralDirectory(buf: Buffer, limits: XlsxLimits): Map<string, ZipEntry> {
  const minEocd = 22;
  if (buf.length < minEocd) throw new XlsxError('xlsx_not_zip', 'file is too small to be an XLSX workbook');
  let eocd = -1;
  for (let i = buf.length - minEocd; i >= Math.max(0, buf.length - minEocd - 0xffff); i -= 1) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new XlsxError('xlsx_not_zip', 'no ZIP end-of-central-directory record');
  const count = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (count === 0xffff || cdOffset === 0xffffffff) throw new XlsxError('xlsx_zip64_unsupported', 'ZIP64 workbooks are not accepted');
  if (count > limits.maxEntries) throw new XlsxError('xlsx_too_many_entries', `workbook has ${count} ZIP entries (limit ${limits.maxEntries})`);
  if (cdOffset + cdSize > eocd) throw new XlsxError('xlsx_corrupt', 'central directory lies outside the file');
  const entries = new Map<string, ZipEntry>();
  let p = cdOffset;
  for (let n = 0; n < count; n += 1) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== 0x02014b50) throw new XlsxError('xlsx_corrupt', 'bad central directory entry');
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    const compressedSize = buf.readUInt32LE(p + 20);
    const size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString('utf8');
    if (name.includes('..') || name.startsWith('/') || name.includes('\\')) throw new XlsxError('xlsx_unsafe_entry', `unsafe ZIP entry name: ${name.slice(0, 80)}`);
    entries.set(name, { name, method, compressedSize, size, localOffset, flags });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function readPart(buf: Buffer, e: ZipEntry, limits: XlsxLimits, budget: { used: number }): string {
  if (e.flags & 0x1) throw new XlsxError('xlsx_encrypted', 'encrypted workbook parts are not accepted');
  if (e.size > limits.maxPartBytes) throw new XlsxError('xlsx_part_too_large', `${e.name} declares ${e.size} bytes (limit ${limits.maxPartBytes})`);
  if (e.compressedSize > 0 && e.size / e.compressedSize > limits.maxRatio) throw new XlsxError('xlsx_compression_ratio', `${e.name} compression ratio exceeds ${limits.maxRatio}:1 (possible zip bomb)`);
  const lp = e.localOffset;
  if (lp + 30 > buf.length || buf.readUInt32LE(lp) !== 0x04034b50) throw new XlsxError('xlsx_corrupt', `bad local header for ${e.name}`);
  const start = lp + 30 + buf.readUInt16LE(lp + 26) + buf.readUInt16LE(lp + 28);
  const data = buf.subarray(start, start + e.compressedSize);
  if (data.length !== e.compressedSize) throw new XlsxError('xlsx_corrupt', `${e.name} is truncated`);
  const remaining = limits.maxTotalInflatedBytes - budget.used;
  let out: Buffer;
  if (e.method === 0) out = Buffer.from(data);
  else if (e.method === 8) {
    try {
      out = inflateRawSync(data, { maxOutputLength: Math.max(1, Math.min(limits.maxPartBytes, remaining)) });
    } catch (err) {
      throw new XlsxError('xlsx_inflate_failed', `${e.name}: ${(err as Error).message.slice(0, 120)}`);
    }
  } else throw new XlsxError('xlsx_unsupported_compression', `${e.name} uses ZIP method ${e.method}`);
  budget.used += out.length;
  if (budget.used > limits.maxTotalInflatedBytes) throw new XlsxError('xlsx_too_large', 'workbook inflates beyond the intake limit');
  return out.toString('utf8');
}

const ENTITY: Record<string, string> = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
export function decodeXmlText(s: string): string {
  return s.replace(/&(#x[0-9a-fA-F]{1,6}|#\d{1,7}|amp|lt|gt|quot|apos);/g, (_, e: string) => {
    if (e[0] === '#') {
      const cp = e[1] === 'x' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return cp > 0 && cp <= 0x10ffff ? String.fromCodePoint(cp) : '';
    }
    return ENTITY[e] ?? '';
  });
}

function textOf(fragment: string): string {
  // Concatenate every <t>…</t> run (rich text has several); ignore phonetic runs.
  const noPhonetic = fragment.replace(/<rPh\b[\s\S]*?<\/rPh>/g, '');
  let out = '';
  for (const m of noPhonetic.matchAll(/<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/g)) out += decodeXmlText(m[1]!);
  return out;
}

function colIndex(ref: string): number {
  const letters = /^([A-Z]{1,3})/.exec(ref)?.[1];
  if (!letters) return -1;
  let n = 0;
  for (const ch of letters) n = n * 26 + (ch.charCodeAt(0) - 64);
  return n - 1;
}

export interface XlsxSheet {
  sheetName: string;
  rows: string[][];
  formulaCells: number;
  truncatedRows: boolean;
}

/** Read the first worksheet as strings. Throws XlsxError with a stable code on any refusal. */
export function readFirstSheet(buf: Buffer, limits: XlsxLimits = DEFAULT_XLSX_LIMITS): XlsxSheet {
  const entries = readCentralDirectory(buf, limits);
  const budget = { used: 0 };
  const part = (name: string): string | null => {
    const e = entries.get(name);
    return e ? readPart(buf, e, limits, budget) : null;
  };
  const workbook = part('xl/workbook.xml');
  if (!workbook) throw new XlsxError('xlsx_no_workbook', 'xl/workbook.xml is missing (not an XLSX workbook)');
  const sheetAttrs = /<sheet\b([^>]*?)\/?>/.exec(workbook)?.[1];
  const sheetName = sheetAttrs ? /\bname="([^"]*)"/.exec(sheetAttrs)?.[1] ?? 'Sheet1' : null;
  const rid = sheetAttrs ? /\br:id="([^"]+)"/.exec(sheetAttrs)?.[1] ?? '' : null;
  if (sheetName === null || rid === null) throw new XlsxError('xlsx_no_sheet', 'workbook has no worksheet');
  const rels = part('xl/_rels/workbook.xml.rels') ?? '';
  let target = 'worksheets/sheet1.xml';
  for (const m of rels.matchAll(/<Relationship\b([^>]*)\/?>/g)) {
    const attrs = m[1]!;
    if (new RegExp(`\\bId="${rid.replace(/[^A-Za-z0-9]/g, '')}"`).test(attrs)) {
      const t = /\bTarget="([^"]+)"/.exec(attrs)?.[1];
      if (t) target = t;
    }
  }
  const sheetPath = target.startsWith('/') ? target.slice(1) : `xl/${target.replace(/^\.\//, '')}`;
  if (sheetPath.includes('..')) throw new XlsxError('xlsx_unsafe_entry', 'worksheet target escapes the workbook');
  const sheetXml = part(sheetPath);
  if (!sheetXml) throw new XlsxError('xlsx_no_sheet', `worksheet part ${sheetPath} is missing`);
  const sharedXml = part('xl/sharedStrings.xml');
  const shared: string[] = [];
  if (sharedXml) for (const m of sharedXml.matchAll(/<si\b[^>]*>([\s\S]*?)<\/si>/g)) shared.push(textOf(m[1]!));

  const rows: string[][] = [];
  let formulaCells = 0;
  let truncatedRows = false;
  for (const rm of sheetXml.matchAll(/<row\b[^>]*?(?:\/>|>([\s\S]*?)<\/row>)/g)) {
    if (rows.length >= limits.maxRows) {
      truncatedRows = true;
      break;
    }
    const cells: string[] = [];
    let nextCol = 0;
    for (const cm of (rm[1] ?? '').matchAll(/<c\b([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g)) {
      const attrs = cm[1]!;
      const inner = cm[2] ?? '';
      const ref = /\br="([A-Z]{1,3}\d+)"/.exec(attrs)?.[1];
      const col = ref ? colIndex(ref) : nextCol;
      nextCol = col + 1;
      if (col < 0 || col >= limits.maxColumns) continue;
      const type = /\bt="([a-zA-Z]+)"/.exec(attrs)?.[1] ?? 'n';
      if (/<f\b/.test(inner)) formulaCells += 1;
      const v = /<v>([\s\S]*?)<\/v>/.exec(inner)?.[1];
      let value = '';
      if (type === 's') value = v !== undefined ? shared[Number(v)] ?? '' : '';
      else if (type === 'inlineStr') value = textOf(inner);
      else if (type === 'b') value = v === '1' ? 'true' : v === '0' ? 'false' : '';
      else if (type === 'e') value = '';
      else value = v !== undefined ? decodeXmlText(v) : '';
      while (cells.length < col) cells.push('');
      cells[col] = value;
    }
    rows.push(cells);
  }
  return { sheetName: decodeXmlText(sheetName), rows, formulaCells, truncatedRows };
}

/** Convert the first sheet to header-keyed records (header row lower-cased, blank rows skipped). */
export function xlsxToRecords(buf: Buffer, limits: XlsxLimits = DEFAULT_XLSX_LIMITS): { records: { line: number; raw: Record<string, unknown> }[]; formulaCells: number; truncatedRows: boolean } {
  const sheet = readFirstSheet(buf, limits);
  const [header, ...body] = sheet.rows;
  if (!header || header.every((h) => !h.trim())) throw new XlsxError('xlsx_no_header', 'the first worksheet has no header row');
  const keys = header.map((h) => h.trim().toLowerCase());
  const records: { line: number; raw: Record<string, unknown> }[] = [];
  body.forEach((cells, i) => {
    if (cells.every((c) => !c || !c.trim())) return;
    const raw: Record<string, unknown> = {};
    keys.forEach((k, idx) => {
      if (k && cells[idx] !== undefined) raw[k] = cells[idx]!.trim();
    });
    records.push({ line: i + 2, raw });
  });
  return { records, formulaCells: sheet.formulaCells, truncatedRows: sheet.truncatedRows };
}
