import { describe, expect, it } from 'vitest';
import { readFirstSheet, xlsxToRecords, XlsxError } from '../../src/importer/xlsx.js';
import { buildXlsx, buildZip } from '../fixtures/xlsx.js';

const code = (fn: () => unknown): string => {
  try {
    fn();
  } catch (err) {
    return err instanceof XlsxError ? err.code : `other:${(err as Error).message}`;
  }
  return 'no_error';
};

describe('defensive XLSX intake reader', () => {
  it('reads shared and inline strings, keeps exact URLs and never evaluates formulas', () => {
    const url = 'https://pay-refund.example/kyc?ref=a&amp=1#step2';
    const buf = buildXlsx([['Target', 'Case_Ref', 'Priority'], [url, 'C-1', 5], ['=HYPERLINK("http://evil")', 'C-1', 1], ['', '', '']]);
    const r = xlsxToRecords(buf);
    expect(r.records).toEqual([{ line: 2, raw: { target: url, case_ref: 'C-1', priority: '5' } }, { line: 3, raw: { target: 'cached', case_ref: 'C-1', priority: '1' } }]);
    expect(r.formulaCells).toBe(1);
    expect(readFirstSheet(buildXlsx([['a'], ['x & <y>']], { inline: true })).rows[1]).toEqual(['x & <y>']);
  });

  it('refuses non-XLSX input, zip bombs, traversal entries, encrypted parts and oversized sheets', () => {
    expect(code(() => readFirstSheet(Buffer.from('target\nhttps://x.example\n')))).toBe('xlsx_not_zip');
    expect(code(() => readFirstSheet(buildZip([{ name: 'a.txt', data: 'x' }])))).toBe('xlsx_no_workbook');
    expect(code(() => readFirstSheet(buildZip([{ name: '../evil.xml', data: 'x' }])))).toBe('xlsx_unsafe_entry');
    const bomb = buildZip([{ name: 'xl/workbook.xml', data: Buffer.alloc(5_000_000, 0x41) }]);
    expect(code(() => readFirstSheet(bomb))).toBe('xlsx_compression_ratio');
    const liar = buildZip([{ name: 'xl/workbook.xml', data: Buffer.alloc(200_000, 0x41), declaredSize: 10 }]);
    expect(code(() => readFirstSheet(liar))).toBe('xlsx_inflate_failed');
    const many = buildXlsx([['target'], ...Array.from({ length: 30 }, (_, i) => [`https://h${i}.example/`])]);
    expect(readFirstSheet(many, { maxEntries: 100, maxPartBytes: 1 << 20, maxTotalInflatedBytes: 1 << 22, maxRatio: 150, maxRows: 10, maxColumns: 8 }).truncatedRows).toBe(true);
    const enc = buildZip([{ name: 'xl/workbook.xml', data: '<workbook/>' }]);
    enc.writeUInt16LE(1, enc.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02])) + 8); // set the encryption flag in the central directory
    expect(code(() => readFirstSheet(enc))).toBe('xlsx_encrypted');
  });
});
