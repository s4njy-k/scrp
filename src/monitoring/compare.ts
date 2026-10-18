/**
 * Change measures for post-action verification (checklist §8): a 64-bit
 * difference hash of a screenshot and word-shingle similarity of rendered text.
 * Both are comparison aids for analysts; neither deletes or replaces evidence.
 */
import { PNG } from 'pngjs';

/** dHash: 9x8 grayscale box-sampled image, one bit per horizontal gradient. Null when undecodable or too large. */
export function differenceHash(png: Buffer, maxMegapixels: number): bigint | null {
  if (png.length < 24 || png.readUInt32BE(12) !== 0x49484452) return null;
  const w = png.readUInt32BE(16);
  const h = png.readUInt32BE(20);
  if (!w || !h || (w * h) / 1e6 > maxMegapixels) return null;
  let img: PNG;
  try {
    img = PNG.sync.read(png);
  } catch {
    return null;
  }
  // Compare the above-the-fold region (first viewport-sized band) so long pages remain comparable.
  const regionH = Math.min(img.height, Math.round(img.width * 0.7) || img.height);
  const gray: number[] = [];
  for (let gy = 0; gy < 8; gy += 1) {
    for (let gx = 0; gx < 9; gx += 1) {
      const x0 = Math.floor((gx * img.width) / 9);
      const x1 = Math.max(x0 + 1, Math.floor(((gx + 1) * img.width) / 9));
      const y0 = Math.floor((gy * regionH) / 8);
      const y1 = Math.max(y0 + 1, Math.floor(((gy + 1) * regionH) / 8));
      let sum = 0;
      let n = 0;
      const sx = Math.max(1, Math.floor((x1 - x0) / 6));
      const sy = Math.max(1, Math.floor((y1 - y0) / 6));
      for (let y = y0; y < y1; y += sy) {
        for (let x = x0; x < x1; x += sx) {
          const i = (y * img.width + x) * 4;
          sum += 0.299 * img.data[i]! + 0.587 * img.data[i + 1]! + 0.114 * img.data[i + 2]!;
          n += 1;
        }
      }
      gray.push(sum / n);
    }
  }
  let hash = 0n;
  for (let y = 0; y < 8; y += 1) {
    for (let x = 0; x < 8; x += 1) {
      hash = (hash << 1n) | (gray[y * 9 + x]! > gray[y * 9 + x + 1]! ? 1n : 0n);
    }
  }
  return hash;
}

export function hammingDistance(a: bigint, b: bigint): number {
  let x = a ^ b;
  let n = 0;
  while (x) {
    n += Number(x & 1n);
    x >>= 1n;
  }
  return n;
}

/** Jaccard similarity of word 3-shingles over the first 200 kB of each text. */
export function textSimilarity(a: string, b: string): number {
  const shingles = (s: string) => {
    const words = s.slice(0, 200_000).toLowerCase().split(/[^\p{L}\p{N}@.]+/u).filter(Boolean);
    const set = new Set<string>();
    for (let i = 0; i + 2 < words.length && set.size < 50_000; i += 1) set.add(`${words[i]} ${words[i + 1]} ${words[i + 2]}`);
    if (set.size === 0 && words.length) set.add(words.join(' '));
    return set;
  };
  const x = shingles(a);
  const y = shingles(b);
  if (x.size === 0 && y.size === 0) return 1;
  let inter = 0;
  for (const s of x) if (y.has(s)) inter += 1;
  return inter / (x.size + y.size - inter);
}
