/**
 * Screenshot validation (blueprint §9 step 8). Checks the PNG decodes and has
 * nonzero dimensions, within a bounded decode budget. Near-uniform/blank
 * heuristics are warnings only: simple pages can legitimately be sparse, and
 * pixel checks cannot establish semantic completeness.
 */
import { PNG } from 'pngjs';

export interface ImageCheck {
  valid: boolean;
  width: number;
  height: number;
  warnings: string[];
  error: string | null;
}

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

export function pngDimensions(buf: Buffer): { width: number; height: number } | null {
  if (buf.length < 24 || !buf.subarray(0, 8).equals(PNG_SIGNATURE) || buf.toString('ascii', 12, 16) !== 'IHDR') return null;
  return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
}

export function checkPng(buf: Buffer, maxDecodeMegapixels: number): ImageCheck {
  const dims = pngDimensions(buf);
  if (!dims) return { valid: false, width: 0, height: 0, warnings: [], error: 'not a PNG (bad signature/IHDR)' };
  const { width, height } = dims;
  if (width === 0 || height === 0) return { valid: false, width, height, warnings: [], error: 'zero dimension' };
  const mp = (width * height) / 1e6;
  if (mp > maxDecodeMegapixels) {
    return { valid: true, width, height, warnings: [`not pixel-decoded: ${mp.toFixed(1)} MP exceeds decode budget`], error: null };
  }
  let png: PNG;
  try {
    png = PNG.sync.read(buf);
  } catch (err) {
    return { valid: false, width, height, warnings: [], error: `decode failed: ${(err as Error).message}` };
  }
  const warnings: string[] = [];
  // Sample a grid of pixels; flag near-uniform images.
  const step = Math.max(1, Math.floor(Math.sqrt((width * height) / 4096)));
  let n = 0;
  let sum = 0;
  let sumSq = 0;
  for (let y = 0; y < height; y += step) {
    for (let x = 0; x < width; x += step) {
      const i = (y * width + x) * 4;
      const lum = 0.299 * png.data[i]! + 0.587 * png.data[i + 1]! + 0.114 * png.data[i + 2]!;
      sum += lum;
      sumSq += lum * lum;
      n += 1;
    }
  }
  const mean = sum / n;
  const variance = sumSq / n - mean * mean;
  if (variance < 4) warnings.push(`near_uniform_image (luminance variance ${variance.toFixed(2)}, mean ${mean.toFixed(0)}) - warning only`);
  return { valid: true, width, height, warnings, error: null };
}
