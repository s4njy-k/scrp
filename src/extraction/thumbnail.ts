/**
 * Lightweight thumbnails for list and timeline views (checklist §10). A
 * thumbnail is a DERIVATIVE: stored apart from originals, hashed, pointing at
 * its source artifact, and never substituted for the original in evidence
 * packages. Tall pages are cropped from the top (recorded in the metadata).
 */
import { PNG } from 'pngjs';

export interface Thumbnail {
  png: Buffer;
  width: number;
  height: number;
  sourceWidth: number;
  sourceHeight: number;
  croppedFromTop: boolean;
}

export function makeThumbnail(source: Buffer, opts: { width?: number; maxHeight?: number; maxSourceMegapixels: number }): Thumbnail | null {
  const width = opts.width ?? 360;
  const maxHeight = opts.maxHeight ?? 540;
  let img: PNG;
  try {
    // Check dimensions from the IHDR before decoding pixels (bounded memory).
    if (source.length < 24 || source.readUInt32BE(12) !== 0x49484452) return null;
    const w = source.readUInt32BE(16);
    const h = source.readUInt32BE(20);
    if (!w || !h || (w * h) / 1e6 > opts.maxSourceMegapixels) return null;
    img = PNG.sync.read(source);
  } catch {
    return null;
  }
  const scale = Math.min(1, width / img.width);
  const outW = Math.max(1, Math.round(img.width * scale));
  const fullH = Math.max(1, Math.round(img.height * scale));
  const outH = Math.min(fullH, maxHeight);
  const out = new PNG({ width: outW, height: outH });
  const step = 1 / scale;
  for (let y = 0; y < outH; y += 1) {
    const y0 = Math.floor(y * step);
    const y1 = Math.min(img.height, Math.max(y0 + 1, Math.floor((y + 1) * step)));
    for (let x = 0; x < outW; x += 1) {
      const x0 = Math.floor(x * step);
      const x1 = Math.min(img.width, Math.max(x0 + 1, Math.floor((x + 1) * step)));
      let r = 0, g = 0, b = 0, a = 0, n = 0;
      // Box filter, sampled sparsely for large reductions to bound CPU.
      const sy = Math.max(1, Math.floor((y1 - y0) / 4));
      const sx = Math.max(1, Math.floor((x1 - x0) / 4));
      for (let yy = y0; yy < y1; yy += sy) {
        for (let xx = x0; xx < x1; xx += sx) {
          const i = (yy * img.width + xx) * 4;
          r += img.data[i]!; g += img.data[i + 1]!; b += img.data[i + 2]!; a += img.data[i + 3]!;
          n += 1;
        }
      }
      const o = (y * outW + x) * 4;
      out.data[o] = r / n; out.data[o + 1] = g / n; out.data[o + 2] = b / n; out.data[o + 3] = a / n;
    }
  }
  return { png: PNG.sync.write(out), width: outW, height: outH, sourceWidth: img.width, sourceHeight: img.height, croppedFromTop: outH < fullH };
}
