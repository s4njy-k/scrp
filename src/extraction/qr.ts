/**
 * QR decoding on preserved screenshots/crops (blueprint §11): runs after
 * capture on saved artifacts, never on the live page.
 */
import jsQRImport from 'jsqr';
import { PNG } from 'pngjs';
import { pngDimensions } from '../capture/imageCheck.js';

type JsQR = (data: Uint8ClampedArray, width: number, height: number, opts?: { inversionAttempts?: 'dontInvert' | 'onlyInvert' | 'attemptBoth' | 'invertFirst' }) => { data: string; location: { topLeftCorner: { x: number; y: number }; bottomRightCorner: { x: number; y: number } } } | null;

// jsqr ships CommonJS with a `default` property; normalise the ESM interop shape.
const jsQR: JsQR = ((jsQRImport as unknown as { default?: JsQR }).default ?? jsQRImport) as unknown as JsQR;

export interface QrResult {
  payload: string;
  bbox: { x: number; y: number; width: number; height: number };
}

/** Decode at most one QR code from a PNG. Bounded by a megapixel budget. */
export function decodeQrFromPng(buf: Buffer, maxMegapixels = 8): QrResult | null {
  const dims = pngDimensions(buf);
  if (!dims || dims.width * dims.height > maxMegapixels * 1e6) return null;
  let png: PNG;
  try {
    png = PNG.sync.read(buf);
  } catch {
    return null;
  }
  const r = jsQR(new Uint8ClampedArray(png.data.buffer, png.data.byteOffset, png.data.length), png.width, png.height, { inversionAttempts: 'attemptBoth' });
  if (!r || !r.data) return null;
  const { topLeftCorner: tl, bottomRightCorner: br } = r.location;
  return { payload: r.data.slice(0, 4000), bbox: { x: Math.round(tl.x), y: Math.round(tl.y), width: Math.round(br.x - tl.x), height: Math.round(br.y - tl.y) } };
}
