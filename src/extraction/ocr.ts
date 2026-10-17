/**
 * Selective OCR on saved element crops using the Tesseract CLI when installed
 * (the application image installs tesseract-ocr). One OCR task at a time
 * (ocr_concurrency: 1) and a hard timeout per crop. OCR output is always a
 * derivative with its own provenance; ambiguous digits are never promoted to
 * confirmed identifiers.
 */
import { execFile } from 'node:child_process';

let available: boolean | null = null;
let queue: Promise<unknown> = Promise.resolve();

export async function ocrAvailable(): Promise<boolean> {
  if (available !== null) return available;
  available = await new Promise<boolean>((resolve) => {
    execFile(process.env.TESSERACT_BIN ?? 'tesseract', ['--version'], { timeout: 5000 }, (err) => resolve(!err));
  });
  return available;
}

export interface OcrResult {
  text: string;
  engine: string;
}

/** Serialised: callers queue behind each other so only one OCR process runs. */
export function ocrImage(path: string, timeoutMs: number, lang = process.env.TESSERACT_LANG ?? 'eng'): Promise<OcrResult> {
  const task = queue.then(() => new Promise<OcrResult>((resolve, reject) => {
    execFile(
      process.env.TESSERACT_BIN ?? 'tesseract',
      [path, 'stdout', '-l', lang, '--psm', '6'],
      { timeout: timeoutMs, maxBuffer: 2 * 1024 * 1024, env: { ...process.env, OMP_THREAD_LIMIT: '1' } },
      (err, stdout) => {
        if (err) reject(new Error(`tesseract failed: ${err.message.slice(0, 200)}`));
        else resolve({ text: stdout.slice(0, 100_000), engine: `tesseract (${lang}, psm 6)` });
      },
    );
  }));
  queue = task.catch(() => undefined);
  return task;
}
