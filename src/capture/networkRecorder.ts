/**
 * Network and page-event recorder (blueprint §10).
 *
 * Registered on the BrowserContext BEFORE navigation so popups, frames and
 * service workers are included. Streams bounded JSONL; saves relevant bodies
 * within explicit limits and records every omission/truncation reason.
 * Never calls request.frame() on service-worker requests.
 */
import type { BrowserContext, Page, Request, Response, WebSocket, Worker } from 'playwright-core';
import type { Policy } from '../config/policy.js';
import { MiB } from '../config/policy.js';
import type { AttemptWriter, BoundedStream } from '../storage/artifactStore.js';
import type { DomainEdgeInput } from '../queue/queue.js';

const SENSITIVE_HEADERS = new Set(['cookie', 'set-cookie', 'authorization', 'proxy-authorization', 'x-csrf-token', 'x-xsrf-token']);

export function redactHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k] = SENSITIVE_HEADERS.has(k.toLowerCase()) ? `[redacted ${v.length} chars; see restricted HAR]` : v;
  }
  return out;
}

function extFor(contentType: string | undefined): string {
  const ct = (contentType ?? '').toLowerCase();
  if (ct.includes('html')) return 'html';
  if (ct.includes('json')) return 'json';
  if (ct.includes('javascript') || ct.includes('ecmascript')) return 'js';
  if (ct.includes('css')) return 'css';
  if (ct.includes('xml')) return 'xml';
  if (ct.includes('text/')) return 'txt';
  if (ct.includes('pdf')) return 'pdf';
  if (ct.includes('png')) return 'png';
  if (ct.includes('jpeg')) return 'jpg';
  return 'bin';
}

function isTextual(contentType: string | undefined): boolean {
  return /text|html|json|javascript|ecmascript|xml/i.test(contentType ?? '');
}

export interface RecorderStats {
  events: number;
  requests: number;
  responses: number;
  failures: number;
  websockets: number;
  wsFrames: number;
  serviceWorkers: number;
  popups: number;
  bodiesSaved: number;
  bodiesOmitted: number;
  truncated: boolean;
}

export class NetworkRecorder {
  private readonly stream: BoundedStream;
  private readonly ids = new WeakMap<Request, number>();
  private seq = 0;
  private bodySeq = 0;
  private bodyBytes = 0;
  private readonly bodyBudget: number;
  private readonly maxBody: number;
  readonly stats: RecorderStats = { events: 0, requests: 0, responses: 0, failures: 0, websockets: 0, wsFrames: 0, serviceWorkers: 0, popups: 0, bodiesSaved: 0, bodiesOmitted: 0, truncated: false };
  readonly edges: DomainEdgeInput[] = [];
  private readonly seenHosts = new Set<string>();
  readonly frames: { url: string; name: string; parentUrl: string | null; at: string }[] = [];
  readonly mainDocumentResponses: { url: string; status: number; headers: Record<string, string>; at: string }[] = [];
  readonly pages: Page[] = [];
  /** The page being captured. Popups are recorded but never stand in for it. */
  private primaryPage: Page | null = null;
  readonly console: string[] = [];
  rendererCrashed = false;
  private stopped = false;

  constructor(
    private readonly writer: AttemptWriter,
    private readonly policy: Policy,
    private readonly onPopupLimit: (page: Page) => void,
  ) {
    const attemptBudget = policy.capture.attempt_artifacts_mib_max * MiB;
    this.stream = writer.openJsonl('network/events.jsonl', Math.floor(attemptBudget * 0.25));
    // Keep at least half of the attempt budget for screenshots, DOM and HAR.
    this.bodyBudget = Math.floor(attemptBudget * 0.4);
    this.maxBody = Math.floor(policy.capture.individual_text_body_mib_max * MiB);
  }

  private emit(event: Record<string, unknown>): void {
    if (this.stopped) return;
    if (this.stats.events >= this.policy.bounds.max_network_events_per_attempt) {
      if (!this.stats.truncated) {
        this.stats.truncated = true;
        this.stream.write(JSON.stringify({ type: 'recorder_truncated', at: new Date().toISOString(), reason: 'max_network_events_per_attempt' }));
      }
      return;
    }
    this.stats.events += 1;
    if (!this.stream.write(JSON.stringify({ at: new Date().toISOString(), ...event }))) this.stats.truncated = true;
  }

  private idFor(req: Request): number {
    let id = this.ids.get(req);
    if (id === undefined) {
      id = ++this.seq;
      this.ids.set(req, id);
    }
    return id;
  }

  private frameInfo(req: Request): Record<string, unknown> {
    const sw = req.serviceWorker();
    if (sw) return { service_worker: sw.url() };
    try {
      const f = req.frame();
      const main = f.parentFrame() === null;
      // main_frame: top frame of ANY page (popups included); primary_page: that page is the captured one.
      return { frame_url: f.url(), main_frame: main, ...(main ? { primary_page: f.page() === this.primaryPage } : {}) };
    } catch {
      return { frame_url: null, frame_unavailable: true };
    }
  }

  private noteHostEdge(fromUrl: string | null, toUrl: string, type: string): void {
    try {
      const host = new URL(toUrl).host;
      const key = `${type}:${host}`;
      if (this.seenHosts.has(key)) return;
      this.seenHosts.add(key);
      this.edges.push({ edgeType: type, fromUrl, toUrl, contacted: true, observedAt: new Date().toISOString() });
    } catch {
      /* non-URL (data:, blob:) */
    }
  }

  attach(context: BrowserContext): void {
    context.on('request', (req) => this.onRequest(req));
    context.on('response', (res) => this.onResponse(res));
    context.on('requestfailed', (req) => {
      this.stats.failures += 1;
      this.emit({ type: 'request_failed', id: this.idFor(req), url: req.url(), failure: req.failure()?.errorText ?? null });
    });
    context.on('requestfinished', (req) => {
      const t = req.timing();
      this.emit({ type: 'request_finished', id: this.idFor(req), timing: t });
    });
    context.on('page', (page) => this.attachPage(page, true));
    // Service workers are retained in normal evidence mode and recorded (§10).
    const onWorker = (w: Worker) => {
      this.stats.serviceWorkers += 1;
      this.emit({ type: 'service_worker', url: w.url() });
      this.noteHostEdge(null, w.url(), 'service_worker');
    };
    if ('serviceWorkers' in context) {
      context.on('serviceworker', onWorker);
    }
  }

  attachPage(page: Page, isNewPage: boolean): void {
    if (this.pages.includes(page)) return;
    if (isNewPage && this.pages.length > 0) {
      this.stats.popups += 1;
      const opener = this.pages[0]?.url() ?? null;
      this.emit({ type: 'popup', url: page.url(), opener });
      this.edges.push({ edgeType: 'popup', fromUrl: opener, toUrl: page.url() || 'about:blank', contacted: true, observedAt: new Date().toISOString() });
      if (this.stats.popups > this.policy.bounds.max_popups_per_attempt) {
        this.emit({ type: 'popup_closed_limit', url: page.url() });
        this.onPopupLimit(page);
        return;
      }
    }
    this.pages.push(page);
    // The context's first page is the captured page (the context 'page' event may
    // deliver it before attachPage(page, false) runs); later pages are popups.
    if (this.primaryPage === null) this.primaryPage = page;
    page.on('frameattached', (f) => {
      if (this.frames.length >= this.policy.bounds.max_frames_per_page * 4) return;
      this.frames.push({ url: f.url(), name: f.name(), parentUrl: f.parentFrame()?.url() ?? null, at: new Date().toISOString() });
      this.emit({ type: 'frame_attached', url: f.url(), name: f.name(), parent: f.parentFrame()?.url() ?? null });
    });
    page.on('framenavigated', (f) => {
      const main = f.parentFrame() === null;
      this.emit({ type: 'frame_navigated', url: f.url(), main_frame: main, name: f.name() });
      if (!main) this.noteHostEdge(f.parentFrame()?.url() ?? null, f.url(), 'frame');
    });
    page.on('websocket', (ws) => this.onWebSocket(ws));
    page.on('console', (msg) => {
      if (this.console.length < this.policy.bounds.max_console_messages) this.console.push(JSON.stringify({ at: new Date().toISOString(), type: msg.type(), text: msg.text().slice(0, 2000) }));
    });
    page.on('pageerror', (err) => {
      if (this.console.length < this.policy.bounds.max_console_messages) this.console.push(JSON.stringify({ at: new Date().toISOString(), type: 'pageerror', text: String(err.message).slice(0, 2000) }));
    });
    page.on('dialog', (d) => {
      this.emit({ type: 'dialog', dialog_type: d.type(), message: d.message().slice(0, 2000), action: 'dismissed' });
      d.dismiss().catch(() => undefined);
    });
    page.on('download', (dl) => {
      // Downloads are never executed and not accepted in the generic profile.
      this.emit({ type: 'download_refused', url: dl.url(), suggested_filename: dl.suggestedFilename().slice(0, 200) });
      dl.cancel().catch(() => undefined);
    });
    page.on('crash', () => {
      this.rendererCrashed = true;
      this.emit({ type: 'renderer_crash', url: page.url() });
    });
  }

  private onRequest(req: Request): void {
    this.stats.requests += 1;
    if (this.stats.requests > this.policy.bounds.max_requests_per_attempt) {
      if (this.stats.requests === this.policy.bounds.max_requests_per_attempt + 1) this.emit({ type: 'request_limit_reached', limit: this.policy.bounds.max_requests_per_attempt });
      return;
    }
    const redirectedFrom = req.redirectedFrom();
    this.emit({
      type: 'request', id: this.idFor(req), url: req.url(), method: req.method(), resource_type: req.resourceType(),
      navigation: req.isNavigationRequest(), redirected_from: redirectedFrom?.url() ?? null,
      headers: redactHeaders(req.headers()), post_data_bytes: req.postDataBuffer()?.length ?? 0, ...this.frameInfo(req),
    });
    if (redirectedFrom) this.edges.push({ edgeType: 'redirect', fromUrl: redirectedFrom.url(), toUrl: req.url(), contacted: true, observedAt: new Date().toISOString() });
    else if (!req.isNavigationRequest()) this.noteHostEdge(null, req.url(), 'subresource');
  }

  private onResponse(res: Response): void {
    this.stats.responses += 1;
    const req = res.request();
    const headers = res.headers();
    const info = this.frameInfo(req);
    // Only the captured page's own documents decide its status/headers; a popup's
    // 401/403/429 must not be mistaken for the target's response.
    const primaryDocument = req.isNavigationRequest() && info.main_frame === true && info.primary_page === true;
    if (primaryDocument) {
      this.mainDocumentResponses.push({ url: res.url(), status: res.status(), headers, at: new Date().toISOString() });
    }
    const id = this.idFor(req);
    this.writer.track((async () => {
      const [addr, sec] = await Promise.all([res.serverAddr().catch(() => null), res.securityDetails().catch(() => null)]);
      this.emit({
        type: 'response', id, url: res.url(), status: res.status(), status_text: res.statusText(),
        from_service_worker: res.fromServiceWorker(), headers: redactHeaders(headers),
        server_addr: addr, security: sec,
        observation_note: 'server_addr is the address the browser connected to (the egress gateway when proxied), not necessarily the origin',
      });
    })());
    if (req.isNavigationRequest() && res.status() >= 300 && res.status() < 400 && headers.location) {
      try {
        this.edges.push({ edgeType: 'redirect', fromUrl: res.url(), toUrl: new URL(headers.location, res.url()).href, contacted: false, observedAt: new Date().toISOString() });
      } catch { /* invalid location */ }
    }
    this.maybeSaveBody(res, req, id, headers, primaryDocument);
  }

  private maybeSaveBody(res: Response, req: Request, id: number, headers: Record<string, string>, isMainDocument: boolean): void {
    if (this.stopped) return; // finalisation has begun: no new body writes
    const type = req.resourceType();
    const isDoc = req.isNavigationRequest();
    if (!isDoc && !this.policy.browser.body_resource_types.includes(type)) return;
    if (res.status() >= 300 && res.status() < 400) return; // redirects have no body
    const ct = headers['content-type'];
    const omit = (reason: string) => {
      this.stats.bodiesOmitted += 1;
      this.emit({ type: 'body_omitted', id, url: res.url(), reason });
    };
    if (!isDoc && !isTextual(ct)) return omit(`non_text_content_type:${ct ?? 'none'}`);
    const declared = Number(headers['content-length'] ?? NaN);
    if (Number.isFinite(declared) && declared > this.maxBody) return omit(`content_length_${declared}_exceeds_${this.maxBody}`);
    if (this.bodyBytes >= this.bodyBudget) return omit('attempt_body_budget_exhausted');
    this.writer.track((async () => {
      let body: Buffer;
      try {
        body = await res.body();
      } catch (err) {
        return omit(`body_unavailable:${(err as Error).message.slice(0, 200)}`);
      }
      let truncated = false;
      if (body.length > this.maxBody) {
        body = body.subarray(0, this.maxBody);
        truncated = true;
      }
      if (this.stopped) return; // body arrived after finalisation started
      if (this.bodyBytes + body.length > this.bodyBudget) return omit('attempt_body_budget_exhausted');
      this.bodyBytes += body.length;
      const n = ++this.bodySeq;
      const rel = `bodies/${String(n).padStart(5, '0')}.${extFor(ct)}`;
      const at = new Date().toISOString();
      const ok = await this.writer.writeArtifact(rel, body, {
        type: isMainDocument ? 'raw_html' : 'response_body',
        observedStart: at, observedEnd: at, creationMethod: 'Playwright response.body() (decoded by browser)',
        completeness: truncated ? 'truncated' : 'complete', limitations: truncated ? [`truncated at ${this.maxBody} bytes`] : [],
        metadata: { request_id: id, url: res.url(), status: res.status(), content_type: ct ?? null, resource_type: req.resourceType() },
      });
      if (ok) {
        this.stats.bodiesSaved += 1;
        this.emit({ type: 'body_saved', id, path: rel, bytes: body.length, truncated });
      } else {
        omit('attempt_artifact_budget_exceeded');
      }
    })());
  }

  private onWebSocket(ws: WebSocket): void {
    this.stats.websockets += 1;
    this.emit({ type: 'websocket_open', url: ws.url() });
    this.noteHostEdge(null, ws.url(), 'websocket');
    const max = this.policy.bounds.max_websocket_frames_per_attempt;
    const keep = this.policy.bounds.max_websocket_frame_bytes_retained;
    const frame = (direction: string) => (data: { payload: string | Buffer }) => {
      this.stats.wsFrames += 1;
      if (this.stats.wsFrames > max) return;
      const p = data.payload;
      const len = typeof p === 'string' ? Buffer.byteLength(p) : p.length;
      const sample = typeof p === 'string' ? p.slice(0, keep) : p.subarray(0, keep).toString('base64');
      this.emit({ type: 'websocket_frame', url: ws.url(), direction, bytes: len, payload: sample, payload_encoding: typeof p === 'string' ? 'text' : 'base64', truncated: len > keep });
    };
    ws.on('framesent', frame('sent'));
    ws.on('framereceived', frame('received'));
    ws.on('socketerror', (e) => this.emit({ type: 'websocket_error', url: ws.url(), error: String(e).slice(0, 500) }));
    ws.on('close', () => this.emit({ type: 'websocket_close', url: ws.url() }));
  }

  stop(): void {
    this.stopped = true;
  }

  async end(): Promise<{ bytes: number; truncated: boolean }> {
    this.stopped = true;
    await this.stream.end();
    return { bytes: this.stream.bytes, truncated: this.stats.truncated || this.stream.truncated };
  }
}
