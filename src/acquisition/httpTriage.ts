/**
 * HTTP triage acquisition (blueprint §7 data path). Produces a recorded HTTP
 * outcome, headers and body where received. Never advertised as browser
 * evidence. Redirects are followed manually so each hop is recorded and
 * validated; the gateway re-checks every destination at connection time.
 */
import { request, type Dispatcher } from 'undici';
import type { Policy } from '../config/policy.js';
import { MiB } from '../config/policy.js';
import type { AttemptWriter } from '../storage/artifactStore.js';
import { classifyNetError, detectAuthWall, detectChallenge, detectJsShell, detectPlaceholderPage, headerValue, htmlToText, parseRetryAfter } from '../router/signals.js';
import type { HttpObservation } from '../router/router.js';
import type { DomainEdgeInput } from '../queue/queue.js';
import { lookupViaGateway, type EgressConfig } from './egress.js';

export interface HttpHop {
  url: string;
  method: string;
  status: number | null;
  headers: Record<string, string | string[]>;
  startedAt: string;
  headersAt: string | null;
  location: string | null;
  error: string | null;
}

export interface HttpTriageResult {
  observation: HttpObservation;
  finalUrl: string | null;
  hops: HttpHop[];
  edges: DomainEdgeInput[];
  bodySaved: boolean;
  limitations: string[];
}

function flattenHeaders(h: Record<string, string | string[] | undefined>): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(h)) if (v !== undefined) out[k] = v;
  return out;
}

function errorChainMessage(err: unknown): string {
  const parts: string[] = [];
  let e: unknown = err;
  for (let i = 0; e && i < 5; i += 1) {
    const x = e as { code?: string; message?: string; cause?: unknown };
    parts.push([x.code, x.message].filter(Boolean).join(' '));
    e = x.cause;
  }
  return parts.join(' <- ').slice(0, 1000);
}

/** Read at most `max` bytes; report truncation instead of buffering unbounded bodies. */
async function readBounded(body: Dispatcher.ResponseData['body'], max: number): Promise<{ buf: Buffer; truncated: boolean; received: number }> {
  const chunks: Buffer[] = [];
  let received = 0;
  let kept = 0;
  let truncated = false;
  for await (const chunk of body) {
    const c = chunk as Buffer;
    received += c.length;
    if (kept + c.length > max) {
      chunks.push(c.subarray(0, max - kept));
      kept = max;
      truncated = true;
      body.destroy();
      break;
    }
    chunks.push(c);
    kept += c.length;
  }
  return { buf: Buffer.concat(chunks), truncated, received };
}

export async function runHttpTriage(args: {
  url: string;
  policy: Policy;
  writer: AttemptWriter;
  dispatcher: Dispatcher;
  egress: EgressConfig;
  deadline: number;
  expectedJson?: boolean;
}): Promise<HttpTriageResult> {
  const { policy, writer } = args;
  const maxBody = Math.floor(policy.capture.individual_text_body_mib_max * MiB);
  const hops: HttpHop[] = [];
  const edges: DomainEdgeInput[] = [];
  const limitations: string[] = ['HTTP client retrieval: no JavaScript execution, no rendering, not browser evidence'];
  const requestHeaders = {
    'user-agent': policy.http.user_agent,
    accept: args.expectedJson ? 'application/json, text/plain, */*' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'accept-language': policy.http.accept_language,
  };

  let currentUrl = args.url;
  let finalStatus: number | null = null;
  let finalHeaders: Record<string, string | string[]> = {};
  let bodyBuf: Buffer | null = null;
  let bodyTruncated = false;
  let netError: HttpObservation['netError'] = null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error('attempt deadline reached (TIMEOUT)')), Math.max(1000, args.deadline - Date.now()));

  try {
    for (let i = 0; i <= policy.scope.max_redirects; i += 1) {
      const hop: HttpHop = { url: currentUrl, method: 'GET', status: null, headers: {}, startedAt: new Date().toISOString(), headersAt: null, location: null, error: null };
      hops.push(hop);
      let res: Dispatcher.ResponseData;
      try {
        res = await request(currentUrl, {
          method: 'GET',
          headers: requestHeaders,
          dispatcher: args.dispatcher,
          signal: controller.signal,
          headersTimeout: Math.max(1000, args.deadline - Date.now()),
          bodyTimeout: Math.max(1000, args.deadline - Date.now()),
        });
      } catch (err) {
        const message = errorChainMessage(err);
        hop.error = message;
        let kind = classifyNetError(message);
        let egressError: string | null = null;
        if (kind === 'proxy_tunnel' || /Proxy response|tunnel|403|502|504/i.test(message) || kind === 'other') {
          const u = new URL(currentUrl);
          const look = await lookupViaGateway(args.egress, u.hostname, Number(u.port || (u.protocol === 'https:' ? 443 : 80)));
          if (look && !look.allowed && look.error) {
            egressError = look.error;
            kind = classifyNetError(look.error);
          } else if (/\(504\)/.test(message)) {
            kind = 'timeout';
          } else if (/\(502\)/.test(message) && kind === 'other') {
            kind = 'refused';
          }
        }
        netError = { kind, message, egressError };
        break;
      }
      hop.status = res.statusCode;
      hop.headers = flattenHeaders(res.headers);
      hop.headersAt = new Date().toISOString();
      const location = headerValue(res.headers, 'location');
      if (res.statusCode >= 300 && res.statusCode < 400 && location) {
        await res.body.dump({ limit: 64 * 1024 }).catch(() => undefined);
        let nextUrl: URL;
        try {
          nextUrl = new URL(location, currentUrl);
        } catch {
          hop.error = 'invalid_redirect_location';
          finalStatus = res.statusCode;
          finalHeaders = hop.headers;
          break;
        }
        hop.location = nextUrl.href;
        edges.push({ edgeType: 'redirect', fromUrl: currentUrl, toUrl: nextUrl.href, contacted: true, observedAt: hop.headersAt });
        if (!(policy.scope.allowed_schemes as readonly string[]).includes(nextUrl.protocol.replace(':', ''))) {
          hop.error = `redirect_to_unsupported_scheme:${nextUrl.protocol}`;
          limitations.push(`redirect to unsupported scheme not followed: ${nextUrl.protocol}`);
          finalStatus = res.statusCode;
          finalHeaders = hop.headers;
          break;
        }
        if (i === policy.scope.max_redirects) {
          limitations.push(`redirect limit ${policy.scope.max_redirects} reached`);
          finalStatus = res.statusCode;
          finalHeaders = hop.headers;
          break;
        }
        currentUrl = nextUrl.href;
        continue;
      }
      finalStatus = res.statusCode;
      finalHeaders = hop.headers;
      try {
        const r = await readBounded(res.body, Math.min(maxBody, writer.remainingBytes()));
        bodyBuf = r.buf;
        bodyTruncated = r.truncated;
        if (r.truncated) limitations.push(`body truncated at ${r.buf.length} bytes (limit ${maxBody})`);
      } catch (err) {
        hop.error = `body_read_failed: ${errorChainMessage(err)}`;
        limitations.push('body read interrupted');
      }
      break;
    }
  } finally {
    clearTimeout(timer);
  }

  const contentType = headerValue(finalHeaders, 'content-type');
  const isTextual = /text|html|json|xml|javascript/i.test(contentType ?? '') || contentType === null;
  const bodyText = bodyBuf && isTextual ? bodyBuf.toString('utf8') : null;
  const visibleText = bodyText && /html|xml/i.test(contentType ?? 'html') ? htmlToText(bodyText) : bodyText ?? '';
  const observation: HttpObservation = {
    status: finalStatus,
    contentType,
    bodyText,
    bodyBytes: bodyBuf?.length ?? 0,
    netError,
    challenge: detectChallenge({ headers: finalHeaders, html: bodyText, visibleTextLength: visibleText.length }),
    authSignals: detectAuthWall({ status: finalStatus, html: bodyText, headers: finalHeaders }),
    jsShellSignals: bodyText ? detectJsShell(bodyText, visibleText) : [],
    visibleTextLength: visibleText.length,
    expectedJson: args.expectedJson ?? false,
    retryAfterSeconds: parseRetryAfter(headerValue(finalHeaders, 'retry-after')),
    placeholder: bodyText ? detectPlaceholderPage({ html: bodyText, text: visibleText }) : { kind: null, signals: [] },
  };

  const now = new Date().toISOString();
  const record = {
    requested_url: args.url,
    final_url: netError ? null : currentUrl,
    request_headers: requestHeaders,
    hops,
    final_status: finalStatus,
    final_headers: finalHeaders,
    net_error: netError,
    body: bodyBuf ? { bytes: bodyBuf.length, truncated: bodyTruncated, content_type: contentType } : null,
    egress: { proxied: Boolean(args.egress.proxyUrl), vantage: args.egress.vantage, observation_point: 'collector HTTP client via egress gateway; DNS resolved by the gateway' },
    limitations,
  };
  await writer.writeArtifact('http/response.json', JSON.stringify(record, null, 2), {
    type: 'http_response_record', observedStart: hops[0]?.startedAt ?? now, observedEnd: now, creationMethod: 'undici request (manual redirects)',
    completeness: netError ? 'partial' : 'complete', limitations: [],
  });

  let bodySaved = false;
  if (bodyBuf) {
    const isHtml = /html/i.test(contentType ?? '') || /^\s*<(!doctype|html)/i.test(bodyText ?? '');
    bodySaved = await writer.writeArtifact(isHtml ? 'http/body.html' : 'http/body.bin', bodyBuf, {
      type: isHtml ? 'raw_html' : 'http_body', observedStart: hops.at(-1)?.headersAt ?? now, observedEnd: now,
      creationMethod: 'raw HTTP response body as received (no Accept-Encoding requested; transfer-decoded only)', completeness: bodyTruncated ? 'truncated' : 'complete',
      limitations: bodyTruncated ? [`truncated at ${bodyBuf.length} bytes`] : [], metadata: { content_type: contentType, final_url: currentUrl },
    });
  } else if (!netError) {
    writer.recordMissing({ type: 'raw_html', observedStart: null, observedEnd: null, creationMethod: 'raw HTTP response body', completeness: 'omitted', limitations: ['no body received'] });
  }

  return { observation, finalUrl: netError ? null : currentUrl, hops, edges, bodySaved, limitations };
}
