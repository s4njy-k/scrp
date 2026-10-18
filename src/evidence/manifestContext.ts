/**
 * Builds the v2 manifest context (checklist §1 "versioned evidence manifest";
 * blueprint v4 §23.3): original input, navigation and observed times (UTC +
 * IST), clock status, engine/build, capture context, vantage, redirect history
 * and software build. Values are runtime observations, never placeholders.
 */
import { readFileSync } from 'node:fs';
import type { ManifestContext } from '../acquisition/contract.js';
import type { DomainEdgeInput } from '../queue/queue.js';
import type { Lease } from '../queue/types.js';
import { effectiveClockStatus, formatIst, type ClockStatus } from './time.js';

let cachedVersion: string | null = null;
export function collectorVersion(): string {
  if (cachedVersion) return cachedVersion;
  try {
    const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as { version?: string };
    cachedVersion = process.env.APP_VERSION ?? pkg.version ?? 'unknown';
  } catch {
    cachedVersion = process.env.APP_VERSION ?? 'unknown';
  }
  return cachedVersion;
}

const REDIRECT_EDGES = new Set(['redirect', 'meta_refresh', 'js_navigation']);

export interface ManifestContextInput {
  lease: Lease;
  engine: string;
  adapter: string;
  vantage: string;
  startedAt: string;
  engineVersion: string | null;
  userAgent: string | null;
  settings: Record<string, unknown>;
  edges: readonly DomainEdgeInput[];
}

export function buildManifestContext(i: ManifestContextInput): ManifestContext {
  const declaredIp = process.env.EGRESS_PUBLIC_IP?.trim() || null;
  const clock: ClockStatus = effectiveClockStatus(i.lease.clock as Partial<ClockStatus> | null | undefined, Date.parse(i.startedAt));
  const s = i.settings;
  return {
    originalInputs: i.lease.originalInputs ?? [],
    navigationUrl: i.lease.target.url,
    observedAtUtc: i.startedAt,
    observedAtIst: formatIst(i.startedAt),
    clock,
    profile: {
      name: i.lease.job.profile,
      captureVariant: i.lease.job.capture_variant,
      retentionClass: i.lease.job.retention_class,
      caseRefs: i.lease.caseRefs ?? (i.lease.job.case_ref ? [i.lease.job.case_ref] : []),
    },
    engineInfo: { name: String(s.engine ?? i.engine), version: i.engineVersion, adapter: i.adapter },
    captureContext: {
      user_agent: i.userAgent,
      viewport: s.viewport ?? null,
      device_scale_factor: s.device_scale_factor ?? null,
      mobile: s.mobile ?? false,
      locale: s.locale ?? null,
      timezone: s.timezone ?? null,
      service_workers: s.service_workers ?? null,
      block_ads: s.block_ads ?? null,
      suppress_render_resources: s.suppress_render_resources ?? null,
      relaxed_tls: s.relaxed_tls ?? false,
      allowed_interactions: s.allowed_interactions ?? i.lease.job.allowed_interactions,
      browser_mode: s.browser_mode ?? null,
      chromium_sandbox: s.chromium_sandbox ?? null,
    },
    networkVantage: {
      id: i.vantage,
      publicIp: declaredIp,
      // The collector does not call third-party "what is my IP" services; an operator may declare the egress IP.
      publicIpSource: declaredIp ? 'operator_declared' : 'not_observed',
    },
    redirectChain: i.edges
      .filter((e) => REDIRECT_EDGES.has(e.edgeType))
      .slice(0, 50)
      .map((e) => ({ type: e.edgeType, from: e.fromUrl, to: e.toUrl, at: e.observedAt })),
    software: { collector_version: collectorVersion(), git_commit: process.env.GIT_COMMIT ?? null, node_version: process.version },
    integrity: {
      algorithm: 'sha256',
      note: 'Each artifact hash is computed over the saved bytes. This manifest\'s own SHA-256 is recorded outside it (ledger attempts.manifest_sha256, custody chain, package index), never inside itself. Hashes support integrity checking; they do not by themselves establish authenticity, lawful acquisition or admissibility.',
    },
  };
}
