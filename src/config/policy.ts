/**
 * Collector application policy (blueprint §14).
 *
 * This is the collector's own schema, not upstream Crawlee/Playwright/Scrapling
 * options. Every value is mapped explicitly onto the pinned libraries by the
 * code that consumes it; nothing here is passed through blindly.
 */
import { readFileSync } from 'node:fs';
import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

const positiveInt = z.number().int().positive();
const nonNegativeInt = z.number().int().nonnegative();
const positiveNumber = z.number().positive();

export const CaptureProfileName = z.enum(['data_triage', 'browser_evidence']);
export type CaptureProfileName = z.infer<typeof CaptureProfileName>;

export const LimitsSchema = z
  .object({
    browser_slots_global: positiveInt.max(8),
    alternate_browser_slots_max: nonNegativeInt,
    http_concurrency_global: positiveInt.max(64),
    top_level_concurrency_per_domain: positiveInt,
    per_domain_delay_seconds: z.number().nonnegative(),
    http_attempts_max: nonNegativeInt,
    browser_attempts_max: nonNegativeInt,
    acquisition_attempts_max: positiveInt,
    active_acquisition_seconds_max: positiveNumber,
    http_attempt_seconds: positiveNumber,
    primary_browser_seconds: positiveNumber,
    alternate_browser_seconds: positiveNumber,
    finalisation_reserve_seconds: positiveNumber,
    child_pages_per_target_max: nonNegativeInt,
  })
  .strict();

export const CaptureSchema = z
  .object({
    viewport: z.object({ width: positiveInt.max(7680), height: positiveInt.max(4320) }).strict(),
    device_scale_factor: positiveNumber.max(4),
    original_format: z.literal('png'),
    original_service_workers: z.enum(['allow', 'block']),
    block_ads: z.boolean(),
    suppress_render_resources: z.boolean(),
    full_image_megapixels_max: positiveNumber,
    scroll_tiles_max: positiveInt,
    individual_text_body_mib_max: positiveNumber,
    attempt_artifacts_mib_max: positiveNumber,
  })
  .strict();

export const StorageSchema = z
  .object({
    captures_gb_soft_limit: positiveNumber,
    host_free_gb_pause_below: positiveNumber,
    host_free_gb_resume_above: positiveNumber,
    delete_case_hold_artifacts: z.literal(false),
  })
  .strict();

export const QueueSchema = z
  .object({
    heartbeat_seconds: positiveNumber,
    lease_seconds: positiveNumber,
    reclaim_expired_leases: z.boolean(),
  })
  .strict();

/** Extensions beyond the blueprint's minimal YAML: scope, derived bounds, engine settings. */
export const ScopeSchema = z
  .object({
    allowed_schemes: z.array(z.enum(['http', 'https'])).min(1),
    allowed_ports: z.array(z.number().int().min(1).max(65535)).min(1),
    domain_seed_schemes: z.array(z.enum(['https', 'http'])).min(1),
    allow_ip_literals: z.boolean(),
    reject_userinfo_urls: z.literal(true),
    follow_external_redirects: z.boolean(),
    max_redirects: positiveInt.max(30),
  })
  .strict();

export const BoundsSchema = z
  .object({
    max_network_events_per_attempt: positiveInt,
    max_requests_per_attempt: positiveInt,
    max_websocket_frames_per_attempt: nonNegativeInt,
    max_websocket_frame_bytes_retained: nonNegativeInt,
    max_frames_per_page: positiveInt,
    max_popups_per_attempt: nonNegativeInt,
    max_page_steps: positiveInt,
    max_dom_snapshot_mib: positiveNumber,
    max_image_decode_megapixels: positiveNumber,
    max_element_captures: nonNegativeInt,
    max_scroll_steps: nonNegativeInt,
    max_console_messages: nonNegativeInt,
  })
  .strict();

export const HttpSchema = z
  .object({
    user_agent: z.string().min(1),
    accept_language: z.string().min(1),
  })
  .strict();

export const BrowserSchema = z
  .object({
    primary_engine: z.literal('chromium'),
    alternate_engine: z.enum(['firefox', 'scrapling', 'none']),
    chromium_channel: z.enum(['chromium', 'chrome-headless-shell']),
    user_agent: z.string().min(1).nullable(),
    locale: z.string().min(2),
    timezone: z.string().min(1),
    navigation_timeout_seconds: positiveNumber,
    readiness_max_seconds: positiveNumber,
    readiness_quiet_ms: positiveInt,
    challenge_wait_seconds: nonNegativeInt,
    scroll_step_wait_ms: nonNegativeInt,
    body_resource_types: z.array(z.string().min(1)),
    recycle_after_jobs: positiveInt,
    recycle_after_minutes: positiveNumber,
    recycle_above_rss_mib: positiveNumber,
  })
  .strict();

export const ExtractionSchema = z
  .object({
    qr_enabled: z.boolean(),
    ocr_enabled: z.boolean(),
    ocr_concurrency: z.literal(1),
    ocr_timeout_seconds: positiveNumber,
    ocr_max_crops_per_attempt: nonNegativeInt,
    ai_enabled: z.literal(false).or(z.boolean()),
  })
  .strict();

export const RetentionSchema = z
  .object({
    classes: z.record(z.string(), z.number().int().positive().nullable()),
    default_class: z.string(),
  })
  .strict()
  .refine((r) => r.default_class in r.classes, { message: 'default_class must be one of classes' });

/**
 * v4 extensions (blueprint v4 §29). Every field has a default so policy files
 * written for schema_version 1 keep validating unchanged. Governance switches
 * whose unsafe value is not implemented are literals: they cannot be enabled.
 */
export const WebSchema = z
  .object({
    session_idle_minutes: positiveInt.max(240).default(30),
    session_absolute_hours: positiveInt.max(24).default(12),
    mfa_required: z.boolean().default(true),
    cookie_secure: z.boolean().default(true),
    hsts: z.boolean().default(false),
    login_attempts_per_minute: positiveInt.max(60).default(5),
    lockout_after_failed_logins: positiveInt.max(50).default(10),
    lockout_minutes: positiveInt.max(1440).default(15),
    api_requests_per_second: positiveInt.max(500).default(20),
    paginated_list_limit_default: positiveInt.max(500).default(50),
    paginated_list_limit_max: positiveInt.max(1000).default(200),
    sse_max_connections: positiveInt.max(500).default(50),
    sse_poll_ms: positiveInt.min(500).max(60_000).default(2000),
    require_case_scope_for_sensitive_search: z.literal(true).default(true),
    require_purpose_for_global_search: z.boolean().default(true),
    intake_max_rows: positiveInt.max(100_000).default(5000),
    intake_max_mib: positiveNumber.max(100).default(10),
    upload_max_mib: positiveNumber.max(200).default(25),
    dashboard_aggregation_cache_seconds: nonNegativeInt.max(3600).default(30),
    show_utc_and_ist: z.literal(true).default(true),
  })
  .strict()
  .prefault({});

export const GovernanceSchema = z
  .object({
    maker_checker_for_external_actions: z.literal(true).default(true),
    external_notice_autosend_enabled: z.literal(false).default(false),
    auto_takedown_enabled: z.literal(false).default(false),
    certificate_autosign: z.literal(false).default(false),
    analyst_review_required: z.literal(true).default(true),
    false_positive_override_requires_new_evidence: z.literal(true).default(true),
    section63_template_source_version: z.string().min(1).default('BSA-2023-Schedule-official'),
    risk_policy_version: z.string().min(1).default('risk-rules-1'),
  })
  .strict()
  .prefault({});

export const MonitoringSchema = z
  .object({
    actioned_target_revisit_enabled: z.boolean().default(true),
    max_auto_revisits_per_target_per_day: positiveInt.max(6).default(2),
    default_interval_hours: positiveNumber.default(24),
    min_interval_hours: positiveNumber.default(6),
    max_rule_duration_days: positiveInt.max(365).default(90),
    revisit_priority: z.number().int().min(-1000).max(1000).default(-10),
    notify_on_resurrection: z.boolean().default(true),
  })
  .strict()
  .prefault({});

export const EnrichmentSchema = z
  .object({
    enabled: z.boolean().default(true),
    dns: z.boolean().default(true),
    tls: z.boolean().default(true),
    rdap: z.boolean().default(true),
    // crt.sh is a third-party service: opt-in only.
    certificate_transparency: z.boolean().default(false),
    cache_hours: positiveNumber.default(24),
    timeout_seconds: positiveNumber.max(60).default(10),
    max_response_kib: positiveInt.max(10_240).default(512),
  })
  .strict()
  .prefault({});

export const PolicySchema = z
  .object({
    schema_version: z.literal(1),
    project: z.literal('cyber-web-collector'),
    profile: CaptureProfileName,
    external_providers_enabled: z.boolean(),
    ai_required_for_collection: z.literal(false),
    limits: LimitsSchema,
    capture: CaptureSchema,
    storage: StorageSchema,
    queue: QueueSchema,
    scope: ScopeSchema,
    bounds: BoundsSchema,
    http: HttpSchema,
    browser: BrowserSchema,
    extraction: ExtractionSchema,
    retention: RetentionSchema,
    web: WebSchema,
    governance: GovernanceSchema,
    monitoring: MonitoringSchema,
    enrichment: EnrichmentSchema,
  })
  .strict()
  .superRefine((p, ctx) => {
    const issue = (path: string[], message: string) => ctx.addIssue({ code: 'custom', path, message });
    const l = p.limits;
    if (l.alternate_browser_slots_max > l.browser_slots_global) {
      issue(['limits', 'alternate_browser_slots_max'], 'cannot exceed browser_slots_global');
    }
    if (l.http_attempts_max + l.browser_attempts_max < 1) {
      issue(['limits'], 'at least one acquisition attempt must be permitted');
    }
    if (l.acquisition_attempts_max > l.http_attempts_max + l.browser_attempts_max) {
      issue(['limits', 'acquisition_attempts_max'], 'exceeds http_attempts_max + browser_attempts_max');
    }
    for (const key of ['primary_browser_seconds', 'alternate_browser_seconds'] as const) {
      if (l.finalisation_reserve_seconds >= l[key]) {
        issue(['limits', 'finalisation_reserve_seconds'], `must be smaller than ${key}`);
      }
      if (l[key] > l.active_acquisition_seconds_max) {
        issue(['limits', key], 'exceeds active_acquisition_seconds_max');
      }
    }
    if (l.http_attempt_seconds > l.active_acquisition_seconds_max) {
      issue(['limits', 'http_attempt_seconds'], 'exceeds active_acquisition_seconds_max');
    }
    if (p.queue.heartbeat_seconds * 3 > p.queue.lease_seconds) {
      issue(['queue', 'lease_seconds'], 'must be at least 3 x heartbeat_seconds so one missed heartbeat does not lose the lease');
    }
    if (p.storage.host_free_gb_resume_above <= p.storage.host_free_gb_pause_below) {
      issue(['storage', 'host_free_gb_resume_above'], 'must be greater than host_free_gb_pause_below (hysteresis)');
    }
    if (p.capture.individual_text_body_mib_max > p.capture.attempt_artifacts_mib_max) {
      issue(['capture', 'individual_text_body_mib_max'], 'exceeds attempt_artifacts_mib_max');
    }
    if (p.bounds.max_requests_per_attempt > p.bounds.max_network_events_per_attempt) {
      issue(['bounds', 'max_requests_per_attempt'], 'exceeds max_network_events_per_attempt');
    }
    if (p.external_providers_enabled) {
      issue(['external_providers_enabled'], 'no external provider adapter is implemented in this release; keep false');
    }
    if (p.web.paginated_list_limit_default > p.web.paginated_list_limit_max) {
      issue(['web', 'paginated_list_limit_default'], 'exceeds paginated_list_limit_max');
    }
    if (p.monitoring.min_interval_hours > p.monitoring.default_interval_hours) {
      issue(['monitoring', 'min_interval_hours'], 'exceeds default_interval_hours');
    }
    if (p.extraction.ai_enabled) {
      issue(['extraction', 'ai_enabled'], 'no AI adapter is configured in this release; keep false');
    }
  });

export type Policy = z.infer<typeof PolicySchema>;

export const DEFAULT_POLICY_PATH = new URL('../../config/policy.default.yaml', import.meta.url);

export function parsePolicy(yamlText: string): Policy {
  const raw: unknown = parseYaml(yamlText);
  const result = PolicySchema.safeParse(raw);
  if (!result.success) {
    const details = result.error.issues.map((i) => `${i.path.join('.') || '<root>'}: ${i.message}`).join('\n  ');
    throw new Error(`Invalid collector policy:\n  ${details}`);
  }
  return result.data;
}

export function loadPolicy(path: string | URL = process.env.COLLECTOR_POLICY_PATH ?? DEFAULT_POLICY_PATH): Policy {
  return parsePolicy(readFileSync(path, 'utf8'));
}

export const MiB = 1024 * 1024;
