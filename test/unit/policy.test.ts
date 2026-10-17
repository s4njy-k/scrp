import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { parse, stringify } from 'yaml';
import { DEFAULT_POLICY_PATH, loadPolicy, parsePolicy } from '../../src/config/policy.js';

const base = () => parse(readFileSync(DEFAULT_POLICY_PATH, 'utf8')) as Record<string, any>;

describe('collector policy schema', () => {
  it('loads the shipped default with the blueprint values', () => {
    const p = loadPolicy();
    expect(p.limits.browser_slots_global).toBe(2);
    expect(p.limits.acquisition_attempts_max).toBe(4);
    expect(p.limits.active_acquisition_seconds_max).toBe(180);
    expect(p.capture.viewport).toEqual({ width: 1440, height: 1000 });
    expect(p.capture.block_ads).toBe(false);
    expect(p.storage.delete_case_hold_artifacts).toBe(false);
    expect(p.queue).toEqual({ heartbeat_seconds: 10, lease_seconds: 120, reclaim_expired_leases: true });
    expect(p.external_providers_enabled).toBe(false);
  });

  it('rejects unknown keys (no silent pass-through to libraries)', () => {
    const y = base();
    y.limits.max_retries_inside_library = 5;
    expect(() => parsePolicy(stringify(y))).toThrow(/Unrecognized key|unrecognized/i);
  });

  it('rejects attempt caps that exceed per-phase sums', () => {
    const y = base();
    y.limits.acquisition_attempts_max = 9;
    expect(() => parsePolicy(stringify(y))).toThrow(/acquisition_attempts_max/);
  });

  it('rejects finalisation reserve not smaller than browser caps', () => {
    const y = base();
    y.limits.finalisation_reserve_seconds = 60;
    expect(() => parsePolicy(stringify(y))).toThrow(/finalisation_reserve_seconds/);
  });

  it('requires disk resume threshold above pause threshold', () => {
    const y = base();
    y.storage.host_free_gb_resume_above = 20;
    expect(() => parsePolicy(stringify(y))).toThrow(/hysteresis/);
  });

  it('refuses deleting case-hold artifacts and enabling unimplemented providers', () => {
    const y = base();
    y.storage.delete_case_hold_artifacts = true;
    expect(() => parsePolicy(stringify(y))).toThrow();
    const z = base();
    z.external_providers_enabled = true;
    expect(() => parsePolicy(stringify(z))).toThrow(/external provider/);
  });

  it('requires lease >= 3 heartbeats', () => {
    const y = base();
    y.queue.lease_seconds = 20;
    expect(() => parsePolicy(stringify(y))).toThrow(/lease_seconds/);
  });
});
