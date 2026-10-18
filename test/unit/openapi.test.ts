/** The committed OpenAPI document covers every live route exactly and is current. */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { loadPolicy } from '../../src/config/policy.js';
import type { Pool } from '../../src/db/pool.js';
import { buildApp } from '../../src/web/app.js';
import { buildOpenApi, ROUTE_DOCS } from '../../src/web/apiDocs.js';

describe('OpenAPI document', () => {
  const routes = buildApp({ pool: {} as unknown as Pool, policy: loadPolicy(), root: '/nonexistent' }).routeTable();
  const version = (JSON.parse(readFileSync('package.json', 'utf8')) as { version: string }).version;

  it('documents every route and nothing else', () => {
    const live = routes.map((r) => `${r.method} ${r.path}`).sort();
    expect(Object.keys(ROUTE_DOCS).sort()).toEqual(live);
  });

  it('records the enforced auth level, roles and CSRF of each operation', () => {
    const doc = buildOpenApi(routes, version) as { paths: Record<string, Record<string, { 'x-auth-level': string; 'x-roles': string[]; operationId: string; parameters?: { $ref?: string }[]; security: unknown[] }>> };
    const ids = new Set<string>();
    for (const r of routes) {
      const op = doc.paths[r.path.replace(/:([A-Za-z]+)/g, '{$1}')]![r.method.toLowerCase()]!;
      expect(op['x-auth-level']).toBe(r.auth);
      expect(op['x-roles']).toEqual(r.roles);
      expect(op.security.length).toBe(r.auth === 'none' ? 0 : 1);
      expect(Boolean(op.parameters?.some((p) => p.$ref === '#/components/parameters/Csrf'))).toBe(r.csrf);
      expect(ids.has(op.operationId), op.operationId).toBe(false);
      ids.add(op.operationId);
    }
  });

  it('docs/openapi.json is up to date (run npm run openapi)', () => {
    const committed = JSON.parse(readFileSync('docs/openapi.json', 'utf8'));
    expect(committed).toEqual(JSON.parse(JSON.stringify(buildOpenApi(routes, version))));
  });
});
