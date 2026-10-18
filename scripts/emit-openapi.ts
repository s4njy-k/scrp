/** Writes docs/openapi.json from the live route table plus src/web/apiDocs.ts. */
import { readFileSync, writeFileSync } from 'node:fs';
import { loadPolicy } from '../src/config/policy.js';
import { buildApp } from '../src/web/app.js';
import { buildOpenApi } from '../src/web/apiDocs.js';
import type { Pool } from '../src/db/pool.js';

const app = buildApp({ pool: {} as unknown as Pool, policy: loadPolicy(), root: '/nonexistent' });
const version = (JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }).version;
writeFileSync(new URL('../docs/openapi.json', import.meta.url), `${JSON.stringify(buildOpenApi(app.routeTable(), version), null, 2)}\n`);
console.log('wrote docs/openapi.json');
