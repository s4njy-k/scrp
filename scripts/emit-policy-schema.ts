/** Writes config/policy.schema.json from the zod schema (single source of truth). */
import { writeFileSync } from 'node:fs';
import { z } from 'zod';
import { PolicySchema } from '../src/config/policy.js';

const schema = z.toJSONSchema(PolicySchema, { target: 'draft-2020-12', unrepresentable: 'any' });
const out = { $id: 'https://cyber-web-collector.invalid/policy.schema.json', title: 'cyber-web-collector policy (schema_version 1)', ...schema };
writeFileSync(new URL('../config/policy.schema.json', import.meta.url), `${JSON.stringify(out, null, 2)}\n`);
console.log('wrote config/policy.schema.json');
