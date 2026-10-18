/**
 * Tamper-evident chain of custody (blueprint v4 §24.1, §24.4; checklist §1).
 *
 * Audit events are inserted by many concurrent transactions; ordering them
 * into a hash chain inside those transactions would serialise every lease and
 * commit behind one lock. Instead a single sealer (advisory-locked) chains
 * committed, unsealed rows in id order a few seconds after they commit. A row
 * that commits late simply joins the chain in a later batch: the chain order
 * is the sealing order, and chain positions are contiguous.
 *
 * Integrity claims are deliberately limited: a host administrator can rewrite
 * the database and recompute the chain. Signed checkpoints copied to storage
 * outside the collector's administrative control are what make later
 * rewriting detectable. This is not WORM storage.
 */
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { audit, withTransaction, type Pool, type Queryable } from '../db/pool.js';
import { canonicalJson } from './canonical.js';

export const GENESIS_HASH = '0'.repeat(64);
const SEALER_LOCK = 727274010;

interface AuditRow {
  id: number;
  at_text: string;
  actor: string;
  actor_kind: string;
  event_type: string;
  job_id: number | null;
  attempt_id: string | null;
  details: Record<string, unknown>;
  case_ref: string | null;
  object_type: string | null;
  object_id: string | null;
  outcome: string | null;
  request_id: string | null;
}

const ROW_COLUMNS = `id, to_char(at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS at_text, actor, actor_kind, event_type,
  job_id, attempt_id::text AS attempt_id, details, case_ref, object_type, object_id, outcome, request_id`;

export function payloadFor(r: AuditRow): string {
  return canonicalJson({
    v: 1, id: Number(r.id), at: r.at_text, actor: r.actor, actor_kind: r.actor_kind, event_type: r.event_type,
    job_id: r.job_id === null ? null : Number(r.job_id), attempt_id: r.attempt_id, details: r.details ?? {},
    case_ref: r.case_ref, object_type: r.object_type, object_id: r.object_id, outcome: r.outcome, request_id: r.request_id,
  });
}

export function chainHash(prevHash: string, chainPos: number, payload: string): string {
  return createHash('sha256').update(`${prevHash}\n${chainPos}\n${payload}`, 'utf8').digest('hex');
}

/** Seal up to `limit` committed, unsealed events. Returns the number sealed (0 if another sealer holds the lock). */
export async function sealPending(pool: Pool, limit = 1000): Promise<number> {
  return withTransaction(pool, async (client) => {
    const lock = await client.query<{ ok: boolean }>('SELECT pg_try_advisory_xact_lock($1) AS ok', [SEALER_LOCK]);
    if (!lock.rows[0]?.ok) return 0;
    const head = await client.query<{ chain_pos: number; event_hash: string }>(
      'SELECT chain_pos, event_hash FROM audit_events WHERE chain_pos IS NOT NULL ORDER BY chain_pos DESC LIMIT 1',
    );
    let prev = head.rows[0]?.event_hash ?? GENESIS_HASH;
    let pos = Number(head.rows[0]?.chain_pos ?? 0);
    const { rows } = await client.query<AuditRow>(
      `SELECT ${ROW_COLUMNS} FROM audit_events WHERE chain_pos IS NULL ORDER BY id LIMIT $1 FOR UPDATE SKIP LOCKED`,
      [limit],
    );
    for (const r of rows) {
      pos += 1;
      const payload = payloadFor(r);
      const hash = chainHash(prev, pos, payload);
      await client.query(
        'UPDATE audit_events SET chain_pos = $2, prev_hash = $3, event_hash = $4, sealed_payload = $5, sealed_at = now() WHERE id = $1',
        [r.id, pos, prev, hash, payload],
      );
      prev = hash;
    }
    return rows.length;
  });
}

export interface ChainVerification {
  ok: boolean;
  sealed_events: number;
  unsealed_events: number;
  oldest_unsealed_seconds: number | null;
  head: { chain_pos: number; event_hash: string } | null;
  problems: string[];
  checkpoint?: { chain_pos: number; event_hash: string; matches: boolean; signature_valid: boolean | null };
}

export interface CheckpointFile {
  format: 'cyber-web-collector/custody-checkpoint@1';
  chain_pos: number;
  event_hash: string;
  created_at: string;
  signature_alg: 'ed25519' | null;
  signature: string | null;
  public_key_pem: string | null;
  public_key_sha256: string | null;
  note: string;
}

function checkpointMessage(c: Pick<CheckpointFile, 'chain_pos' | 'event_hash' | 'created_at'>): Buffer {
  return Buffer.from(canonicalJson({ chain_pos: c.chain_pos, event_hash: c.event_hash, created_at: c.created_at }), 'utf8');
}

/**
 * Recompute the whole chain from stored payloads, check positions are
 * contiguous, and check each payload still matches its row's columns (which
 * catches column edits made with the append-only trigger disabled).
 */
export async function verifyChain(db: Queryable, opts: { checkpoint?: CheckpointFile; batch?: number } = {}): Promise<ChainVerification> {
  const problems: string[] = [];
  const batch = opts.batch ?? 2000;
  let prev = GENESIS_HASH;
  let expectedPos = 1;
  let sealed = 0;
  let head: ChainVerification['head'] = null;
  let checkpointHash: string | null = null;
  for (;;) {
    const { rows } = await db.query<AuditRow & { chain_pos: number; prev_hash: string; event_hash: string; sealed_payload: string }>(
      `SELECT ${ROW_COLUMNS}, chain_pos, prev_hash, event_hash, sealed_payload FROM audit_events
        WHERE chain_pos >= $1 ORDER BY chain_pos LIMIT $2`,
      [expectedPos, batch],
    );
    if (rows.length === 0) break;
    for (const r of rows) {
      const pos = Number(r.chain_pos);
      if (pos !== expectedPos) {
        problems.push(`chain gap: expected position ${expectedPos}, found ${pos}`);
        expectedPos = pos;
      }
      if (r.prev_hash !== prev) problems.push(`position ${pos}: prev_hash does not link to position ${pos - 1}`);
      const recomputed = chainHash(r.prev_hash, pos, r.sealed_payload);
      if (recomputed !== r.event_hash) problems.push(`position ${pos}: event_hash does not match its payload`);
      if (payloadFor(r) !== r.sealed_payload) problems.push(`position ${pos} (event ${r.id}): row columns differ from the sealed payload`);
      if (opts.checkpoint && pos === opts.checkpoint.chain_pos) checkpointHash = r.event_hash;
      prev = r.event_hash;
      head = { chain_pos: pos, event_hash: r.event_hash };
      sealed += 1;
      expectedPos = pos + 1;
      if (problems.length > 200) break;
    }
    if (problems.length > 200 || rows.length < batch) break;
  }
  const uns = await db.query<{ n: number; oldest: number | null }>(
    `SELECT count(*)::int AS n, EXTRACT(EPOCH FROM now() - min(at))::float8 AS oldest FROM audit_events WHERE chain_pos IS NULL`,
  );
  const result: ChainVerification = {
    ok: problems.length === 0,
    sealed_events: sealed,
    unsealed_events: uns.rows[0]?.n ?? 0,
    oldest_unsealed_seconds: uns.rows[0]?.oldest === null || uns.rows[0]?.oldest === undefined ? null : Math.round(Number(uns.rows[0].oldest)),
    head,
    problems,
  };
  if (opts.checkpoint) {
    const cp = opts.checkpoint;
    let signatureValid: boolean | null = null;
    if (cp.signature && cp.public_key_pem) {
      try {
        signatureValid = verify(null, checkpointMessage(cp), createPublicKey(cp.public_key_pem), Buffer.from(cp.signature, 'base64'));
      } catch {
        signatureValid = false;
      }
    }
    const matches = checkpointHash === cp.event_hash;
    if (!matches) problems.push(`checkpoint at position ${cp.chain_pos} does not match the current chain (history rewritten or truncated)`);
    if (signatureValid === false) problems.push('checkpoint signature is invalid');
    result.checkpoint = { chain_pos: cp.chain_pos, event_hash: cp.event_hash, matches, signature_valid: signatureValid };
    result.ok = problems.length === 0;
  }
  return result;
}

export function generateSigningKey(): { privatePem: string; publicPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

async function loadSigningKey(path: string | undefined): Promise<KeyObject | null> {
  if (!path) return null;
  return createPrivateKey(await readFile(path, 'utf8'));
}

/**
 * Seal outstanding events, then export a (signed, when a key is configured)
 * checkpoint of the chain head under ARTIFACT_ROOT/exports/custody-checkpoints/.
 * Copy that file to storage outside the collector's administrative control.
 */
export async function createCheckpoint(pool: Pool, root: string, actor: string, opts: { signingKeyPath?: string; note?: string } = {}): Promise<CheckpointFile & { path: string; sha256: string }> {
  while ((await sealPending(pool)) > 0) { /* drain */ }
  const head = (await pool.query<{ chain_pos: number; event_hash: string }>(
    'SELECT chain_pos, event_hash FROM audit_events WHERE chain_pos IS NOT NULL ORDER BY chain_pos DESC LIMIT 1',
  )).rows[0];
  if (!head) throw new Error('custody chain is empty; nothing to checkpoint');
  const key = await loadSigningKey(opts.signingKeyPath ?? process.env.CUSTODY_SIGNING_KEY_FILE);
  const createdAt = new Date().toISOString();
  const base = { chain_pos: Number(head.chain_pos), event_hash: head.event_hash, created_at: createdAt };
  let publicPem: string | null = null;
  let signature: string | null = null;
  if (key) {
    signature = sign(null, checkpointMessage(base), key).toString('base64');
    publicPem = createPublicKey(key).export({ type: 'spki', format: 'pem' }).toString();
  }
  const file: CheckpointFile = {
    format: 'cyber-web-collector/custody-checkpoint@1',
    ...base,
    signature_alg: key ? 'ed25519' : null,
    signature,
    public_key_pem: publicPem,
    public_key_sha256: publicPem ? createHash('sha256').update(publicPem).digest('hex') : null,
    note: opts.note ?? (key ? 'Signed custody chain head.' : 'UNSIGNED: no CUSTODY_SIGNING_KEY_FILE configured; integrity relies on where this file is stored.'),
  };
  const text = `${JSON.stringify(file, null, 2)}\n`;
  const rel = `exports/custody-checkpoints/${createdAt.replace(/[:.]/g, '-')}-pos${base.chain_pos}.json`;
  await mkdir(join(root, 'exports', 'custody-checkpoints'), { recursive: true });
  await writeFile(join(root, rel), text, { mode: 0o640, flag: 'wx' });
  const sha = createHash('sha256').update(text).digest('hex');
  await pool.query(
    `INSERT INTO custody_checkpoints (chain_pos, event_hash, created_by, signature_alg, signature, public_key_sha256, exported_path, exported_sha256, note)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [base.chain_pos, base.event_hash, actor, file.signature_alg, signature, file.public_key_sha256, rel, sha, file.note],
  );
  await audit(pool, actor, 'custody_checkpoint_created', { chain_pos: base.chain_pos, event_hash: base.event_hash, signed: Boolean(key), path: rel, sha256: sha },
    { actorKind: 'operator', objectType: 'custody_chain', objectId: base.chain_pos });
  return { ...file, path: rel, sha256: sha };
}
