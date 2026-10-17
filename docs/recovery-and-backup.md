# Backup, restore and recovery (blueprint §15)

## What is backed up

| Item | How | Why |
|---|---|---|
| PostgreSQL ledger | `pg_dump -Fc` (custom format, verified with `pg_restore --list`) | Jobs, attempts, artifact records, identifiers, audit log |
| All manifests | `manifests.tar.gz` of `captures/`, `incomplete/` and `derived/` `manifest.json` files | Lets artifacts be reconciled against hashes even if the ledger is lost |
| Original captures (optional) | `--with-originals`: rsync of `captures/` and `incomplete/`, never deleting at the destination | Evidence preservation |
| Checksums | `SHA256SUMS` over the backup set | Backup integrity |

```bash
BACKUP_DEST=/mnt/independent-storage scripts/backup.sh --context rootless --with-originals
docker --context rootless compose -p cyber-web-collector exec coordinator node dist/cli.js backup status
```

The script records the result in `system_state.backup`: last success time, destination, and
whether the destination is on **independent storage** (a different device from
`COLLECTOR_DATA_DIR`). `status` reports the backup age and `single_disk_risk`.

> A backup on the same disk is not disaster recovery, and recovery on a single host is not high
> availability. If no independent destination exists, the remaining single-disk risk must be
> reported, as `docs/deployment-readiness.md` currently does.

Suggested schedule: run the ledger and manifest backup daily (cron or a systemd user timer, under
the host's existing service policy). Mirror originals daily, or more often for held cases.

## Restore verification

```bash
scripts/restore-verify.sh /mnt/independent-storage/20261017T020000Z --context rootless --sample 25
```

The script:

1. checks the backup's `SHA256SUMS`;
2. restores the dump into a scratch database `collector_restore_check`, leaving the live
   database untouched;
3. compares row counts of `jobs`, `attempts`, `artifacts`, `identifiers` and `audit_events`;
4. re-hashes a random sample of committed attempt directories against their manifests and the
   ledger (`cli verify`);
5. drops the scratch database.

Run it after the first backup and then at least monthly. Record each result (date, sample size,
mismatches) in `docs/deployment-readiness.md`.

## Recovery objectives (to be confirmed on the VM)

| Objective | Proposed value | Depends on |
|---|---|---|
| RPO (ledger) | ≤ 24 h | Daily dump. Shorter needs WAL archiving to independent storage (`archive_mode=on`, not enabled by default) |
| RPO (originals) | ≤ 24 h, or immediate for held cases | `--with-originals` frequency |
| RTO | ~1 h | Image rebuild or pull, dump restore, reconciliation |

## Full restore procedure (disaster)

1. Provision the host and run `scripts/preflight.sh`.
2. Restore `$COLLECTOR_DATA_DIR/artifacts` from the originals mirror.
3. Start only PostgreSQL: `$DC up -d postgres`, then
   `$DC exec -T postgres pg_restore -U postgres -d collector --clean --if-exists < collector.dump`.
4. Start the coordinator. Start-up reconciliation records orphan directories, salvages tmp
   directories and reclaims stale leases.
5. Run `scripts/restore-verify.sh` against the same backup and `cli status` (`integrity`).

Restored jobs that were mid-lease are reclaimed and visited again (at-least-once semantics).
Result commits are idempotent per attempt id.
