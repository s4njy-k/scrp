# Release, upgrade and rollback

## Principles

* Keep a tested known-good release. Images are tagged with `APP_VERSION` (`cyber-web-collector/app:<version>`,
  `.../browser-engine:<version>`).
* Driver (`playwright-core` in `package-lock.json`) and engine (`docker/browser-engine/package-lock.json`
  and the Playwright base image tag) **must have the same version**. Upgrade them together.
* Migrations only move forward and are checksummed. Every new migration must be backward
  compatible with the previous release: add columns, never drop or rename them in the same
  release. That way the previous image can still run against the newer schema.
* **Never** use `docker compose down -v`, and never delete `$COLLECTOR_DATA_DIR/postgres` or
  `artifacts`, as an upgrade or rollback step.

## Upgrade procedure

1. Update the dependencies on a branch. Re-resolve with a review buffer
   (`npm install --save-exact --before=<date two weeks ago> ...`). Bump the Playwright base
   image digest and `docker/browser-engine/package.json` together.
2. `npm ci && npm run typecheck && npm test`: unit tests plus every fixture
   (static, hydration, fragment route, lazy, slow, challenge, frames, popups, service worker,
   WebSocket, QR, gateway refusals).
3. Run a backup (`scripts/backup.sh`).
4. Build the new images with a new `APP_VERSION`, keeping the old images.
5. `$DC up -d` with the new version. The coordinator applies new migrations at start-up.
6. Run the canaries (runbook §6) and watch `cli status` for one hour.

## Rollback procedure

1. Set `APP_VERSION` back to the known-good version in `.env`.
2. `$DC up -d`. Containers are recreated from the old images. Data directories and volumes are untouched.
3. In-flight leases from the new version expire and are reclaimed. Their attempts are recorded
   as interrupted.
4. If a migration from the new release is incompatible (it should not be, under the rule
   above), restore the pre-upgrade dump into a scratch database first. Plan the fix forward;
   do not drop data.
5. Record the rollback (version, time, reason) in the deployment change log in
   `docs/deployment-readiness.md`.
