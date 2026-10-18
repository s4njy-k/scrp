/** Assembles the analyst API: every route group registered in one place. */
import { ApiApp, type AppDeps } from './server.js';
import { authRoutes } from './routes/auth.js';
import { actionRoutes } from './routes/actions.js';
import { caseRoutes } from './routes/cases.js';
import { evidenceRoutes } from './routes/evidence.js';
import { investigateRoutes } from './routes/investigate.js';
import { jobRoutes } from './routes/jobs.js';
import { monitoringRoutes } from './routes/monitoring.js';
import { opsRoutes } from './routes/ops.js';

export function buildApp(deps: AppDeps): ApiApp {
  const app = new ApiApp(deps);
  const d = { pool: deps.pool, policy: deps.policy, root: deps.root };
  app.register(
    { method: 'GET', path: '/api/v1/health', auth: 'none', handler: async () => {
      await deps.pool.query('SELECT 1');
      return { ok: true, note: 'API liveness only' };
    } },
    ...authRoutes(d),
    ...caseRoutes(d),
    ...jobRoutes(d),
    ...evidenceRoutes(d),
    ...investigateRoutes(d),
    ...actionRoutes(d),
    ...monitoringRoutes(d),
    ...opsRoutes(d),
  );
  return app;
}
