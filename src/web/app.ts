/** Assembles the analyst API: every route group registered in one place. */
import { ApiApp, type AppDeps } from './server.js';
import { authRoutes } from './routes/auth.js';
import { caseRoutes } from './routes/cases.js';

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
  );
  return app;
}
