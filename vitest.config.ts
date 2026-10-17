import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    testTimeout: 60_000,
    hookTimeout: 60_000,
    // Integration suites share one PostgreSQL cluster and fixed fixture ports.
    fileParallelism: false,
    env: { LOG_LEVEL: process.env.LOG_LEVEL ?? 'warn', COLLECTOR_ALLOW_DIRECT_EGRESS: 'true' },
  },
});
