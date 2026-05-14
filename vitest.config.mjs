import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['scripts/__tests__/**/*.test.mjs'],
    environment: 'node',
    globals: false,
    reporters: ['default'],
    coverage: {
      provider: 'v8',
      include: ['scripts/**/*.mjs'],
      exclude: [
        'scripts/__tests__/**',
        'scripts/scan_diff.mjs',           // CLI orchestrator — hard to unit-test
        'scripts/providers/anthropic.mjs', // SDK wrapper — needs SDK mocks
        'scripts/providers/openai.mjs',    // SDK wrapper — needs SDK mocks
      ],
      reporter: ['text', 'lcov', 'html'],
      thresholds: {
        // Calibrated to current coverage with ~5% headroom for non-trivial
        // refactors. Excluded files (scan_diff, provider SDKs) need integration
        // tests with API mocks to cover the request/response path — out of scope
        // for unit-test budget.
        lines: 75,
        functions: 70,
        statements: 75,
        branches: 70,
      },
    },
  },
});
