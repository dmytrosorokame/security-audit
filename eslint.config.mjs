// Minimal flat-config ESLint for plain Node ESM. Keeps zero new heavy deps —
// only `@eslint/js` is needed; install with: pnpm add -D eslint @eslint/js
import js from '@eslint/js';

export default [
  js.configs.recommended,
  {
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: {
        process: 'readonly',
        console: 'readonly',
        Buffer: 'readonly',
        setTimeout: 'readonly',
        clearTimeout: 'readonly',
        setInterval: 'readonly',
        clearInterval: 'readonly',
        AbortController: 'readonly',
        URL: 'readonly',
      },
    },
    rules: {
      // Project conventions
      'prefer-const': 'error',
      'no-var': 'error',
      'eqeqeq': ['error', 'smart'],
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],

      // Loosen what's noisy in a CLI codebase:
      'no-console': 'off',          // CLI tool, console is the UI
      'no-empty': ['error', { allowEmptyCatch: true }],
      'no-prototype-builtins': 'off',
    },
  },
  {
    files: ['scripts/__tests__/**/*.test.mjs'],
    rules: {
      // Vitest globals are imported explicitly, no need for env: vitest/jest
      'no-unused-expressions': 'off',
    },
  },
  {
    ignores: [
      'node_modules/**',
      'coverage/**',
      '.security-audit-cache/**',
      'benchmark/diff_corpus/**',
    ],
  },
];
