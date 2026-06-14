# Contributing to security-audit

Thanks for considering a contribution. This document covers the development setup, what we expect in pull requests, and how to ship a release.

## Development setup

```bash
git clone https://github.com/dmytrosorokame/security-audit
cd security-audit
pnpm install --ignore-workspace          # node ≥ 20

# one-shot sanity check
pnpm test                                # lint + unit + smoke
```

You will need at least one LLM API key in your environment to run real scans:

```bash
export OPENAI_API_KEY=sk-...             # or ANTHROPIC_API_KEY
```

For development, **never commit a key to git**. The `.gitignore` already excludes `.env` and similar.

## Project layout

```
scripts/             — runtime code (orchestrator, providers, formatters, validators)
scripts/__tests__/   — Vitest unit tests (mirrors scripts/ structure)
prompts/             — LLM system prompt + few-shot examples
references/          — OWASP catalog (LLM grounding) + report schema
benchmark/           — example diffs with expected ground truth, plus the runner
examples/            — same diffs as benchmark inputs (referenced by README)
docs/adr/            — Architecture Decision Records (one decision per file)
.github/workflows/   — CI (test.yml = lint + unit + smoke; benchmark.yml = real-API runs)
```

## Running the test suite

```bash
pnpm test                  # lint + unit + smoke (the gate CI uses)
pnpm test:unit             # unit tests only (Vitest)
pnpm test:watch            # Vitest in watch mode
pnpm test:coverage         # unit + coverage HTML report at coverage/index.html
pnpm lint                  # ESLint, zero warnings tolerated
pnpm lint:fix              # auto-fix what ESLint can
```

A live benchmark run (requires an API key) writes `benchmark/results.md`:

```bash
node benchmark/run_benchmark.mjs --seeds=3 --provider=openai --model=cheap
```

Use `--dry-run --no-write` for a harness sanity check that costs nothing.

## What we expect in a PR

1. **Unit tests for new logic.** If you touch a `.mjs` file, add or update a test in `scripts/__tests__/`. Coverage thresholds (75 % lines / 70 % branches) are enforced in CI.
2. **Lint clean.** `pnpm lint` exits 0. No warnings.
3. **One topic per PR.** Mixing a refactor with a feature makes the diff impossible to review and breaks `git bisect`.
4. **If you add a rule to the catalog (`references/owasp-rules.md`)**: also update `owasp-mapping.md` (cross-reference) and consider adding a `benchmark/expected/*.json` ground-truth case. The `catalog_drift.test.mjs` unit test will fail CI if the three files disagree.
5. **If you touch the prompt (`prompts/system.md` or `few_shot.md`)**: run the live benchmark on your branch and attach the resulting `benchmark/results.md` to the PR. Prompt changes can affect every finding type.
6. **For architectural decisions**: add an ADR under `docs/adr/`. Use the next sequential number; do not delete superseded ADRs (set their status to "Superseded by ADR-NNN").
7. **Security-sensitive changes**: discuss in a draft security advisory first (see `SECURITY.md`).

## Commit message style

Short imperative subject (≤ 72 chars), optional body explaining *why* (not *what*).

```
provider: drop AbortError in the 5xx-retry classifier

Anthropic SDK surfaces AbortController-triggered aborts as AbortError
with no status code, which the old shouldRetry predicate treated as a
non-status error and retried 3 times.  Now we short-circuit on
err.name === 'AbortError' before checking err.status.
```

## Release process

1. All PRs merge into `main` via squash-merge.
2. When ready to cut a release:
   1. Bump `version` in `package.json` and `.claude-plugin/plugin.json`.
   2. Commit: `release: vX.Y.Z`.
   3. Tag: `git tag -s vX.Y.Z -m 'vX.Y.Z'` (signed if possible).
   4. Push: `git push --follow-tags`.
3. The `release.yml` workflow builds and publishes the GitHub release.
4. Users pin the tag in their workflows: `uses: dmytrosorokame/security-audit@vX.Y.Z`.

## Reporting security issues

See [`SECURITY.md`](./SECURITY.md). Do **not** file public issues for vulnerabilities.

## Code of conduct

Be kind, assume good intent, prefer specifics over generalities. The project is small enough that we trust people; we will adopt a formal CoC if it ever becomes necessary.
