# OSS pilot corpus

Fourth and most external corpus. Contains diffs scraped from **real, recently-merged PRs** in third-party Node/TypeScript open-source projects. Unlike the three other corpora — where the author wrote every diff — these diffs are written by **OSS maintainers and contributors who have never heard of this project**.

This is the closest we currently get to the unbiased, real-world test set described as Stage 2 in [`docs/INDEPENDENT_VALIDATION.md`](../../docs/INDEPENDENT_VALIDATION.md).

## Status

The corpus is **populated on demand**. Diffs are not committed by default — they are fetched and labelled per evaluation run. See [`docs/OSS_AUDIT_PLAYBOOK.md`](../../docs/OSS_AUDIT_PLAYBOOK.md) for the operator workflow.

When unpopulated, this directory contains:

- `targets.json` — list of repositories to sample from + selection criteria
- `README.md` — this file

After a collection run (`node scripts/collect_oss_diffs.mjs`), it contains:

- `diffs/<repo>__pr<N>.diff` — raw unified diffs fetched via `gh pr diff`
- `expected/<repo>__pr<N>.json` — initially `expected: []` + `expect_zero_findings: null`; **operator hand-labels these** before running the benchmark

## Why this corpus is the strongest external-validity argument we can make right now

| Source | Catalog author wrote the code? | Catalog author wrote the labels? | External validity |
|---|---|---|---|
| `benchmark/expected/` | Yes (curated) | Yes | Lowest |
| `benchmark/independent_corpus/` | Yes (CVE-pattern reproductions) | Yes | Reduced |
| `benchmark/complex_corpus/` | Yes (multi-file synthesis) | Yes | Reduced |
| `benchmark/oss_pilot/` (this) | **No** (real OSS contributors) | Yes (operator labels them) | Strongest available without a second annotator |

Adding a second annotator (Cohen's κ) would push this corpus toward "Stage 2 complete" status. The collection script makes that drop-in: another reviewer labels a held-out 20% sample and we compute κ from the disagreement.

## Methodology constraints (honest version)

1. **Cherry-picking risk.** `targets.json` is hand-curated. We picked libraries with security-relevant code, which biases the corpus toward findable issues. We do **not** filter PRs by content — we take recent merged PRs regardless of whether they touch security.
2. **Label bias.** The operator (initially the author) still labels each PR's ground truth. This is a known weakness — fixed by a second annotator, planned for Stage 2 completion.
3. **PR size bias.** The collection script applies `--max-files=5` and `--max-lines=200` by default. Larger refactors are skipped. Real-world security issues sometimes land in 5000-line PRs; those are out of this pilot.
4. **Sample size.** Default collection runs scrape 3 PRs/repo × 10 repos = up to 30 PRs. Not all will pass filters; expect 10–20 viable diffs per collection run.

## How to use

```bash
# 1. Ensure `gh` is authenticated
gh auth status

# 2. Collect (about 1 min with default settings)
node scripts/collect_oss_diffs.mjs --per-repo=3

# 3. Hand-label every benchmark/oss_pilot/expected/*.json:
#    set `expected: [...]` and `expect_zero_findings: true|false`
#    set `unlabeled: false` once labelled
#    (see docs/OSS_AUDIT_PLAYBOOK.md for label-writing rubric)

# 4. Run the benchmark
node benchmark/run_benchmark.mjs \
  --corpus=benchmark/oss_pilot \
  --provider=openai --model=cheap \
  --seeds=3 \
  --cache-dir=.security-audit-cache \
  --max-cost=2.00       # safety budget for the unknown-sized corpus
```

## Reporting

When `oss_pilot` is included in a run, `benchmark/results.md` gains a fourth corpus block and the generalisation-gap section reports both:

- `independent − oss_pilot` (catalog vs. real OSS) — primary external-validity metric
- `complex − oss_pilot` (cross-file ≈ realistic) — degradation under realistic refactor noise

A small positive gap (independent F1 > oss_pilot F1 by 0.05–0.15) is the **expected and healthy** result. It means the catalog works on documented patterns but loses some signal on the long tail of real-world diff styles — which is the truth we want to be able to defend.

## Ethics & licensing

- Diffs fetched are public open-source code. They remain under their upstream license.
- We do **not** redistribute the diffs in the main `security-audit` repository. Operators fetch them per run; the local cache is `.gitignore`'d.
- We **never** report a finding about a vulnerability in a target repo without first reporting it privately to the upstream maintainers via their security-disclosure channel.
