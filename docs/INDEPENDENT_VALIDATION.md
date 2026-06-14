# Independent validation

This document collects the validation roadmap and operational guidance for the
project's multi-corpus benchmark. It exists so the explanation lives in one
place instead of being repeated across `benchmark/{expected, independent_corpus,
complex_corpus, oss_pilot}/README.md`.

## Stage layout

Four corpora with deliberately different bias profiles:

| Corpus | Bias profile | What it validates |
|---|---|---|
| `benchmark/expected/` (smoke) | Author-curated; overlaps with few-shot examples | Regression detection only |
| `benchmark/independent_corpus/` | Author-written, derived from public CVE families | Generalisation to known pattern families |
| `benchmark/complex_corpus/` | Author-written, multi-file / compositional | Reasoning across hunks and configuration-as-relaxation |
| `benchmark/oss_pilot/` | Real merged PRs from public OSS, provisional-TN labels | Real-world false-positive rate |

A healthy result has F1 monotonically degrade smoke → independent → complex → oss_pilot. The **gap between corpora** is the honest indicator of generalisability; any single-corpus F1 in isolation is suspect. Both regimes (strict / loose) are reported side by side in `benchmark/results.md`.

## Threats to validity

These limit how strongly the benchmark numbers can be cited:

1. **Sample size.** n = 7..19 per corpus. The runner attaches a 95 % Wilson score interval on precision and recall and a non-parametric bootstrap interval on F1 (`wilsonCI()` / `bootstrapF1CI()` in `benchmark/run_benchmark.mjs`). Point estimates without their CI should be read as indicative, not conclusive. For small n the lower bound is often well below the point estimate (e.g. precision 1.0 at n = 11 has Wilson lower bound ≈ 0.72).
2. **Single annotator.** All ground truth labels were written by one person. Cohen's κ with a second annotator on a 20 % random sample is the open work item; until that exists, all corpora carry single-author bias.
3. **Few-shot ↔ corpus overlap.** Several examples in `prompts/few_shot.md` overlap structurally with cases in smoke, independent, and complex. The overlap table at the top of `prompts/few_shot.md` lists each pair. The genuinely held-out subset is smaller than the headline n.
4. **`oss_pilot` is provisional-TN.** All 19 PRs presume no security regression unless an annotator marks otherwise. The observed FP rate is an upper bound; the true rate could be lower if any flagged finding turns out to be a real regression.
5. **Temporal validity.** Any benchmark run is a snapshot at one moment in OWASP / catalog / model history. Periodic re-runs against the same corpora are needed to detect drift; the `catalog_drift.test.mjs` CI test catches the rule-id half of this automatically.

## Stage 2 roadmap — raw CVE-fix corpus

The next external test set is the **actual git diff** of CVE-fix commits, not author reproductions of their patterns. Plan:

- **Source.** GitHub Advisory Database (GHSA), filtered to npm ecosystem, severity high / critical, 2022-01-01 onwards, single-commit fix touching ≤ 5 files / ≤ 200 lines. Estimated target: n ≈ 50.
- **Labels frozen before first LLM run.** Two annotators on a 20 % random sample; Cohen's κ reported.
- **Tooling.** `scripts/collect_cve_corpus.mjs` and `scripts/label_cve_corpus.mjs` — both deliverables of stage 2, not yet implemented.

For the OSS-PR pilot workflow (collection, hand-labelling, suggested time budget), see [`docs/OSS_AUDIT_PLAYBOOK.md`](./OSS_AUDIT_PLAYBOOK.md).

## Operational notes

```bash
# Multi-seed run with cache auto-disabled (cache is keyed on diff content,
# not seed index, so a hot cache would zero out the variance we want to measure)
node benchmark/run_benchmark.mjs --seeds=5 --provider=openai --model=cheap

# Single-corpus run
node benchmark/run_benchmark.mjs --corpus=benchmark/independent_corpus --seeds=3

# CI gate thresholds (current defaults in benchmark.yml)
--min-f1-strict=0.6 --min-f1-loose=0.65
```

Detailed methodology for the Wilson and bootstrap CIs is in the JSDoc on `wilsonCI()` and `bootstrapF1CI()` in `benchmark/run_benchmark.mjs`. Both functions are exported and unit-testable in isolation.
