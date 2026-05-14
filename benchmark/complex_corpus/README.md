# Complex corpus

Third tier of benchmarks. Where:

- `benchmark/expected/` (smoke set, n=9) is **simple single-file diffs** designed for regression detection;
- `benchmark/independent_corpus/` (n=10) reproduces **publicly-documented CVE patterns**, still single-file;
- **this** corpus (n=7) brings **multi-file, compositional, and noise-heavy diffs** — the shape PRs take in real codebases.

The point is to test whether the analyzer's verdicts hold up under conditions that the catalog and few-shot examples did not foresee:

- Vulnerabilities split across 2–3 files (the diff piece in any single file looks innocuous)
- Real-world refactor noise that distracts from a small but critical change
- Sanitiser-shaped APIs that don't sanitise (configuration-level regressions)
- True negatives that look dangerous on first glance (over-flagging probe)

## Cases

| # | Pattern | Files | Difficulty | Expected |
|---|---------|-------|-----------|----------|
| c01 | SSRF hidden behind an "extracted helper" refactor | 3 | multi-file | B-04 |
| c02 | XSS via DOMPurify allowlist relaxation | 3 | compositional | R-01 (or NEW_PATTERN) |
| c03 | IDOR — authz middleware moved from router.use to PUT only | 2 | semantic | B-11 |
| c04 | Hardcoded Stripe live key buried in "logger improvements" PR | 3 | noise-heavy | R-07 |
| c05 | SQL injection via tenant filter string-concatenation | 2 | taint-chain | B-01 |
| c06 | True negative: repository-pattern refactor with allowlist preserved | 3 | noise-heavy | — |
| c07 | Prototype pollution: DENY dropped + spread guard removed | 2 | compositional | R-05 |

## Difficulty taxonomy

- **multi-file** — the regression spans ≥2 files. Single-file analysis misses it.
- **compositional** — two seemingly benign changes combine into a vulnerability.
- **semantic** — the diff preserves the API shape (function still called, middleware still imported) but changes its semantics.
- **noise-heavy** — significant unrelated improvements in the same PR draw attention away from a small but critical change.
- **taint-chain** — source and sink live in different files; the analyzer must follow data across files.

## Running

```bash
node benchmark/run_benchmark.mjs \
  --corpus=benchmark/complex_corpus \
  --seeds=3 \
  --include-file-context        # recommended — these cases need cross-file context
```

The combined run with all three corpora is the **headline academic result**:

```bash
node benchmark/run_benchmark.mjs --seeds=3 \
  --corpus=benchmark/expected \
  --corpus=benchmark/independent_corpus \
  --corpus=benchmark/complex_corpus
```

Three F1 numbers + two generalisation-gap numbers (smoke→independent, independent→complex) appear in `benchmark/results.md`. The **second gap** is the central metric — it measures degradation as cases shift further from the smoke set's design assumptions.

## Expected behaviour

The hypothesis going into stage-1 evaluation: F1 should degrade monotonically across the three corpora.

- Smoke F1: ≈ 1.0 (by construction — curated regression detection)
- Independent F1: 0.7–0.9 (catalog generalisation to documented CVE families)
- Complex F1: 0.4–0.7 (the analyzer's weakest point — cross-file taint, compositional regressions)

A complex-corpus F1 above 0.8 is **suspicious** — it suggests either over-fitting to our specific complex cases (the author wrote them) or that the cases are easier than they look. A complex-corpus F1 below 0.3 is also a warning — the analyzer may be giving up on multi-file inputs and emitting `NEEDS_HUMAN` on everything.

The *honest* outcome to report on the defence is a **measurable, explainable gap**: clear evidence that diff-only analysis loses signal as cases approach real-world complexity, with `--include-file-context` named as the practical mitigation.

## Why we wrote these cases (instead of using real OSS PRs)

Real OSS PRs would be the canonical stage-2 evidence (see `docs/INDEPENDENT_VALIDATION.md`). They cost:

- A `gh` CLI scrape + filtering pipeline (≈ 1 week of work)
- Hand-labelled ground truth on each (≈ 30 min per PR × 50 PRs = 25 h)
- A second annotator for Cohen's κ (matching cost)

The complex corpus is the **week-1 deliverable** of that plan: synthetic-but-realistic. The OSS-pilot pipeline (`scripts/collect_oss_diffs.mjs`) is shipped alongside so the stage-2 work can start from the same harness without re-engineering it.

## How to contribute a case

1. Identify a real-world regression class that single-file diffs underrepresent. Look at CVEs that required multiple commits to fix, or post-mortems where the issue lived "between the files".
2. Write a minimal multi-file diff (2–4 files, ≤ 100 changed lines total) that reproduces the pattern.
3. Create `expected/cNN_<short_name>.json` with `complexity`, `files_changed`, `challenge`, `notes` fields filled in honestly.
4. Run `node benchmark/run_benchmark.mjs --corpus=benchmark/complex_corpus --case=cNN_<short_name>` to confirm parsing.
5. PR with diff + JSON.
