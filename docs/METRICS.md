# Evaluation metrics and methodology

This document defines **how we measure success** for security-audit. It is the operational counterpart to the F1 numbers in `benchmark/results.md` (and the thesis-side rollup `f1_table.md`, which lives in the diploma appendix and is not committed to this repository) — what those numbers mean, how they are computed, and what they can and cannot claim.

## Primary metrics

We report **two regimes** for every benchmark run, because the same scan can be "correct" in different senses depending on what the reviewer cares about.

### Strict regime — exact rule match

A finding is counted as **True Positive** only if its `rule_id` is identical to the expected `rule_id` in the ground truth (or to one explicitly enumerated in `expected.accept_alternatives`). Different rule under the same OWASP/CWE category counts as a partial miss, not a TP.

- **Use case.** Operational dashboards, alerting, severity gating in CI. The exact `rule_id` controls which OWASP Cheat Sheet link is shown, which severity is applied, and which remediation template is offered. Mis-routing here costs time.
- **What it answers.** "How often does the tool emit the *correct specific* recommendation?"

### Loose regime — OWASP/CWE category match

A finding is counted as **True Positive** if its `owasp_id` AND `cwe_id` match the expected entry's `owasp_id` AND `cwe_id`, even when `rule_id` differs.

- **Use case.** Academic comparisons against other LLM/SAST tools that may not use our exact rule taxonomy. Also useful for trend analysis ("how many XSS-class findings did we catch this quarter?").
- **What it answers.** "How often does the tool put the finding in the *right family*?"

The two regimes are reported side by side in `benchmark/run_benchmark.mjs` output and in `benchmark/results.md`. Headline F1 in `README.md` always quotes both with their disclaimer.

## Definitions

For a run over N test cases, each case has an expected list and an actual list of findings.

| Outcome | Strict regime | Loose regime |
|---|---|---|
| **Full TP** | actual `rule_id` matches expected `rule_id` (or its `accept_alternatives`) | actual `owasp_id` + `cwe_id` match expected |
| **Partial TP** | category matches but `rule_id` does not (counted as FN in strict) | n/a (collapses into TP) |
| **False Negative (FN)** | expected entry has no matching actual finding | same |
| **False Positive (FP)** | actual finding has no matching expected entry **on a non-zero-findings case**; or any actual finding **on a `expect_zero_findings` case** | same |
| **True Negative (TN)** | `expect_zero_findings: true` AND actual list is empty | same |

From these:

- **Precision** = TP / (TP + FP)
- **Recall** = TP / (TP + FN)
- **F1** = 2 · P · R / (P + R)

`benchmark/run_benchmark.mjs` emits all four counts and both F1s, plus the median latency and cost across `--seeds` reruns of the same case.

## Calibration metric (new in 0.1.0)

The `confidence` field on each finding is **self-reported by the LLM**. We measure how well it matches reality:

- **Downgrade rate.** Fraction of findings where `confidence_downgraded_from` is set (the LLM claimed a higher confidence than its `exploit_trace` could support, and `calibrateConfidence` lowered it).
- **Downgrade outcome.** For `confidence_downgraded_from` findings, what fraction turn out to be FP in the ground truth. A downgrade should correlate with "less likely to be exploitable" — if not, the calibration rules need tuning.

`run_benchmark.mjs` does **not yet** emit calibration metrics; this is a roadmap item once the benchmark grows beyond the n=5 smoke set.

## Cost & latency metrics

- **Median cost per scan (USD).** `cost_usd` reported by the provider envelope. Median across `--seeds` reruns to dampen single-call noise from cache misses.
- **Median latency (ms).** Wall-clock time from `scan_diff.mjs` start to JSON emit.
- **Cache hit rate.** Across all scans in a benchmark, fraction whose response was served from `.security-audit-cache/`. Reported when `--cache-dir` is set.

## What the metrics **do not** measure

- **Real-world FP / FN distribution.** Our benchmark is a curated smoke set of 9 diffs (5 vulnerable + 4 edge cases). An external CVE-fix corpus is required for any claim of generalisability. Tracked in `README.md > Roadmap`.
- **Confidence calibration *vs. exploit success rate*.** "Did this finding actually lead to a successful exploit on the real system?" — this needs a separate study with a security researcher in the loop, not automatable.
- **Reviewer workload.** Even a precision-1.0 tool may produce findings that take 15 min each to triage; a precision-0.7 tool may produce findings that take 30 seconds each. We do not measure triage cost.
- **Hidden FN (vulnerabilities the catalog never describes).** Our recall is bounded by `references/owasp-rules.md`. We have no way to evaluate the long tail.

## How to run a measurement

```bash
# Live, with stats over 3 reruns per case
export OPENAI_API_KEY=sk-...
node benchmark/run_benchmark.mjs --seeds=3 --provider=openai --model=cheap

# Or against Anthropic
export ANTHROPIC_API_KEY=sk-ant-...
node benchmark/run_benchmark.mjs --seeds=3 --provider=anthropic --model=sonnet

# To compare two prompts: stash, edit prompts/system.md, rerun, diff results.md
git stash
# (edit prompt)
node benchmark/run_benchmark.mjs --seeds=3 --provider=openai
cat benchmark/results.md  # save somewhere
git stash pop
node benchmark/run_benchmark.mjs --seeds=3 --provider=openai
diff <(prev) <(current)
```

The benchmark writes a Markdown report to `benchmark/results.md` and exits non-zero if F1 (in either regime) drops below the configured threshold (`--min-f1-strict`, `--min-f1-loose`). CI uses this to detect regression on prompt or catalog changes.

## Threshold setting

Current thresholds (configurable):

- Strict F1 ≥ 0.60
- Loose F1 ≥ 0.80

These are intentionally below current measured F1 (0.857 strict / 1.00 loose on the smoke set) so the gate trips on actual regression rather than expected noise. As the corpus grows beyond n=5, thresholds should be raised in step with the new baseline.
