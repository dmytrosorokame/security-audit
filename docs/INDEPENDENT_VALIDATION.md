# Independent validation plan

This document responds directly to the central methodological criticism of this work: that the smoke benchmark (`benchmark/expected/`) was created by the same author who wrote the catalog (`references/owasp-rules.md`), and therefore cannot be used to argue generalisability.

We tackle the criticism in **two staged moves**, only the first of which is currently implemented.

## Stage 1 (implemented) — independent CVE-pattern corpus

Live at `benchmark/independent_corpus/`. Ten cases reproducing publicly disclosed vulnerability patterns from CVE families that **were not used as input** when designing the catalog or the system prompt.

### What this gives us

- A second F1 number, reported alongside the smoke F1 in `benchmark/results.md`.
- A **generalisation gap** metric: `smoke F1 − independent F1`. A small gap (< 0.10) supports the claim that the catalog generalises; a large gap signals over-fit.
- A test surface for prompt edits: a prompt tweak that helps the smoke set but hurts the independent corpus is, with high probability, an over-fit.

### What this does **not** give us

- True external validity. The author still wrote the diffs. The reduction in bias comes from (a) writing them without referencing the catalog text and (b) targeting documented CVE families rather than scenarios designed to make the catalog look good. The bias is not eliminated.
- Coverage of compositional / multi-file vulnerabilities. Every case here is a single-file diff. Real CVEs often span 3–10 files.
- Coverage of rule classes the catalog doesn't enumerate (race conditions, business-logic flaws, protocol-level issues).

### Train/test leakage with few-shot examples — acknowledged

Earlier revisions of this document only acknowledged overlap between few-shot examples and the **smoke** corpus. Closer inspection shows additional structural overlap with the **independent** and **complex** corpora as well. The exhaustive list is now maintained at the top of [`prompts/few_shot.md`](../prompts/few_shot.md); the short version:

| Few-shot | Corpus case | Corpus | Nature of overlap |
|---|---|---|---|
| Example 1 | `01_dom_xss_introduction` | smoke | identical pattern |
| Example 4 | `04_idor_ambiguous` | smoke | identical pattern |
| Example 5 | `05_sanitizer_removed` | smoke | identical pattern |
| Example 7 | `i01_prototype_pollution_argv_merge` | **independent** | same file path / function name |
| Example 8 | `c06_safe_large_refactor` | complex | same allowlist-constant pattern |
| Example 9 | `i09_nosql_injection_mongoose_where` | **independent** | same file path + same expected JSON spelled out in the prompt |
| Example 10 | `c02_compositional_xss_regression` | complex | same sanitizer-shape relaxation pattern |

This **invalidates** the previously claimed reading of the independent corpus as a clean external-validity test:

- The genuinely held-out subset of `independent_corpus` is **8 of 10 cases** (`i02..i08`, `i10`), not all 10. With i01 + i09 contributing to the reported F1 = 1.000, that headline is partly memorisation, not generalisation.
- The complex corpus is similarly contaminated for 2 of 7 positive cases (c02, c06).
- The only corpus with **no** few-shot overlap is the OSS pilot (TN-only). Its precision = 0/4 on emitted findings is therefore the only number in this report with genuine external-validity weight, and it is much less flattering than the headline F1s.

### How honest we are about the result

When reporting numbers we **always** quote both F1s side by side and the gap. A README headline of "F1 = 1.0" without disclaimer is forbidden. The benchmark runner enforces this by emitting a two-table report. The overlap table above is the second part of that discipline: any future few-shot edit that touches a benchmark file path must also update this disclosure.

## Stage 2 (roadmap) — raw CVE-fix corpus

The next-level honest test set is the **actual git diff** of CVE-fix commits, not our reproductions of their patterns. The plan:

### Source

GitHub Advisory Database (GHSA) — public, machine-readable, links each advisory to a fix commit when one exists. Limited to:

- npm ecosystem (matches our supported language stack).
- Severity High or Critical (avoids triaging hundreds of low-severity advisories).
- 2022-01-01 onwards (more recent code style; more likely to be Node ≥ 16).
- Fix commit is a **single** commit that touches **≤ 5 files** and **≤ 200 changed lines** (clean diff for ground truth).

A rough estimate from manual sampling: ~200 advisories per year satisfy these filters, of which ~50 yield diffs in scope of our catalog (XSS, SSRF, injection, traversal, deserialisation, etc.). Target corpus size: **n = 50** advisories.

### Ground truth labelling

The author labels each diff with the expected `rule_id`, `owasp_id`, `cwe_id`, `severity` from the advisory text — independently from running the analyser. The CWE on the advisory is the primary signal; the catalog rule is the secondary mapping.

To reduce annotator bias:
- Labels are **frozen before any LLM run**. Once a label JSON is committed, it is not edited after seeing the LLM's output.
- A second annotator (a peer reviewer) re-labels a 20 % random sample. Inter-annotator agreement (Cohen's κ) is reported.

### Collection pipeline

```bash
# Fetch GHSA database (public download)
gh api -X GET /advisories?ecosystem=npm&severity=high,critical&per_page=100 > ghsa.json

# Filter to single-commit fixes in scope
node scripts/collect_cve_corpus.mjs --input=ghsa.json --output=benchmark/cve_corpus/ \
  --max-files=5 --max-lines=200 --since=2022-01-01

# Hand-label
node scripts/label_cve_corpus.mjs --corpus=benchmark/cve_corpus/
```

`scripts/collect_cve_corpus.mjs` and `scripts/label_cve_corpus.mjs` are not yet implemented — they are the deliverable of stage 2.

### Reporting

When stage 2 lands, the benchmark report grows a third corpus column (`benchmark/cve_corpus/`) and two extra rows in the generalisation gap section. Headline F1 in README.md becomes a triple: smoke / independent / CVE-raw.

## Measured failure modes (complex corpus, cycle-5)

After two improvement cycles on the prompt + few-shot, three cases remain FN/Partial on the complex corpus. We measured each on both `gpt-4o-mini` (default) and `gpt-4o` (35× cost, $0.06/call) — **same outcome on both**, so this is a cognitive gap of the diff-only architecture, not a model-size issue:

| Case | Failure mode | Root cause | Defendable on defence? |
|---|---|---|---|
| c02 — DOMPurify `ADD_TAGS: ['script']` | FN | Model sees `DOMPurify.sanitize()` is still called and short-circuits self-critique step 3 ("is there a guard?") with YES. The configuration argument (`ADD_TAGS:['script']` defeats the protection) is not recognised as a relaxation. System-prompt rule 12 ("config changes on a security mechanism are always security-relevant") added in round-2 did not move the needle for gpt-4o-mini *or* gpt-4o. | Yes — documents the limitation of structural pattern matching vs semantic configuration analysis. |
| c03 — `router.use('/items/:id', requireOwner)` removed, replaced by per-route guard on PUT only | FN | The removal is visible in the diff (a deleted `router.use` line). What is NOT in the diff is the surrounding **other routes** in the same file (GET on the same path) that previously inherited the protection. Diff-only context omits exactly the evidence needed to reason about this regression. `--include-file-context` is the architectural mitigation. | Yes — direct illustration of ADR-001's documented trade-off. |
| c04 — Stripe key as env-fallback default in `config.ts` | Partial (was) → TP (now, after accept_alternatives) | Catalog overlap: R-07 (hardcoded secrets / API keys) and B-10 (hardcoded credentials in connection string) and B-07 (weak crypto / hardcoded JWT secret) all plausibly apply to a server-side Stripe live key. The benchmark now accepts any of the three with `accept_alternatives`, and system-prompt rule 13 documents the catalog disambiguation. | Partially — admits that the catalog has overlapping rule definitions; round-3 work to split B-07 into "weak crypto algo" and "hardcoded crypto secret" would clean this up. |

These three are the **persistent failure modes**. The honest read is:

- **One is a cognitive gap of LLM-SAST writ large** (c02): no amount of prompt tweaking will get a model to override its "the protection is called, therefore there is protection" prior unless the configuration analysis is offloaded to a deterministic AST pass — which ADR-002 explicitly rejected. This is the principled limitation of the architecture.

- **One is the documented ADR-001 trade-off** (c03): diff-only context is too narrow to reason about middleware-inheritance regressions; `--include-file-context` exists as the operator-controlled mitigation.

- **One is catalog overlap** (c04): tractable, scheduled for a catalog refactor.

## Comparison with prior art

| Stage | Corpus type | Bias | What it proves |
|-------|-------------|------|----------------|
| 0 (initial) | Author-curated smoke set | High (catalog co-authored) | Regression-detection only |
| 1 (now) | Author-written, CVE-pattern-derived | Reduced (catalog not consulted while writing) | Generalisation across known pattern families |
| 2 (planned) | Raw CVE-fix git commits | Minimal (annotator-labelled but author wrote neither code nor catalog) | Empirical recall on real-world regressions |

Khare et al. (2023) and Steenhoek et al. (2024) operate at stage 2 directly — they use Big-Vul, Devign, etc. Our trajectory matches theirs, with the difference that we **report stage 1 results explicitly** rather than skipping straight to stage 2 with no validation that the catalog generalises at all.

## Known threats to validity (declared explicitly, not patched-over)

These are limitations of the current results. They are listed here so a reviewer doesn't have to dig them out of source code. Each one has a planned fix in stage 2 / stage 3.

### 1. Single-seed runs — variance not measured

All cycle-6 numbers in `benchmark/results.md` (and the thesis-side rollup `f1_table.md`) come from `--seeds=1`. LLM outputs are stochastic even at `temperature=0` (provider-side caching, batching boundaries, hidden non-determinism). The 0.909 strict-F1 on smoke is itself a symptom: `04_idor_ambiguous` flipped from TP (earlier cycles, also gpt-4o-mini, also temperature=0) to FN at the current seed. **Run-to-run F1 variance has not been quantified.**

Mitigation roadmap:
- Stage 2 — re-run each corpus with `--seeds=5` and report mean ± stddev.
- Stage 3 — temperature sweep `{0.0, 0.3, 0.7}` to characterise the determinism/diversity trade-off.
- Decision rule for now: any single-seed F1 quoted in this project should be read with an implicit ±0.1 band.

### 2. Single-annotator ground truth — no Cohen's κ

Every label across `expected/`, `independent_corpus/`, `complex_corpus/`, and `oss_pilot/` was written by one person (the author). Standard practice for empirical SE work is ≥2 annotators on a held-out 20% sample, reporting inter-annotator agreement (Cohen's κ ≥ 0.6 considered acceptable).

Mitigation roadmap:
- Stage 2 — recruit a second annotator for the OSS pilot (cheapest entry point: 19 cases × 5–15 min/case ≈ 2–4 h).
- Stage 3 — labels for the raw CVE-fix corpus are derived from GHSA advisory text (`cwe_id`, severity), reducing — but not eliminating — single-annotator bias.

### 3. Few-shot ↔ smoke overlap

Examples 1, 4, 5 in `prompts/few_shot.md` are structurally identical to smoke cases 01_dom_xss_introduction, 04_idor_ambiguous, 05_sanitizer_removed. This is **deliberate** grounding on canonical catalog patterns, but it means smoke F1 cannot be used as a generalisability claim — it measures whether the model can reproduce its own examples. **The smoke F1 number is honest only when paired with the independent / complex / oss_pilot numbers** (the multi-corpus reporting in `results.md` enforces this pairing).

### 4. OSS pilot — provisional-TN ground truth

All 19 OSS-pilot expected JSONs carry `unlabeled: true` and `expect_zero_findings: true` by default. This is a **presumption**, not a human-validated label. The benchmark treats them as TN cases for FP-rate computation, but if a real regression slipped through any of these PRs, the corpus would silently misclassify the analyser's correct detection as a FP. The 4/19 = 21% FP rate is therefore an upper bound: the true precision could be higher if any of the four flagged findings is in fact a real regression.

Mitigation roadmap:
- Stage 2 — promote each of the 19 PRs from `unlabeled: true` to `unlabeled: false` after manual review, separating real-TN from "we presume TN".
- Stage 3 — actively seek `expect_zero_findings: false` cases (real upstream security fix commits) so OSS pilot becomes a corpus with both positive and negative ground truth.

## Comparison with prior art

| Stage | Corpus type | Bias | What it proves |
|-------|-------------|------|----------------|
| 0 (initial) | Author-curated smoke set | High (catalog co-authored, 3/10 few-shots overlap) | Regression-detection only |
| 1 (now) | Author-written, CVE-pattern-derived | Reduced (catalog not consulted while writing) | Generalisation across known pattern families |
| 1.5 (now) | OSS PR provisional-TN baseline | Low (3rd-party diffs) + Medium (single annotator, provisional) | Real-world FP rate on the long tail of routine diffs |
| 2 (planned) | Raw CVE-fix git commits, 2-annotator κ | Minimal (annotator-labelled but author wrote neither code nor catalog) | Empirical recall on real-world regressions |

Khare et al. (2023) and Steenhoek et al. (2024) operate at stage 2 directly — they use Big-Vul, Devign, etc. Our trajectory matches theirs, with the difference that we **report stage 1 and 1.5 results explicitly** rather than skipping straight to stage 2 with no validation that the catalog generalises at all.

## How a reviewer should read this

1. Open `benchmark/results.md`. The header tells you the corpus list and the disclaimer.
2. Look at the **gap** numbers, not any single F1. If smoke is 0.909 and independent is 1.000, the smoke FN is single-seed instability, not a generalisation failure. If complex is 0.727, that's the diff-only architectural limit. If oss_pilot FP rate is 21%, that's the routine-deployment cost.
3. Disregard any single-corpus F1 in isolation. A tool that scores 1.00 on a single corpus is suspicious until at least two other corpora are reported.
4. Look at the threats-to-validity section above (§1–4) — those are the limits known at the cutoff date. Everything else is conjecture until stage 2 lands.

This document is part of the project's permanent record because the "we tested on our own data" question will be asked again by every careful reviewer. The answer should be in the repo, not lost in a defence transcript.
