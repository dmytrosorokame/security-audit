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

### How honest we are about the result

When reporting numbers we **always** quote both F1s side by side and the gap. A README headline of "F1 = 1.0" without disclaimer is forbidden. The benchmark runner enforces this by emitting a two-table report.

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

## How a reviewer should read this

1. Open `benchmark/results.md`. The header tells you the corpus list and the disclaimer.
2. Look at the **gap** number, not the smoke F1. If smoke is 1.00 and independent is 0.80, the realistic upper bound for production performance is closer to 0.80 — and even that bound is optimistic until stage 2 lands.
3. Disregard any single-corpus F1 in isolation. A tool that scores 1.00 on a single corpus is suspicious until the gap is reported.

This document is part of the project's permanent record because the "we tested on our own data" question will be asked again by every careful reviewer. The answer should be in the repo, not lost in a defence transcript.
