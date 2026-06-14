# Independent corpus

This directory holds a **second** benchmark set, distinct from `benchmark/expected/`. Its purpose is to **counter the central methodological criticism** of the primary smoke benchmark: namely, that the catalog (`references/owasp-rules.md`), the system prompt, and the curated 9-case smoke set were all written by the same author. That makes the smoke benchmark useful for regression detection but **invalid** as a generalisability claim.

## What this corpus is

Ten reproductions of vulnerability patterns drawn from **publicly disclosed CVE families and CWE entries**, none of which were used as input when designing the catalog or the system prompt. Each case:

- references a real CVE family or CWE classification (see `expected/iNN_*.json → cve_reference`),
- expresses the **pattern** in code typical of a Node.js / TypeScript codebase, written without reference to our catalog's wording or rule list,
- mixes regressions (a guard removed) with introductions (a new dangerous sink), with one true-negative case (a hardening commit) to detect over-flagging.

## What this corpus is **not**

It is **not** raw `git show` of the actual CVE-fix commits. We are not redistributing those commits because:
1. Doing so adds a license-tracking burden (each upstream commit has its own license, contributor agreements, etc.).
2. Real commits include unrelated noise (imports, formatting, comments) that confuses ground-truth labelling.
3. CVE commits sometimes contain the *partial* fix, requiring multiple commits to fully patch — making single-diff testing ambiguous.

Instead, each case is a **representative reproduction** of the vulnerability pattern that the cited CVE family exhibits. The author wrote these without referencing the catalog or testing them against the LLM before finalising. The intent is to test recall on the **pattern**, not the literal commit.

This is intermediate between "curated by the catalog author" (the smoke set, biased) and "raw CVE-fix corpus" (the future-work goal). The bias here is reduced but **not eliminated** — the same author still wrote the diffs. See `docs/INDEPENDENT_VALIDATION.md` for the plan to move further toward raw CVE-fix data.

## Cases

| # | Pattern | CVE family / CWE | Catalog rule |
|---|---------|------------------|--------------|
| i01 | Prototype pollution via CLI argv deep-merge | CVE-2021-44906, CVE-2022-37601 (minimist, loader-utils) | R-05 |
| i02 | XXE via libxmljs2 `noent:true` | CVE-2023-23362, CVE-2022-39353 (libxmljs2, xmldom) | B-12 |
| i03 | Command injection via `execFile` → `exec` regression | CVE-2023-26136 family (Node child_process) | B-02 |
| i04 | Path traversal via removed `basename()` + boundary check | CVE-2022-25881 family | B-05 |
| i05 | Server-side open redirect via removed allowlist | CVE-2024-21505, CVE-2023-26159 family | B-14 |
| i06 | Mass assignment via removed field allowlist | CWE-915, CVE-2020-9484 family (Sequelize, loopback) | B-13 |
| i07 | Weak crypto: bcrypt → MD5 on password storage | CWE-327 / CWE-916; OWASP A04 | B-07 |
| i08 | CSRF middleware removed from Express app | CWE-352; CVE-2024-39014 family | B-08 |
| i09 | NoSQL injection via Mongoose `$where` + template string | CVE-2019-7609 (Kibana family) | B-03 |
| i10 | True negative: Helmet middleware **added** with hardened directives | (probes over-flagging) | — |

## Running

```bash
# Independent corpus only
node benchmark/run_benchmark.mjs --corpus=benchmark/independent_corpus --seeds=3

# Both corpora side by side (default is the smoke set; --corpus repeats supported)
node benchmark/run_benchmark.mjs --corpus=benchmark/expected --corpus=benchmark/independent_corpus
```

Use `--dry-run --no-write` for harness sanity-check without LLM cost.

## What the results mean

Reporting F1 separately for the two corpora is **the point**. The expected outcome (which validates the smoke set's value):

- **Smoke set F1 ≈ 1.0** — the catalog matches its own targeted scenarios.
- **Independent corpus F1 lower, but still meaningfully > 0.5** — this is the honest indicator that the catalog generalises to patterns it wasn't specifically tuned for.

A large gap between the two would tell us the catalog is over-fit; a near-equal F1 across both would suggest the patterns we catalogued match what the CVE world actually surfaces.

## How to contribute a new case

1. Pick a CVE family or CWE entry not already represented.
2. Write a minimal diff that **reproduces the pattern** without copying the upstream commit verbatim.
3. Create `expected/iNN_<short_name>.json` with `cve_reference`, `pattern_description`, and a target rule.
4. Run `node benchmark/run_benchmark.mjs --corpus=benchmark/independent_corpus --case=iNN_<short_name>` — confirm the case parses and classifies sensibly.
5. PR with both files.
