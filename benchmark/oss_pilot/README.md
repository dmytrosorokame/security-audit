# OSS pilot corpus

Fourth and most external corpus. Contains diffs scraped from **real, recently-merged PRs** in third-party Node/TypeScript open-source projects. Unlike the three other corpora — where the author wrote every diff — these diffs are written by **OSS maintainers and contributors who have never heard of this project**.

This is the closest we currently get to the unbiased, real-world test set described as Stage 2 in [`docs/INDEPENDENT_VALIDATION.md`](../../docs/INDEPENDENT_VALIDATION.md).

## Status — a labelled snapshot IS committed (Plan 5)

This corpus now contains a **committed, fully-labelled snapshot of 26 cases** (no longer populated-on-demand only). All sources are permissively licensed (see *Attribution & licensing* below), so the diffs and labels are checked in to make the oss_pilot F1 **reproducible**. The snapshot has two kinds of case:

- **19 scraped-PR cases** `diffs/<repo>__pr<N>.diff` + `expected/<repo>__pr<N>.json` — real recently-merged PRs from the `targets.json` repos, **review-labelled by a single annotator**. All 19 are reviewed true-negatives (`expect_zero_findings: true`): each diff was read and judged to introduce no security regression (refactors, dep bumps, robustness/encoding fixes, docs/CI). Rationale in each `notes`.
- **7 CVE-derived positive cases** `diffs/op<NN>_<slug>.diff` + `expected/op<NN>_<slug>.json` — each the **inverse of a public upstream fix** for an already-disclosed-and-patched npm CVE (`+` side = pre-fix vulnerable code). These give the corpus true positives so it yields a meaningful F1. Strongest realism (§4.4).

> ⚠️ **Single-annotator pilot.** Every label here is one-author (the project author). This is disclosed in the headline F1, not a footnote (playbook §8). The Cohen's κ second-annotator step (§4.4 stretch) is **not done** — there is no second annotator yet.

You can still re-populate fresh scraped PRs on demand with `node scripts/collect_oss_diffs.mjs` and label per [`docs/OSS_AUDIT_PLAYBOOK.md`](../../docs/OSS_AUDIT_PLAYBOOK.md).

### The 7 CVE-derived positive cases
| id | package | CVE | class | rule |
|----|---------|-----|-------|------|
| op01 | follow-redirects | CVE-2023-26159 | open redirect / SSRF | B-14 (alt B-04) |
| op02 | semver | CVE-2022-25883 | ReDoS | B-18 |
| op03 | lodash | CVE-2020-8203 | prototype pollution | R-05 |
| op04 | lodash | CVE-2021-23337 | code injection (`_.template`) | B-15 (alt B-06) |
| op05 | minimist | CVE-2020-7598 | prototype pollution | R-05 |
| op06 | ansi-regex | CVE-2021-3807 | ReDoS | B-18 |
| op07 | json5 | CVE-2022-46175 | prototype pollution | R-05 |

Each `op*` case is `provenance.kind:"real"`, citing the upstream fix commit + CVE/GHSA id + licence. Reversing an already-public, patched advisory discloses nothing new (responsible-disclosure-safe).

## Attribution & licensing

All sources in this committed snapshot are **permissively licensed** (MIT/ISC) and attributed per-case in `provenance.source` (PR/commit URL + CVE/GHSA + licence). Scraped-PR repos (all MIT): fastify, express, koa, axios, form-data, mongoose, multer, nodemailer, validator.js. CVE-positive packages: follow-redirects (MIT), semver (ISC), lodash (MIT), minimist (MIT), ansi-regex (MIT), json5 (MIT). Upstream diffs remain under their original licences. **A diff from a copyleft (GPL/AGPL/LGPL) or unknown-licence source must NOT be committed** — see `.gitignore`.

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
- The committed snapshot redistributes only **permissively-licensed** (MIT/ISC) diffs, with per-case attribution (see *Attribution & licensing*). We do **not** commit diffs from copyleft (GPL/AGPL/LGPL) or unknown-licence sources — those stay per-run and `.gitignore`'d (see `.gitignore`).
- All 7 CVE-positive cases reverse an **already-public, patched** advisory, so they disclose nothing new. We **never** report a *new* finding about a vulnerability in a live target repo without first reporting it privately to the upstream maintainers via their security-disclosure channel (playbook §6).
