# OSS audit playbook

How to evaluate security-audit on real-world third-party OSS code. This is the operator workflow for Stage 2 of the validation plan ([`docs/INDEPENDENT_VALIDATION.md`](./INDEPENDENT_VALIDATION.md)).

The goal is **external validity**: the diffs are written by people who have never heard of this project, on codebases the catalog was not designed around. The cost is operator labour — every PR needs a hand-applied ground-truth label.

---

## 1. Prerequisites

```bash
# gh CLI authenticated (one-time)
gh auth login --hostname github.com --git-protocol https
gh auth status   # must report ✓

# pnpm install already done
pnpm install --ignore-workspace

# One API key (either provider)
export OPENAI_API_KEY=sk-...        # cheap option
# or
export ANTHROPIC_API_KEY=sk-ant-...
```

Estimated full-pilot cost on `--seeds=3` and `--model=cheap`: ≤ $1.00. Set `--max-cost=2.00` as a safety net.

---

## 2. Collect

```bash
# Default: 3 PRs from each of 10 repos, filtered to small/medium changes
node scripts/collect_oss_diffs.mjs

# Wider sample
node scripts/collect_oss_diffs.mjs --per-repo=5 --max-files=10 --max-lines=400

# Preview without writing anything
node scripts/collect_oss_diffs.mjs --dry-run
```

Output:

- `benchmark/oss_pilot/diffs/<repo>__pr<N>.diff` — raw unified diffs
- `benchmark/oss_pilot/expected/<repo>__pr<N>.json` — **provisional-TN stubs** (`unlabeled: true`, prefix `[PROVISIONAL-TN]`).
  Each stub presumes the recent merged PR contains no security regression — that presumption MUST be replaced with a human-reviewed label before the case counts toward any F1 claim.

A typical run lands 10–20 PRs through the filter. Expect 2–4 minutes wall time.

---

## 3. Label

Open every JSON under `benchmark/oss_pilot/expected/` and fill in the ground truth. **This is the hard part.** The rubric below mirrors the format used by `benchmark/expected/` and `benchmark/independent_corpus/` so the same benchmark runner can process the data.

### 3.1 Read the diff

Open the corresponding `.diff` file. Read every changed hunk. Identify:

- **What did the diff actually change?** State it in one sentence as if explaining to a colleague.
- **Is there a security-relevant change?** If yes, classify it; if no, mark as `expect_zero_findings: true`.

### 3.2 Choose the label

If you decide **no security regression**:

```json
{
  "expected": [],
  "expect_zero_findings": true,
  "unlabeled": false,
  "name": "[oss] axios/axios PR #6543: ...",
  "notes": "Refactor: extract URL parsing helper. No taint chain affected."
}
```

If you decide **there is a security regression**:

```json
{
  "expected": [
    {
      "rule_id": "B-04",
      "owasp_id": "A01",
      "cwe_id": "CWE-918",
      "severity": "high",
      "accept_alternatives": ["NEW_PATTERN"]
    }
  ],
  "expect_zero_findings": false,
  "unlabeled": false,
  "name": "[oss] axios/axios PR #...: removed allowlist on followRedirect",
  "notes": "1-sentence justification + URL of the upstream PR if available"
}
```

Decision rules (matches the system prompt's verdict table):

- The catalog `rule_id` you pick is the one that **best describes the introduced issue**. If unsure, prefer `NEW_PATTERN` and write a clear `notes`.
- The `severity` comes from the catalog (look up the rule in `references/owasp-rules.md`). Don't soften it because the upstream PR didn't flag it.
- `accept_alternatives` is for cases where two rule IDs both legitimately apply (e.g. R-01 vs R-02 for two React XSS sinks).

### 3.3 Don't gild the lily

If you can't tell whether the diff introduces a vulnerability from the diff alone, **say so** in `notes` and leave `expected: []` + `expect_zero_findings: false`. Set `unlabeled: false` regardless — that flag tracks whether you reviewed it, not whether you found something. The benchmark counts this as "this case was reviewed and we decided no finding is appropriate" — a true negative.

### 3.4 Time budget

Realistic: 5–15 min per PR. For a 15-PR sample, budget 2 hours of focused labelling. Don't label late at night; tired annotators silently default to "no finding".

---

## 4. Inter-annotator agreement (optional but strongly recommended)

For an academic-grade result, ask a second person to independently label a random 20% sample:

```bash
# Pick a random 20%
ls benchmark/oss_pilot/expected/*.json | shuf | head -n $(( $(ls benchmark/oss_pilot/expected/*.json | wc -l) / 5 ))
```

Have them label those into a separate directory (e.g. `benchmark/oss_pilot_v2/expected/`) without seeing your labels. Compute Cohen's κ:

```bash
node scripts/agreement.mjs benchmark/oss_pilot/expected benchmark/oss_pilot_v2/expected
# (not yet implemented — Stage-2 deliverable)
```

A κ < 0.4 means the labels are too noisy to support empirical claims; revisit the rubric.

---

## 5. Run the benchmark

```bash
# All four corpora in one go
node benchmark/run_benchmark.mjs \
  --corpus=benchmark/expected \
  --corpus=benchmark/independent_corpus \
  --corpus=benchmark/complex_corpus \
  --corpus=benchmark/oss_pilot \
  --seeds=3 \
  --provider=openai --model=cheap \
  --cache-dir=.security-audit-cache \
  --timeout=120 \
  --max-cost=3.00
```

`benchmark/results.md` will contain four per-corpus tables and three generalisation-gap rows. The honest headline number for the defence is the **oss_pilot F1**, **not** the smoke F1.

---

## 6. Report findings to upstream (if any)

If the analyzer flags a real, exploitable vulnerability in a target repo:

1. **Do not** publish it in your benchmark report yet.
2. Open a private security advisory with the upstream project. Most of the targets in `targets.json` have GitHub Security Advisories enabled — file via `https://github.com/<org>/<repo>/security/advisories/new`.
3. Wait for upstream's coordinated-disclosure timeline (typically 30–90 days).
4. After upstream fixes (or after the disclosure window expires), update your report to cite the CVE / advisory ID.

This step is not optional for an academic project. Publishing zero-day details without coordinated disclosure violates the OWASP and ACM code of ethics.

---

## 7. Limitations to keep front of mind

- **Selection bias persists.** `targets.json` is hand-curated and biased toward security-relevant projects.
- **Labels are one-author until a second annotator joins.** Disclose this in your write-up.
- **Sample size matters.** A 15-PR sample gives F1 with a confidence interval roughly ±0.15. Bigger samples shrink the CI; budget accordingly.
- **`gh` rate limits.** GitHub API: 5000 requests/hour for authenticated users. The collection script is far below that for sensible `--per-repo` values, but parallel runs can trip it.

---

## 8. Checklist before publishing results

- [ ] Every labelled JSON has `unlabeled: false` set (no half-labelled cases).
- [ ] At least one true-negative (`expect_zero_findings: true`) case is included.
- [ ] Notes field explains the call for every case, not just the ones with findings.
- [ ] Inter-annotator κ computed (if the second-annotator step was done).
- [ ] Any vulnerabilities found in real OSS were responsibly disclosed before publication.
- [ ] The four-corpus F1 numbers and the generalisation gaps are in the README / defence slides.
- [ ] The disclaimer "this is a single-annotator pilot" is **in** the headline number, not buried in a footnote.
