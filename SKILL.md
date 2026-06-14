---
name: security-audit
description: Use this skill whenever the user wants a security review of changed code — a pull request, staged commit, branch, or unified diff file. Triggers include "review this PR for security", "is this safe to merge", "scan my staged changes", "audit this diff for OWASP issues", "check for vulnerabilities in this commit", or any mention of OWASP / CWE / SAST in the context of a code change. The skill runs scripts/scan_diff.mjs, which extracts the diff, sends it to an LLM grounded in references/owasp-rules.md, validates findings against the diff, applies suppression, and emits CLI / PR-comment / SARIF / JSON. Works on TypeScript, JavaScript, TSX, JSX, Dockerfile, and docker-compose. Requires ANTHROPIC_API_KEY or OPENAI_API_KEY in env.
---

# Security Audit (diff-mode)

## Overview

Invoke `scripts/scan_diff.mjs` on a git diff to produce findings mapped to OWASP Top 10 (2025) and CWE. The pipeline is deterministic except for one LLM call (temperature 0, grounded in `references/owasp-rules.md`). Output is structured JSON; four format adapters render it to CLI, PR comment, SARIF, or raw JSON.

For the rule catalog, see `references/owasp-rules.md`. For the output schema, see `references/report-schema.md`. For suppression syntax, see the §Suppression section below.

## Quick start

```bash
# PR review — diff against base branch
node scripts/scan_diff.mjs --against=main

# Pre-commit — diff of staged changes
node scripts/scan_diff.mjs --staged

# External unified diff
node scripts/scan_diff.mjs --diff=path/to/patch.diff
```

One API key must be set:

```bash
export ANTHROPIC_API_KEY=sk-ant-...    # preferred when both are set
export OPENAI_API_KEY=sk-...
```

## Workflow

1. **Determine the input mode**. Ask the user or infer from context:
   - PR review → `--against=<ref>` (defaults to `origin/<base>` in CI via `$GITHUB_BASE_REF`)
   - Pre-commit local check → `--staged`
   - External patch file → `--diff=<path>`

2. **Pick the output format** with `--format`:
   - `cli` (default) — colourised terminal output
   - `pr` — Markdown for a GitHub PR comment
   - `sarif` — SARIF 2.1.0 for GitHub Code Scanning
   - `json` — pipe to downstream tooling

3. **Set the failure gate** with `--fail-on=<severity>` (`critical | high | medium | low | info | none`). Default `critical`. Exit code 2 means at least one finding meets or exceeds that severity.

4. **Run the scan**. Findings are validated against the diff (file / line / evidence cross-check) and any quotation the LLM fabricated is dropped before output.

5. **Surface the report**. Findings come pre-sorted by `risk_score` descending. For each, show: `severity`, `rule_id`, `owasp_id`, `cwe_id`, `file:line`, `evidence`, `rationale`, `remediation`. Treat `verdict=NEEDS_HUMAN` as a request for human review — do **not** auto-block, but do not silently drop either.

6. **Honor exit codes**:
   - `0` — no findings ≥ `--fail-on`
   - `2` — at least one finding ≥ `--fail-on` (CI should block merge)
   - `3` — tool error (extraction failed, API down, schema invalid, cost cap exceeded)

## Output schema

Each finding has this shape:

```json
{
  "rule_id": "R-02",
  "owasp_id": "A05",
  "cwe_id": "CWE-79",
  "severity": "high",
  "confidence": "high",
  "verdict": "TRUE_POSITIVE",
  "risk_score": 7.5,
  "file": "src/components/Comment.tsx",
  "line": 13,
  "evidence": "el.innerHTML = comment.body",
  "exploit_trace": [
    "source: comment.body (user-controlled)",
    "sink: innerHTML at line 13",
    "missing guard: no sanitizer between source and sink"
  ],
  "rationale": "1–2 sentence explanation",
  "remediation": "concrete fix, ideally with an OWASP Cheat Sheet link"
}
```

Verdict semantics:

- `TRUE_POSITIVE` — exploitable from the diff content alone.
- `LIKELY_TP` — strong signal; exploitability depends on context outside the diff.
- `NEEDS_HUMAN` — pattern present but ambiguous; bias toward human review.
- `FALSE_POSITIVE` — LLM ruled it out; surfaced so the user can audit the decision.

Full schema: `references/report-schema.md`.

## Common flags

| Flag | Purpose |
|---|---|
| `--against=<ref>` | Diff against a git ref (`main`, `origin/main`, `HEAD~1`, sha). |
| `--staged` | Diff of staged changes (pre-commit mode). |
| `--diff=<file>` | Parse an existing unified diff file. |
| `--format=<fmt>` | `cli` (default), `pr`, `sarif`, `json`. |
| `--output=<path>` | Write to file instead of stdout. |
| `--fail-on=<sev>` | `critical \| high \| medium \| low \| info \| none`. Default `critical`. |
| `--provider=<p>` | `auto` (default), `anthropic`, `openai`. |
| `--model=<m>` | Alias (`sonnet`, `haiku`, `best`, `cheap`, `nano`, `reasoning`) or exact id. |
| `--include=<glob>` | Restrict to files matching glob (repeatable). |
| `--exclude=<glob>` | Skip files matching glob (repeatable). |
| `--include-file-context` | Attach full-file content for hunks that depend on out-of-diff state. |
| `--max-files=<n>` | Cap on files in the diff (default 50). |
| `--max-cost=<usd>` | Refuse to emit results from a scan that exceeded this USD cap. |
| `--timeout=<sec>` | Abort the LLM call after N seconds. |
| `--no-cache` / `--cache-dir=<path>` | Disable or relocate the file-based response cache (24h TTL, on by default). |
| `--dry-run` | Assemble the prompt without calling the API. |
| `--help` | Full flag reference. |

## Suppression

If the user wants to silence a finding, choose **inline** for one-off cases and the **repo-wide ignore file** for systemic ones (vendored code, test fixtures).

Inline directive on the flagged line or up to 3 lines above:

```js
// security-audit-ignore: B-04 — internal URL, allowlisted upstream
const data = await fetch(internalUrl);
```

Recognised comment styles: `//`, `/* */`, `{/* */}` (JSX), `#` (Dockerfile / YAML), `<!-- -->` (HTML). Comma-separate multiple rule IDs. `*` matches any rule.

Repo-wide via `.security-audit-ignore` at repo root (gitignore-style globs + rule IDs):

```
vendor/legacy/**     R-01,R-05
**/__fixtures__/**   *
```

## Provider selection

| `ANTHROPIC_API_KEY` | `OPENAI_API_KEY` | Provider chosen |
|---|---|---|
| set | unset | Anthropic |
| unset | set | OpenAI |
| set | set | Anthropic (override with `--provider=openai`) |
| unset | unset | error — at least one key required |

Force a provider explicitly with `--provider=anthropic|openai` or `SECURITY_AUDIT_PROVIDER=...`. Pin an exact model id with `--model=<id>` for reproducibility — generation aliases (`sonnet`, `best`, etc.) track the latest release in each tier and will drift.

Defaults: Anthropic → `claude-sonnet-4-6`, OpenAI → `gpt-5`. For cheap runs use `--model=haiku` or `--model=cheap` respectively.

## Files in this skill

Files Claude may need to read while running the skill:

- `scripts/scan_diff.mjs` — main entry. Invoke this directly; do not bypass.
- `scripts/extract_diff.mjs` — pure git wrapper; emits structured diff JSON without any LLM call.
- `scripts/llm_analyze.mjs` — provider dispatcher; LLM-only entry point.
- `scripts/validate_finding.mjs` — schema validation, anti-hallucination, secret redaction.
- `scripts/suppression.mjs` — inline + repo-wide muting logic.
- `prompts/system.md` — system prompt sent to the LLM.
- `prompts/few_shot.md` — few-shot examples that anchor verdict discipline.
- `references/owasp-rules.md` — 41-rule catalog. Read this when the user asks "what does rule X-NN detect?" or "is pattern Y in the catalog?".
- `references/owasp-mapping.md` — OWASP → CWE → manifestation map.
- `references/report-schema.md` — output JSON schema, for downstream parsing.

If the user wants to add a new rule or check catalog drift, point them at `references/owasp-rules.md` and `scripts/__tests__/catalog_drift.test.mjs`.

## Common follow-ups

- **"Show me only the high-severity findings"** → re-run with `--fail-on=high` and read off the report; or filter `--format=json` output by `severity` and `verdict !== "FALSE_POSITIVE"`.
- **"Why was this flagged?"** → present `rationale`, `exploit_trace`, and the matching `rule_id` entry from `references/owasp-rules.md`.
- **"How do I fix it?"** → quote `remediation`. Include the OWASP Cheat Sheet link from the rule entry when present.
- **"How do I suppress this?"** → follow §Suppression. Recommend inline for one-off, repo-wide for whole directories.
- **"This is a false positive"** → confirm by checking the `evidence` line and surrounding context. If genuinely FP, suggest suppression with a reason in the directive comment so future reviewers see the justification.

## Out of scope

Redirect the user; do not attempt to extend this skill to:

- **Full-repository SAST** — use Semgrep, CodeQL.
- **Dependency CVEs** — use Dependabot, Snyk Open Source, OSV-Scanner, `npm audit`.
- **Runtime / DAST** — this is static analysis on a diff only.
- **Languages other than TS / JS / TSX / JSX / Dockerfile / docker-compose** — Python, Go, Java, Rust are unsupported.
- **OWASP A09 operational logging** — only the code-level diff-observable subset (rule B-16) is in catalog scope.
