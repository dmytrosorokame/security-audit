---
name: security-audit
description: Reviews a git diff (pull request, staged commit, or arbitrary unified diff) for security vulnerabilities. Returns structured findings mapped to OWASP Top 10 (2021) and CWE, each with severity, confidence, evidence, risk score (0–10), verdict (TRUE_POSITIVE / LIKELY_TP / NEEDS_HUMAN / FALSE_POSITIVE), and remediation. Covers XSS, SQL/NoSQL/command injection, SSRF, IDOR, XXE, SSTI, mass assignment, prototype pollution, insecure storage, open redirects, missing CSP/CSRF/Helmet, weak crypto, hardcoded secrets, and Docker/compose misconfigurations. Unlike file-based SAST, it reads only the changed lines so it ignores legacy noise and reasons about the intent of the change. Use when the user asks to audit, review, or check the security of a PR, a commit, a branch, or a diff — e.g. "review this PR", "is this safe to merge", "scan my staged changes", "OWASP review". Node.js agent (`scripts/scan_diff.mjs`) running on TypeScript/JavaScript/TSX/JSX/Dockerfile/docker-compose with pluggable LLM providers (Anthropic Claude or OpenAI GPT).
---

# Security Audit Skill — diff-mode LLM agent

A deterministic pipeline for security auditing of **git diffs** (pull request, pre-commit, arbitrary diff), using an LLM as the primary analyzer with mapping to OWASP Top 10 (2021) and CWE.

**Provider-agnostic**: built-in adapters for Anthropic Claude and OpenAI GPT. Selected via `--provider=auto|anthropic|openai` or automatically from the env key present. Same prompt, schema, and output formats regardless of provider.

## Purpose

Unlike file-based SAST (Semgrep, ESLint plugin-security), this skill analyses **only the changed code**:

- The LLM understands the **intent** of the change, not just static patterns.
- It does not flag legacy noise (pre-existing vulnerabilities — not introduced by this PR).
- Small diffs → cheap LLM calls (~$0.003 per average PR on gpt-4o-mini with prompt caching).
- It catches semantic flaws (IDOR with missing authz check, mass-assignment intent) that AST patterns miss.

Each finding contains:
- `rule_id` — `R-XX` (FE), `B-XX` (BE), `D-XX` (Docker) from the catalog, or `NEW_PATTERN` if none matches
- `owasp_id` — OWASP Top 10 Web (2021) category, e.g. `A03:2021`
- `cwe_id` — CWE ID, e.g. `CWE-79`
- `severity` — `critical | high | medium | low | info`
- `confidence` — `high | medium | low`
- `risk_score` — 0.0–10.0 number (CVSS-like)
- `verdict` — `TRUE_POSITIVE | LIKELY_TP | NEEDS_HUMAN | FALSE_POSITIVE`
- `file:line` — exact location in the new revision of the code
- `evidence` — verbatim diff fragment
- `remediation` — concrete fix + link to the relevant OWASP Cheat Sheet

## Workflow (4 phases)

### Phase 1 — Trigger detection and scope

Determine what to audit:

1. **GitHub Action mode** (default in CI): `pull_request` event → diff = `git diff origin/<base>...HEAD`
2. **Pre-commit mode** (local): diff = `git diff --cached`
3. **CLI mode** (manual): `--against=<ref>` or `--diff=<file>`
4. **Skill mode** (inside Claude Code): the user asks "review this PR" → the agent invokes `extract_diff` itself

### Phase 2 — Diff extraction

```sh
node ${SKILL_DIR}/scripts/extract_diff.mjs --against=main --context=10
```

Optional parameters:
- `--context=N` — N context lines around each change (default 10)
- `--include='**/*.ts'` — restrict to file glob patterns
- `--exclude='**/*.test.ts'` — exclude patterns (defaults: tests, node_modules, dist)
- `--max-files=50` — cap on the number of changed files

Output: JSON `{files: [{path, hunks: [{old_start, old_lines, new_start, new_lines, content}]}]}`.

### Phase 3 — LLM-driven analysis

```sh
# Anthropic Claude (default if ANTHROPIC_API_KEY set)
node ${SKILL_DIR}/scripts/llm_analyze.mjs --diff=<diff.json> --provider=anthropic --model=sonnet

# OpenAI GPT
node ${SKILL_DIR}/scripts/llm_analyze.mjs --diff=<diff.json> --provider=openai --model=best
```

The dispatcher (`scripts/llm_analyze.mjs`) selects a provider from `--provider` or from env (`ANTHROPIC_API_KEY` → anthropic, `OPENAI_API_KEY` → openai), then delegates to `scripts/providers/<name>.mjs`.

Each provider receives:

1. **System prompt** (`prompts/system.md`) — OWASP/CWE framework and rules for analysing a diff
2. **References** — inlined `references/owasp-rules.md` (catalog of 34 patterns) and `references/owasp-mapping.md`
3. **Few-shot** (`prompts/few_shot.md`) — 10 input/output examples covering DOM XSS, SSRF, safe refactor (TN), ambiguous IDOR (`NEEDS_HUMAN`), sanitizer removal, self-critique downgrade (FP catch), prototype pollution, repository-pattern TN, NoSQL injection, sanitizer-shape API relaxation
4. **User message** — the extracted diff JSON

Provider-specific details:
- **Anthropic** — system blocks array + `cache_control: ephemeral` on the last block (~90% cache-read discount), JSON via prompt engineering
- **OpenAI** — single system message string + automatic prefix caching (~50% discount), JSON via `response_format: { type: 'json_object' }`

Temperature: 0 for reproducibility.

Default models:
- anthropic → `claude-sonnet-4-6` (alias `sonnet`); pin `--model=sonnet-4-5` for reproducibility against cycle-6 numbers, or `--model=haiku` for cheaper runs
- openai → `gpt-4o` (alias `best`); use `--model=cheap` for gpt-4o-mini

Output: normalised JSON `{ schema_version, findings: [...], summary, provider, model, cost, latency_ms, usage }`.

### Phase 4 — Validation, scoring, formatting

1. `scripts/validate_finding.mjs` — validates each finding against the schema (valid `owasp_id`, `cwe_id`, `severity`, etc.)
2. `scripts/risk_score.mjs` — computes a CVSS-like `risk_score` from `severity × confidence × verdict`
3. Output format — caller's choice:
   - `format_pr_comment.mjs` — Markdown for a GitHub PR (default in Action mode)
   - `format_sarif.mjs` — SARIF 2.1.0 for GitHub Code Scanning
   - `format_cli.mjs` — human-readable terminal output (default in CLI mode)
4. Exit code:
   - `0` — no findings above the threshold
   - `1` — findings present but severity below `--fail-on`
   - `2` — at least one finding ≥ `--fail-on` (default `critical`)
   - `3` — tool error

## Principles

- **LLM as primary analyzer**: the verdict comes from the LLM (Claude / GPT), not from AST rules. AST verification is out of scope — the pipeline relies on the model's semantic understanding plus deterministic post-processing (`validate_finding.mjs`).
- **Diff-focused**: report only on added or modified lines. Context (`-U10`) is for understanding, not reporting.
- **Grounded reasoning**: every finding must map to a rule from `references/owasp-rules.md` or be labelled `NEW_PATTERN`.
- **Structured output**: JSON is schema-validated; formatters are deterministic.
- **Verdict transparency**: `NEEDS_HUMAN` beats an over-confident `FALSE_POSITIVE` — we do not hide uncertainty.
- **Progressive disclosure**: small diffs → short system prompt without the full catalog inlined; large diffs → catalog inlined for grounding.

## Skill structure

```
security-audit/
  SKILL.md                          ← this file
  README.md                         ← quick start + install
  package.json                      ← bin: scan-diff, security-audit
  action.yml                        ← GitHub Action composite
  .pre-commit-hooks.yaml            ← pre-commit framework entry
  prompts/
    system.md                       ← OWASP-grounded system prompt
    few_shot.md                     ← input/output examples
  scripts/
    extract_diff.mjs                ← git diff wrapper, no API
    scan_diff.mjs                   ← main orchestrator (entry)
    llm_analyze.mjs                 ← provider-agnostic dispatcher
    providers/
      _common.mjs                   ← shared utils (JSON extraction, errors)
      anthropic.mjs                 ← Claude adapter (Anthropic SDK + cache_control)
      openai.mjs                    ← GPT adapter (OpenAI SDK + auto-cache + JSON mode)
    validate_finding.mjs            ← output schema validator
    format_pr_comment.mjs           ← markdown for PR
    format_sarif.mjs                ← SARIF 2.1.0
    format_cli.mjs                  ← terminal output
    risk_score.mjs                  ← CVSS-like risk score
  references/
    owasp-rules.md                  ← 34 vulnerability patterns (LLM grounding, no AST artifacts)
    owasp-mapping.md                ← OWASP→CWE map
    report-schema.md                ← finding JSON schema
  ci/
    github-action.yml               ← workflow template for users
    setup.md                        ← integration guide
  benchmark/
    diff_corpus/                    ← synthetic diffs + ground truth
    run_benchmark.mjs               ← orchestrator: runs scan_diff on examples and compares vs expected
    expected/                       ← ground-truth JSON for each example diff
    results.md                      ← latest benchmark output (committed)
  examples/                         ← representative vulnerable/safe samples
  vitest.config.mjs                 ← Vitest config (ESM, coverage)
  scripts/__tests__/                ← unit tests (Vitest)
  .github/workflows/
    test.yml                        ← CI for the tool itself
    release.yml
```

## Limitations

- Covers JS/TS/TSX/JSX (FE: React/Vue/Svelte components; BE: Express/Koa/NestJS/Fastify) + Dockerfile + docker-compose YAML. Other languages (Go, Python, Rust) are out of scope.
- Analyses **only the diff**, not full file context. Vulnerabilities that depend on global state outside the diff may be missed. Mitigation: the `--include-file-context` flag attaches full-file content for critical hunks.
- Not a DAST replacement — diff-only static analysis.
- LLMs have inherent variance — `temperature: 0` gives near-deterministic output, but some stochasticity remains. For deterministic CI, use cached responses via `--cache-dir`.
- Token cost scales with diff size. Large PRs (>500 changed lines) are chunked per file and aggregated.
- Requires `ANTHROPIC_API_KEY` (paid Anthropic) **or** `OPENAI_API_KEY` (paid OpenAI). Self-hosted models (Ollama, vLLM, LiteLLM) are out of scope; they can be added as a new provider in `scripts/providers/`.

## References

- OWASP Top 10 (2021): https://owasp.org/Top10/
- CWE: https://cwe.mitre.org/
- OWASP Cheat Sheets: https://cheatsheetseries.owasp.org/
- SARIF 2.1.0 specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
- Anthropic SDK: https://github.com/anthropics/anthropic-sdk-typescript
