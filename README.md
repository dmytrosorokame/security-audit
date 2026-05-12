# security-audit

> **LLM-driven security review for git diffs.** Analyzes pull requests and pre-commit changesets with Claude or GPT, maps findings to OWASP Top 10 (2021) + CWE, blocks the dangerous ones.

[![test](https://github.com/dmytrosorokame/security-audit/actions/workflows/test.yml/badge.svg)](https://github.com/dmytrosorokame/security-audit/actions/workflows/test.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Unlike file-based SAST (Semgrep, ESLint plugin-security), security-audit reads **only the diff** — added or changed lines, with surrounding context — and asks an LLM to reason about what the change actually introduces. Three properties fall out of that:

- **No legacy noise.** Findings are attributable to *this* PR, not to whoever wrote the file three years ago.
- **Semantic understanding.** The model sees intent. It can tell apart "added a sanitizer call" from "added an `eval(req.body)`", even when both touch identical lines.
- **Cheap by design.** Diffs are small (typically 50–200 lines); prompt caching keeps grounding tokens warm across PRs. Full-repo LLM scan would be prohibitively expensive by comparison.

**Provider-agnostic**: works with **Anthropic Claude** (Sonnet/Haiku/Opus) or **OpenAI GPT** (gpt-4o, gpt-4o-mini, o-series). Pick whichever you have an API key for; the same prompts, schema, and output formats apply.

## What it catches

34 vulnerability patterns grounded in OWASP Top 10 (2021), covering:

- **Frontend (11 rules)**: DOM XSS, prototype pollution, insecure token storage, open redirects, missing CSP/SRI, postMessage misuse, `dangerouslySetInnerHTML`, `target="_blank"` tabnabbing, hardcoded secrets, CORS misconfiguration. (Dependency-CVE scanning is out of scope — use Dependabot or Snyk for that.)
- **Backend (15 rules)**: SQL injection (incl. ORM raw queries), command injection, NoSQL injection, SSRF across all HTTP clients (fetch/axios/got/undici/superagent/http.request), path traversal, unsafe deserialization, weak crypto, missing CSRF/Helmet, hardcoded credentials, IDOR, XXE, mass assignment, server-side open redirect, server-side template injection (SSTI).
- **Container (8 rules)**: root user, latest tag, hardcoded secrets in ENV, `ADD` vs `COPY`, privileged compose service, host network, docker.sock mount, unsafe apt-get.

Full catalog: [`references/owasp-rules.md`](./references/owasp-rules.md).

## Install

Four entry points, one engine. Pick what fits.

### GitHub Action (PR review)

`.github/workflows/security-audit.yml`:

```yaml
name: Security Audit
on: [pull_request]

permissions:
  contents: read
  pull-requests: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: dmytrosorokame/security-audit@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          # or:
          # openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          fail-on: critical
```

Open a PR. Within ~30 seconds, security-audit posts a sticky comment with findings (file:line, OWASP/CWE labels, severity, remediation).

### Pre-commit hook (block before push)

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/dmytrosorokame/security-audit
    rev: v0.1.0
    hooks:
      - id: security-audit-diff
```

```bash
pre-commit install
export ANTHROPIC_API_KEY=sk-...

# Now `git commit` runs security-audit on staged changes.
# Blocks the commit if any finding is at or above $SECURITY_AUDIT_FAIL_ON (default: critical).

# Bypass once:
SECURITY_AUDIT_SKIP=1 git commit -m '...'
```

### npm CLI

```bash
npm install -g security-audit

# Pick a provider — set whichever key you have:
export ANTHROPIC_API_KEY=sk-...      # Claude
export OPENAI_API_KEY=sk-...         # GPT

scan-diff --against=main                                          # auto-pick provider, diff vs origin/main
scan-diff --staged                                                # staged changes (pre-commit mode)
scan-diff --diff=patch.diff                                       # external diff file
scan-diff --against=main --format=sarif --output=audit.sarif      # SARIF for GitHub Code Scanning

# Pick provider / model explicitly:
scan-diff --against=main --provider=anthropic --model=haiku       # cheap Claude
scan-diff --against=main --provider=openai    --model=cheap       # cheap GPT (gpt-4o-mini)
scan-diff --against=main --provider=openai    --model=best        # gpt-4o
scan-diff --against=main --provider=openai    --model=o3-mini     # reasoning model

# Inspect what each provider supports:
scan-diff --help
node node_modules/security-audit/scripts/llm_analyze.mjs --list-models
```

### Anthropic Skill (Claude Code)

```bash
git clone https://github.com/dmytrosorokame/security-audit \
  ~/.claude/skills/security-audit
```

Trigger inside Claude Code with phrases like *"review this PR for security"*, *"audit my latest commit"*, *"check this diff for OWASP issues"*. Skill manifest: [`SKILL.md`](./SKILL.md).

## Output formats

The same JSON report drives three output channels:

| Format     | Where it goes                          | Command                                     |
|------------|----------------------------------------|---------------------------------------------|
| `cli`      | Terminal (human-readable, colorized)   | `scan-diff … --format=cli` (default)        |
| `pr`       | GitHub PR comment (Markdown)           | `scan-diff … --format=pr`                   |
| `sarif`    | GitHub Code Scanning, security dashboards | `scan-diff … --format=sarif --output=…`  |
| `json`     | Pipe to anything                       | `scan-diff … --format=json`                 |

Each finding contains:

```json
{
  "rule_id": "R-02",
  "owasp_id": "A03:2021",
  "cwe_id": "CWE-79",
  "severity": "high",
  "confidence": "high",
  "verdict": "TRUE_POSITIVE",
  "risk_score": 7.5,
  "file": "apps/web/src/Comment.tsx",
  "line": 13,
  "evidence": "el.innerHTML = comment.body",
  "title": "DOM XSS via innerHTML with user-supplied comment body",
  "rationale": "...",
  "remediation": "Use JSX text interpolation or DOMPurify.sanitize. See https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
}
```

`verdict` is one of:

- `TRUE_POSITIVE` — confirmed, exploitable as-is
- `LIKELY_TP` — strong signal, exploitability depends on context outside the diff
- `NEEDS_HUMAN` — pattern present but ambiguous; bias toward review
- `FALSE_POSITIVE` — LLM ruled out (rare; surfaces explicitly so you can audit it)

## How it works

```
  git diff ──▶ extract_diff.mjs ──▶ structured JSON
                                          │
                                          ▼
                                 ┌────────┴────────┐
                                 ▼                 ▼
                     providers/anthropic.mjs  providers/openai.mjs
                  (cache_control + msg blocks)  (auto-cache + JSON mode)
                                 │                 │
                                 └────────┬────────┘
                                          ▼
                           validated, normalized findings
                                          │
                  ┌───────────┬───────────┼───────────┐
                  ▼           ▼           ▼           ▼
                 CLI         PR        SARIF        JSON
```

The detection layer is **purely deterministic in everything except the model call**: extraction is `git diff`; validation is schema-checked; formatting is straightforward template substitution. The LLM call uses `temperature=0` and prompt caching, so identical diffs against an unchanged catalog converge on identical findings within the provider's cache window (5 min on Anthropic, prefix-cache on OpenAI).

Provider adapters live in `scripts/providers/`. Each implements one function — `analyze({groundingBlocks, userMessage, model, apiKey})` — and the dispatcher (`scripts/llm_analyze.mjs`) picks one based on `--provider` or which env key is set. Adding a third provider (e.g. Gemini) is ~120 lines and does not touch any other part of the pipeline.

**Per-run telemetry**. Every JSON report carries `cost`, `latency_ms`, and a `usage` block (input/output/cached tokens). Use these for your own pricing analysis — published cost figures will be added once we have measured benchmarks (see `benchmark/`).

## Provider auto-detection

When `--provider` is not specified, the tool picks from environment:

| ANTHROPIC_API_KEY | OPENAI_API_KEY | Chosen provider |
|---|---|---|
| set | unset | **Anthropic** |
| unset | set | **OpenAI** |
| set | set | **Anthropic** (emits stderr notice) |
| unset | unset | error: at least one key required |

**Why Anthropic on tie**: explicit `cache_control` markers give roughly 90% cache-read discount on the ~12K stable grounding tokens, versus ~50% on OpenAI's automatic prefix cache. Once the cache is warm, that's a 2× cost difference for the same call. This is a heuristic about cost, not quality — both providers produce valid findings.

**Override**: pass `--provider=openai`, or set `SECURITY_AUDIT_PROVIDER=openai`. The stderr notice is suppressed in non-interactive environments unless `SECURITY_AUDIT_DEBUG=1`.

## Configuration

Suppress a single finding inline:

```js
// security-audit-ignore: B-04 — internal-only URL, allowlisted upstream
const data = await fetch(internalUrl);
```

Suppress repo-wide via `.security-audit-ignore` (planned, gitignore-style globs + rule IDs).

Override defaults via env:

```bash
# Pick at least one provider key:
ANTHROPIC_API_KEY=sk-...
OPENAI_API_KEY=sk-...

# Optional configuration:
SECURITY_AUDIT_PROVIDER=anthropic   # auto (default) | anthropic | openai
SECURITY_AUDIT_MODEL=sonnet         # provider-specific alias or exact id
SECURITY_AUDIT_FAIL_ON=critical     # critical | high | medium | low | info | none
SECURITY_AUDIT_DEBUG=1              # verbose stderr
```

## Limitations

- **Diff-only context.** The model sees changed lines plus 10 lines of context per hunk by default. Vulnerabilities that depend on global state (e.g. a sanitizer defined in another file) may be misclassified. Increase `--context` or use `--include-file-context` (planned).
- **One language ecosystem.** TS/JS/TSX/JSX + Dockerfile + docker-compose. Python/Go/Java/Rust are out of scope.
- **LLM variance.** `temperature=0` makes runs near-deterministic but not bit-identical across model versions. Pin a model ID in CI for reproducibility.
- **Cost scales with diff size.** A 5000-line diff is expensive. The tool truncates to `--max-files=50` by default and warns on stderr.
- **3rd-party LLM API dependency.** No Anthropic *or* OpenAI key, no scan. Self-hosted alternatives (Ollama, vLLM, LiteLLM) are not yet supported.
- **A09 not covered.** OWASP A09 (Logging & Monitoring Failures) is operational, not code-level — most subcategories cannot be detected by reading code alone.

## License

MIT — see [LICENSE](./LICENSE).
