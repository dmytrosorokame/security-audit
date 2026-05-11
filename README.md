# security-audit

> **LLM-driven security review for git diffs.** Analyzes pull requests and pre-commit changesets with Claude, maps findings to OWASP Top 10 (2021) + CWE, blocks the dangerous ones.

[![test](https://github.com/dmytrosorokame/security-audit/actions/workflows/test.yml/badge.svg)](https://github.com/dmytrosorokame/security-audit/actions/workflows/test.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Unlike file-based SAST (Semgrep, ESLint plugin-security), security-audit reads **only the diff** — added or changed lines, with surrounding context — and asks Claude to reason about what the change actually introduces. Three properties fall out of that:

- **No legacy noise.** Findings are attributable to *this* PR, not to whoever wrote the file three years ago.
- **Semantic understanding.** Claude sees intent. It can tell apart "added a sanitizer call" from "added an `eval(req.body)`", even when both touch identical lines.
- **Cheap.** A 100-line diff costs ~$0.03 on Claude Sonnet 4.5 with prompt caching. Full-repo LLM scan would be $50+.

## What it catches

35 vulnerability patterns grounded in OWASP Top 10 (2021), covering:

- **Frontend (12 rules)**: DOM XSS, prototype pollution, insecure token storage, open redirects, missing CSP/SRI, postMessage misuse, `dangerouslySetInnerHTML`, `target="_blank"` tabnabbing, hardcoded secrets, CORS misconfiguration.
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

export ANTHROPIC_API_KEY=sk-...

scan-diff --against=main                       # diff vs origin/main
scan-diff --staged                             # current staged changes
scan-diff --diff=patch.diff                    # external diff file
scan-diff --against=main --format=sarif --output=audit.sarif
scan-diff --staged --fail-on=high --model=haiku
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
                  Claude (cached system + OWASP catalog + few-shot)
                                          │
                                          ▼
                           validated, normalized findings
                                          │
                  ┌───────────┬───────────┼───────────┐
                  ▼           ▼           ▼           ▼
                 CLI         PR        SARIF        JSON
```

The detection layer is **purely deterministic in everything except the model call**: extraction is `git diff`; validation is schema-checked; formatting is straightforward template substitution. The LLM call uses `temperature=0` and prompt caching, so identical diffs against an unchanged catalog converge on identical findings within an hour-long cache window.

Cost: a 100-line diff is roughly **3–5K input tokens (cached) + ~500 output tokens** → **$0.02–$0.04 per PR** on Sonnet 4.5, **$0.005–$0.01** on Haiku. Cold-cache cost is ~$0.05.

## Configuration

Suppress a single finding inline:

```js
// security-audit-ignore: B-04 — internal-only URL, allowlisted upstream
const data = await fetch(internalUrl);
```

Suppress repo-wide via `.security-audit-ignore` (planned, gitignore-style globs + rule IDs).

Override defaults via env:

```bash
ANTHROPIC_API_KEY=sk-...            # required for live runs
SECURITY_AUDIT_MODEL=sonnet         # sonnet (default) | haiku | <exact-model-id>
SECURITY_AUDIT_FAIL_ON=critical     # critical | high | medium | low | info | none
SECURITY_AUDIT_DEBUG=1              # verbose stderr
```

## Limitations

- **Diff-only context.** The model sees changed lines plus 10 lines of context per hunk by default. Vulnerabilities that depend on global state (e.g. a sanitizer defined in another file) may be misclassified. Increase `--context` or use `--include-file-context` (planned).
- **One language ecosystem.** TS/JS/TSX/JSX + Dockerfile + docker-compose. Python/Go/Java/Rust are out of scope.
- **LLM variance.** `temperature=0` makes runs near-deterministic but not bit-identical across model versions. Pin a model ID in CI for reproducibility.
- **Cost scales with diff size.** A 5000-line diff is expensive. The tool truncates to `--max-files=50` by default and warns on stderr.
- **3rd-party dependency on Anthropic.** No API key, no scan. Self-hosted alternatives are out of scope.
- **A09 not covered.** OWASP A09 (Logging & Monitoring Failures) is operational, not code-level — most subcategories cannot be detected by reading code alone.

## License

MIT — see [LICENSE](./LICENSE).
