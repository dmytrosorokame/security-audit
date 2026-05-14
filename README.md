# security-audit

> LLM-driven security review for git diffs. Reads only the changed lines, maps each finding to OWASP Top 10 (2021) + CWE, and blocks the dangerous ones at PR time.

[![test](https://github.com/dmytrosorokame/security-audit/actions/workflows/test.yml/badge.svg)](https://github.com/dmytrosorokame/security-audit/actions/workflows/test.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Unlike file-based SAST (Semgrep, ESLint plugin-security), security-audit looks **only at the diff** — added or modified lines with surrounding hunk context — and asks an LLM to reason about what the change introduces. Three properties fall out of that:

- **No legacy noise.** Findings are attributable to *this* PR, not to whoever wrote the file three years ago.
- **Semantic understanding.** The model sees the intent of the change. It can tell "added a sanitizer call" apart from "added `eval(req.body)`" even when both touch identical lines.
- **Cheap by design.** Real PRs are 50–200 lines. Prompt caching keeps the ~12k grounding tokens warm across calls. Average cost of a scan on `gpt-4o-mini` is around **$0.003**.

Provider-agnostic: works with **Anthropic Claude** (Sonnet / Haiku) or **OpenAI GPT** (gpt-4o, gpt-4o-mini, o-series). Pick whichever key you have — same prompts, same schema, same output formats.

## Live demo

A companion repo, [`dmytrosorokame/security-audit-demo`](https://github.com/dmytrosorokame/security-audit-demo), runs the action on **eight** reference pull requests — six that introduce a vulnerability, one that is a pure refactor, and one that demonstrates the inline-suppression mechanism. Each PR is publicly reproducible:

| # | PR | Pattern | Expected | Detected |
|---|---|---|---|---|
| 1 | [demo/01-dom-xss](https://github.com/dmytrosorokame/security-audit-demo/pull/1) | New `Bio.tsx` injects user HTML via `dangerouslySetInnerHTML` | R-01 / A03 / CWE-79 (high) | TP |
| 2 | [demo/02-ssrf](https://github.com/dmytrosorokame/security-audit-demo/pull/2) | Outbound proxy with allowlist removed | B-04 / A10 / CWE-918 (high) | TP |
| 3 | [demo/03-safe-refactor](https://github.com/dmytrosorokame/security-audit-demo/pull/3) | Extract auth middleware to its own module | — | TN (0 findings) |
| 4 | [demo/04-idor](https://github.com/dmytrosorokame/security-audit-demo/pull/4) | Route returns any user by id without ownership check | B-11 / A01 / CWE-639 (medium) | TP |
| 5 | [demo/05-sanitizer-removed](https://github.com/dmytrosorokame/security-audit-demo/pull/5) | DOMPurify wrapper removed before `dangerouslySetInnerHTML` | R-01 / A03 / CWE-79 (high) | TP |
| 6 | [demo/06-sqli](https://github.com/dmytrosorokame/security-audit-demo/pull/6) | Parameterized `ILIKE $1` swapped for template-literal concat, disguised as perf optimisation | B-01 / A03 / CWE-89 (critical) | TP |
| 7 | [demo/07-docker-root](https://github.com/dmytrosorokame/security-audit-demo/pull/7) | `Dockerfile` drops `USER app`, process runs as root | D-01 / A05 / CWE-250 (high) | TP |
| 8 | [demo/08-fp-suppress](https://github.com/dmytrosorokame/security-audit-demo/pull/8) | Admin cron with raw-SQL template literal that looks like B-01 but is sourced from module constants; inline `// security-audit-ignore: B-01` directive present | (B-01 suppressed) | TP→Suppressed |

**Local benchmark (smoke corpus, n=9 cases inside `benchmark/expected/`):** strict F1 = **0.909**, loose F1 = 0.909 (one persistent FN on `04_idor_ambiguous` at `seeds=1`, single-seed instability — see [`docs/INDEPENDENT_VALIDATION.md`](./docs/INDEPENDENT_VALIDATION.md)).
**Cross-corpus picture (cycle 6, gpt-4o-mini, seeds=1):** smoke 0.909 → independent 1.000 → complex 0.727 → oss_pilot 21% FP rate (TN-only). Full breakdown in [`benchmark/results.md`](./benchmark/results.md). A consolidated thesis-side rollup (`f1_table.md`) lives in the diploma appendix and is not committed to this repository — see `docs/INDEPENDENT_VALIDATION.md` for the validity threats and Stage 2 plan.

This is a regression-detection benchmark, not an unbiased generalisability measurement: the same author wrote both the rule catalog and the smoke diffs, three of ten few-shot examples mirror smoke cases 01/04/05, and all four corpora are single-author labelled with no inter-annotator agreement measured. Run `node benchmark/run_benchmark.mjs --seeds=3` against your own corpus before drawing conclusions.

## What it catches

34 vulnerability patterns mapped to OWASP Top 10 (2021):

- **Frontend (11 rules, R-01…R-11)** — DOM XSS via `dangerouslySetInnerHTML` / `innerHTML`, `target="_blank"` tabnabbing, `javascript:` URLs, prototype pollution, tokens in `localStorage`/`sessionStorage`, hardcoded secrets, open redirect via `window.location`, `postMessage` without origin check, missing CSP/SRI, CORS misconfiguration. Dependency-CVE scanning is out of scope — use Dependabot or Snyk for that.
- **Backend (15 rules, B-01…B-15)** — SQL injection (incl. ORM raw queries), command injection, NoSQL injection, SSRF across HTTP clients (fetch/axios/got/undici/superagent), path traversal, unsafe deserialization, weak crypto, missing CSRF/Helmet, hardcoded credentials in connection strings, IDOR, XXE, mass assignment, server-side open redirect, SSTI.
- **Container (8 rules, D-01…D-08)** — root user, `:latest` tag, hardcoded secrets in ENV/ARG, `ADD` vs `COPY`, privileged compose service, host network, docker.sock mount, unsafe `apt-get install`.

Full grounding catalog: [`references/owasp-rules.md`](./references/owasp-rules.md). Each rule includes OWASP/CWE IDs, severity, vulnerable + safe examples, confidence guidance, and a remediation reference.

## Install

Three entry points, one engine. Pick what fits your workflow.

### GitHub Action

`.github/workflows/security-audit.yml`:

```yaml
name: Security Audit
on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: dmytrosorokame/security-audit@main
        with:
          openai-api-key: ${{ secrets.OPENAI_API_KEY }}
          # or: anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          model: cheap          # cheap | best | sonnet | haiku | <full-id>
          fail-on: high         # critical | high | medium | low | info | none
          upload-sarif: 'true'  # populate the Security tab
```

Open a PR. Within ~30 seconds, security-audit posts a sticky comment with findings and blocks the merge if any finding is at or above `fail-on`.

### Anthropic Skill (Claude Code)

```bash
git clone https://github.com/dmytrosorokame/security-audit \
  ~/.claude/skills/security-audit
```

Trigger inside Claude Code with phrases like *"review this PR for security"*, *"audit my latest commit"*, or *"check this diff for OWASP issues"*. Skill manifest: [`SKILL.md`](./SKILL.md).

### CLI

```bash
git clone https://github.com/dmytrosorokame/security-audit && cd security-audit
pnpm install --ignore-workspace
export OPENAI_API_KEY=sk-...    # or ANTHROPIC_API_KEY

node scripts/scan_diff.mjs --against=origin/main
node scripts/scan_diff.mjs --staged                                   # pre-commit mode
node scripts/scan_diff.mjs --diff=patch.diff                          # external diff
node scripts/scan_diff.mjs --against=main --format=sarif --output=audit.sarif
```

## Output formats

The same JSON report drives four output channels:

| Format | Where it goes | Flag |
|---|---|---|
| `cli` | Terminal (human-readable, colorized) | `--format=cli` (default) |
| `pr` | GitHub PR comment (Markdown) | `--format=pr` |
| `sarif` | GitHub Code Scanning, security dashboards | `--format=sarif --output=…` |
| `json` | Pipe to anything | `--format=json` |

Each finding contains:

```json
{
  "rule_id": "R-01",
  "owasp_id": "A03:2021",
  "cwe_id": "CWE-79",
  "severity": "high",
  "confidence": "high",
  "verdict": "TRUE_POSITIVE",
  "risk_score": 7.5,
  "file": "src/client/components/Bio.tsx",
  "line": 17,
  "evidence": "<div dangerouslySetInnerHTML={{ __html: bioHtml }} />",
  "title": "DOM XSS via dangerouslySetInnerHTML with user-controlled input",
  "rationale": "The Bio component renders bioHtml (user-controlled) via dangerouslySetInnerHTML without sanitization.",
  "remediation": "Sanitize with DOMPurify.sanitize(bioHtml) before injecting, or switch to plain-text rendering."
}
```

`verdict` values:

- `TRUE_POSITIVE` — confirmed, exploitable as-is.
- `LIKELY_TP` — strong signal; exploitability depends on context outside the diff.
- `NEEDS_HUMAN` — pattern present but ambiguous; bias toward review.
- `FALSE_POSITIVE` — LLM ruled it out and explained why (rare; surfaced so you can audit the decision).

## How it works

```
  git diff ──▶ extract_diff.mjs ──▶ structured JSON ──▶ grounding (owasp-rules.md)
                                                              │
                                                              ▼
                                              ┌───────────────┴───────────────┐
                                              ▼                               ▼
                                  providers/anthropic.mjs            providers/openai.mjs
                              (cache_control + msg blocks)          (auto prefix cache + JSON mode)
                                              │                               │
                                              └───────────────┬───────────────┘
                                                              ▼
                                            validate_finding.mjs (file / line / evidence)
                                                              │
                                                              ▼
                                                  anti-hallucination pass
                                              (auto-correct context-line numbers
                                              to nearest added line; drop findings
                                              whose evidence is not in the diff)
                                                              │
                                                              ▼
                                                  suppression.mjs (inline
                                              directives + .security-audit-ignore)
                                                              │
                                                              ▼
                                                  secret redaction (AWS / Stripe /
                                              JWT / GitHub PAT / connection strings)
                                                              │
                                            ┌─────────┬───────┴────────┬─────────┐
                                            ▼         ▼                ▼         ▼
                                           CLI       PR              SARIF      JSON
```

The detection pipeline is deterministic everywhere except the LLM call. Extraction is `git diff`. Validation is JSON-schema checked. Formatting is template substitution. The LLM call uses `temperature=0` and prompt caching, so identical diffs against an unchanged grounding catalog converge on identical findings within the provider's cache window — about 5 minutes on Anthropic, prefix-cache on OpenAI.

Provider adapters live in `scripts/providers/`. Each implements one function — `analyze({groundingBlocks, userMessage, model, apiKey})` — and the dispatcher (`scripts/llm_analyze.mjs`) picks one based on `--provider` or which env key is set. Adding a third provider (Gemini, Mistral, a self-hosted model behind an OpenAI-compatible API) is roughly 120 lines and does not touch any other part of the pipeline.

## Provider auto-detection

When `--provider` is not specified, the tool picks from the environment:

| `ANTHROPIC_API_KEY` | `OPENAI_API_KEY` | Chosen provider |
|---|---|---|
| set | unset | Anthropic |
| unset | set | OpenAI |
| set | set | **Anthropic** (stderr notice; override with `--provider=openai` or `SECURITY_AUDIT_PROVIDER=openai`) |
| unset | unset | error — at least one key is required |

The Anthropic-on-tie default is a cost heuristic, not a quality claim: explicit `cache_control` markers give roughly 90% cache-read discount on the stable grounding prefix, vs. ~50% on OpenAI's automatic prefix cache. Once warm, that is a 2× cost difference per call. Both providers produce valid findings.

## Configuration

Suppress a single finding inline:

```js
// security-audit-ignore: B-04 — internal-only URL, allowlisted upstream
const data = await fetch(internalUrl);
```

Comment syntaxes recognised: `//`, `/* */`, `{/* */}` (JSX), `#` (Dockerfile / YAML), `<!-- -->` (HTML). The directive can be on the same line or up to 3 lines above the flagged code.

Suppress repo-wide via `.security-audit-ignore` — gitignore-style globs plus rule IDs:

```
# Legacy bundle we cannot fix yet
vendor/legacy/**     R-01,R-15

# Test fixtures intentionally contain XSS payloads
**/__fixtures__/**   *
```

Environment overrides:

```bash
ANTHROPIC_API_KEY=sk-...
OPENAI_API_KEY=sk-...

SECURITY_AUDIT_PROVIDER=anthropic   # auto (default) | anthropic | openai
SECURITY_AUDIT_MODEL=sonnet         # provider-specific alias or exact id
SECURITY_AUDIT_FAIL_ON=critical     # critical | high | medium | low | info | none
SECURITY_AUDIT_DEBUG=1              # verbose stderr
```

## Limitations

- **Diff-only context.** The model sees changed lines plus ~10 lines of context per hunk. Vulnerabilities that depend on global state (a sanitizer defined in another file, a middleware mounted elsewhere) may be misclassified.
- **One language ecosystem.** TS / JS / TSX / JSX + Dockerfile + docker-compose. Python / Go / Java / Rust are out of scope.
- **LLM variance.** `temperature=0` makes runs near-deterministic but not bit-identical across model versions. Pin a model id in CI for reproducibility.
- **Cost scales with diff size.** A 5000-line diff is expensive; the tool truncates to `--max-files=50` by default and warns on stderr.
- **3rd-party LLM API dependency.** No Anthropic or OpenAI key, no scan. Self-hosted alternatives (Ollama, vLLM, LiteLLM) are not yet supported.
- **A09 not covered.** OWASP A09 (Security Logging & Monitoring Failures) is operational, not code-level — most subcategories cannot be detected by reading source.

## Roadmap

- **Benchmark corpus** — 15–20 synthetic PRs against both providers (Anthropic + OpenAI), measuring F1 with seed variation, latency p50/p95, and cost. Comparison with Semgrep / Snyk Code on the same diffs.
- **Plugin manifest** — package as a Claude Code plugin (`.claude-plugin/plugin.json`) for `/plugins install dmytrosorokame/security-audit`.
- **`pull_request_target` mode** — secure handling of fork PRs (current `pull_request` event excludes forks for safety).
- **Self-hosted LLM adapter** — OpenAI-compatible API (vLLM, Ollama) for organisations that cannot use hosted models.
- **More language ecosystems** — Python and Go.

## License

MIT — see [LICENSE](./LICENSE).
