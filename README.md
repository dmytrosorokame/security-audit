# security-audit

> LLM-driven security review for git diffs. Reads only the changed lines, maps each finding to OWASP Top 10 + CWE, and blocks the dangerous ones at PR time.

[![test](https://github.com/dmytrosorokame/security-audit/actions/workflows/test.yml/badge.svg)](https://github.com/dmytrosorokame/security-audit/actions/workflows/test.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Unlike file-based SAST (Semgrep, ESLint plugin-security), security-audit looks **only at the diff** — added or modified lines with surrounding hunk context — and asks an LLM to reason about what the change introduces. Three properties fall out of that:

- **No legacy noise.** Findings are attributable to *this* PR, not to whoever wrote the file three years ago.
- **Semantic understanding.** The model sees the intent of the change. It can tell "added a sanitizer call" apart from "added `eval(req.body)`" even when both touch identical lines.
- **Cheap by design.** Real PRs are 50–200 lines. Prompt caching keeps the ~12k grounding tokens warm across calls. Average cost of a scan ranges from **~$0.001** on a small model (gpt-5-mini / claude-haiku-4-5) to **~$0.01** on a flagship (gpt-5 / claude-sonnet-4-6).

Provider-agnostic: works with **Anthropic Claude** (Sonnet / Haiku / Opus) or **OpenAI GPT** (gpt-5, gpt-5-mini, gpt-4.1 family, gpt-4o legacy, o3/o4-mini reasoning). Pick whichever key you have — same prompts, same schema, same output formats.

## Live demo

A companion repo, [`dmytrosorokame/security-audit-demo`](https://github.com/dmytrosorokame/security-audit-demo), runs the action on **eight** reference pull requests — six that introduce a vulnerability, one that is a pure refactor, and one that demonstrates the inline-suppression mechanism. Each PR is publicly reproducible:

| # | PR | Pattern | Expected | Detected |
|---|---|---|---|---|
| 1 | [demo/01-dom-xss](https://github.com/dmytrosorokame/security-audit-demo/pull/1) | New `Bio.tsx` injects user HTML via `dangerouslySetInnerHTML` | R-01 / A05 / CWE-79 (high) | TP |
| 2 | [demo/02-ssrf](https://github.com/dmytrosorokame/security-audit-demo/pull/2) | Outbound proxy with allowlist removed | B-04 / A01 / CWE-918 (high) | TP |
| 3 | [demo/03-safe-refactor](https://github.com/dmytrosorokame/security-audit-demo/pull/3) | Extract auth middleware to its own module | — | TN (0 findings) |
| 4 | [demo/04-idor](https://github.com/dmytrosorokame/security-audit-demo/pull/4) | Route returns any user by id without ownership check | B-11 / A01 / CWE-639 (medium) | TP |
| 5 | [demo/05-sanitizer-removed](https://github.com/dmytrosorokame/security-audit-demo/pull/5) | DOMPurify wrapper removed before `dangerouslySetInnerHTML` | R-01 / A05 / CWE-79 (high) | TP |
| 6 | [demo/06-sqli](https://github.com/dmytrosorokame/security-audit-demo/pull/6) | Parameterized `ILIKE $1` swapped for template-literal concat, disguised as perf optimisation | B-01 / A05 / CWE-89 (critical) | TP |
| 7 | [demo/07-docker-root](https://github.com/dmytrosorokame/security-audit-demo/pull/7) | `Dockerfile` drops `USER app`, process runs as root | D-01 / A02 / CWE-250 (high) | TP |
| 8 | [demo/08-fp-suppress](https://github.com/dmytrosorokame/security-audit-demo/pull/8) | Admin cron with raw-SQL template literal that looks like B-01 but is sourced from module constants; inline `// security-audit-ignore: B-01` directive present | (B-01 suppressed) | TP→Suppressed |

**Current run (gpt-5, `--seeds=3`, cache auto-disabled):** smoke F1 = **0.933** (n=11, one persistent FN on `04_idor_ambiguous`) → independent F1 = **0.947** (n=10) → complex F1 = **0.909** (n=7). Full breakdown in [`benchmark/results.md`](./benchmark/results.md).

This is a regression-detection benchmark, not an unbiased generalisability measurement: the same author wrote both the rule catalog and the smoke diffs, three of ten few-shot examples mirror smoke cases 01/04/05, and all four corpora are single-author labelled with no inter-annotator agreement measured. Run `node benchmark/run_benchmark.mjs --seeds=3` against your own corpus before drawing conclusions.

## What it catches

41 rule-grounded vulnerability patterns, partitioned into three zones — **frontend** (R-01…R-11, 11 rules), **backend** (B-01…B-22, 22 rules), and **container** (D-01…D-08, 8 rules) — covering all 10 OWASP Top 10 (2025) categories.

Full grounding catalog with OWASP/CWE IDs, severities, vulnerable + safe code examples, confidence guidance, and remediation links: [`references/owasp-rules.md`](./references/owasp-rules.md). The academic rationale for using the catalog as LLM grounding (rather than as a regex filter) lives in [ADR-004](./docs/adr/004-catalog-grounding.md).

## Install

Three integration points share the same prompts, schema, and output formats — they differ only in *where* the verdict appears. Pick by use case:

| You want… | Use |
|---|---|
| A blocking check on every pull request, posted as a PR comment + SARIF on the Security tab | **GitHub Action** |
| Conversational review while you code, triggered by phrases like *"is this safe to merge"* | **Claude Code Skill** |
| One-off scan from a terminal, a pre-commit hook, or a script against an arbitrary unified diff | **CLI** |

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
          model: cheap          # cheap (gpt-5-mini / haiku) — fits most PRs
                                # best  (gpt-5 / sonnet)     — flagship, ~10× cost
                                # nano | reasoning | sonnet-4-5 | <pinned-id>
          fail-on: high         # critical | high | medium | low | info | none
          upload-sarif: 'true'  # populate the Security tab
```

Open a PR. Within ~30 seconds, security-audit posts a sticky comment with findings and blocks the merge if any finding is at or above `fail-on`.

### Claude Code Skill

Two commands inside Claude Code:

```
/plugin marketplace add dmytrosorokame/security-audit
/plugin install security-audit@security-audit-marketplace
```

Then in any subsequent session, trigger the skill with phrases like *"review this PR for security"*, *"audit my latest commit"*, *"is this safe to merge"*, or *"check this diff for OWASP issues"*. Claude Code matches the request to the skill description in [`SKILL.md`](./SKILL.md) and invokes the diff-mode pipeline.

The marketplace manifest lives at [`.claude-plugin/marketplace.json`](./.claude-plugin/marketplace.json); the plugin manifest at [`.claude-plugin/plugin.json`](./.claude-plugin/plugin.json) declares the allowed `bash` permissions (limited to `git diff *`, `node scripts/*`, `node benchmark/*`) and the env vars the skill reads (`ANTHROPIC_API_KEY` / `OPENAI_API_KEY` and the `SECURITY_AUDIT_*` overrides).

> **Manual fallback** (no marketplace): `git clone --depth=1 https://github.com/dmytrosorokame/security-audit ~/.claude/skills/security-audit && cd ~/.claude/skills/security-audit && pnpm install --ignore-workspace`. The clone tracks the whole repo; only `SKILL.md`, `scripts/`, `prompts/`, and `references/` are consumed at runtime — everything else (`benchmark/`, `docs/`, `examples/`) is academic scaffolding kept alongside for traceability.

### CLI

Use when you need to scan from a terminal — one-off audits, pre-commit hooks, scripting against an external diff file, or pulling SARIF into your own dashboard.

```bash
git clone https://github.com/dmytrosorokame/security-audit && cd security-audit
pnpm install --ignore-workspace
export OPENAI_API_KEY=sk-...    # or ANTHROPIC_API_KEY

node scripts/scan_diff.mjs --against=origin/main                     # PR-style review
node scripts/scan_diff.mjs --staged                                  # pre-commit mode
node scripts/scan_diff.mjs --diff=patch.diff                         # external diff
node scripts/scan_diff.mjs --against=main --format=sarif --output=audit.sarif
```

For `pre-commit` framework integration see [`.pre-commit-hooks.yaml`](./.pre-commit-hooks.yaml).

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
  "owasp_id": "A05",
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

Architectural decisions behind this pipeline shape — diff-only input, LLM-as-primary-analyzer, provider-agnostic dispatch, catalog as grounding, confidence calibration via `exploit_trace` — are documented in [`docs/adr/`](./docs/adr/) (ADR-001…ADR-005).

## Provider auto-detection

When `--provider` is not specified, the tool picks from the environment:

| `ANTHROPIC_API_KEY` | `OPENAI_API_KEY` | Chosen provider |
|---|---|---|
| set | unset | Anthropic |
| unset | set | OpenAI |
| set | set | **Anthropic** (stderr notice; override with `--provider=openai` or `SECURITY_AUDIT_PROVIDER=openai`) |
| unset | unset | error — at least one key is required |

The Anthropic-on-tie default is a historical cost heuristic, not a quality claim: explicit `cache_control` markers give a ~90% cache-read discount on the stable grounding prefix. OpenAI's gpt-5 family now lands at ~90% as well (cached input ≈ 10× cheaper than uncached), so the per-call gap on the default flagship is small. The tie still resolves to Anthropic for backward compatibility; pin `--provider=openai` or `SECURITY_AUDIT_PROVIDER=openai` if you prefer GPT. Both providers produce valid findings.

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
vendor/legacy/**     R-01,R-10

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

## Scope at a glance

security-audit is an **incremental guardrail on pull-request diffs**, not a full security audit. Out-of-scope categories that the tool will not handle (use the listed alternatives):

- Full-repository SAST → Semgrep, CodeQL, Snyk Code.
- Dependency / package CVEs → Dependabot, Snyk Open Source, OSV-Scanner, `npm audit`.
- Runtime / DAST and architectural threat modelling.
- Languages other than TS / JS / TSX / JSX + Dockerfile + docker-compose.

Threats to validity and the validation roadmap are documented in [`docs/INDEPENDENT_VALIDATION.md`](./docs/INDEPENDENT_VALIDATION.md).

## License

MIT — see [LICENSE](./LICENSE).
