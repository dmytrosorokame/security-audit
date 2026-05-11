# Setup guide

security-audit ships with **four entry points** and **two LLM providers** (Anthropic Claude or OpenAI GPT). Pick whichever combination fits.

## Choosing a provider

Provider is selected automatically based on which env var / GitHub secret is set. To force one, pass `--provider=anthropic` or `--provider=openai` on the CLI, or the `provider` input in the GitHub Action.

| Provider | Default model | Cheapest model | Cache discount | Best for |
|---|---|---|---|---|
| Anthropic | `claude-sonnet-4-5` (`sonnet`) | `claude-haiku-4-5` (`haiku`) | ~90% (5-min TTL) | Highest cache savings; strong JSON discipline via prompt |
| OpenAI | `gpt-4o` (`best`) | `gpt-4o-mini` (`cheap`) | ~50% (auto prefix cache) | Cheapest cold-cache runs; strict JSON mode via `response_format` |

You can use both — set both env vars and pass `--provider=anthropic` or `--provider=openai` per call.

---

## 1. GitHub Action — review every PR

**Best for**: teams using GitHub. Automatic on every PR.

1. Add `ANTHROPIC_API_KEY` **and/or** `OPENAI_API_KEY` to your repo secrets (Settings → Secrets and variables → Actions → New repository secret).
2. Copy [`ci/github-action.yml`](./github-action.yml) into your repo at `.github/workflows/security-audit.yml`.
3. Open a PR. Within ~30s, security-audit posts a sticky comment with findings (or "no issues found").

Tunable inputs are documented at the top of the workflow file. The action's `provider:` input defaults to `auto` (uses whichever key is present).

---

## 2. Pre-commit hook — block locally before push

**Best for**: catching critical issues before they leave the developer's machine.

Requires the [`pre-commit`](https://pre-commit.com/) framework (`pip install pre-commit` or `brew install pre-commit`).

Add to your repo's `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/dmytrosorokame/security-audit
    rev: v0.1.0   # pin to a tag
    hooks:
      - id: security-audit-diff
```

Then install the hook:

```bash
pre-commit install
```

Configure via env:

```bash
# Pick at least one (or both):
export ANTHROPIC_API_KEY=sk-...              # use Claude (default if both are set)
export OPENAI_API_KEY=sk-...                 # use GPT

# Optional:
export SECURITY_AUDIT_PROVIDER=openai        # force a specific provider
export SECURITY_AUDIT_FAIL_ON=critical       # default
export SECURITY_AUDIT_MODEL=cheap            # anthropic: haiku | openai: cheap (gpt-4o-mini)

# One-time bypass:
SECURITY_AUDIT_SKIP=1 git commit -m 'wip'
```

Inline suppression: add a comment on the line above the flagged construct:

```js
// security-audit-ignore: B-04 — internal-only URL, allowlisted upstream
const data = await fetch(internalUrl);
```

---

## 3. npm CLI — ad-hoc scans

**Best for**: scripting and one-off local audits.

```bash
npm install -g security-audit
# or: npx security-audit ...

# Pick at least one (or both):
export ANTHROPIC_API_KEY=sk-...
export OPENAI_API_KEY=sk-...

scan-diff --against=main                                   # diff vs origin/main (auto provider)
scan-diff --staged                                         # current staged changes
scan-diff --diff=patch.diff                                # external diff file
scan-diff --against=main --format=pr                       # markdown for a PR comment
scan-diff --against=main --format=sarif --output=audit.sarif
scan-diff --staged --fail-on=high --provider=anthropic --model=haiku
scan-diff --staged --fail-on=high --provider=openai    --model=cheap
```

`security-audit` is the same binary, aliased.

---

## 4. Anthropic Skill — conversational review

**Best for**: ad-hoc review inside Claude Code or any Claude Agent SDK harness.

```bash
git clone https://github.com/dmytrosorokame/security-audit ~/.claude/skills/security-audit
```

Then in Claude Code, the skill triggers automatically on phrases like:

> review this PR for security
> audit my latest commit
> check this diff for OWASP issues

---

## Severity gate cheat sheet

`--fail-on=<sev>` (or `SECURITY_AUDIT_FAIL_ON`) controls when the tool blocks.

| Setting | Blocks on |
|---|---|
| `critical` | only critical findings (RCE, SQL injection, hardcoded secrets) |
| `high` | critical + high (XSS, SSRF, IDOR, XXE, …) |
| `medium` | adds missing security headers, weak crypto |
| `low` | adds best-practice deviations |
| `info` | reports everything, blocks on everything |
| `none` | report only, never block |

Default is `critical`.
