---
name: security-audit
description: Reviews git diffs (pull request, staged commit, or arbitrary diff text) for security vulnerabilities using an LLM (Claude via Anthropic, or GPT via OpenAI — configurable per-call) as the primary analyzer. Performs LLM-driven semantic analysis grounded in the OWASP Top 10 (2021) and CWE taxonomies. Detects client-side vulnerabilities (DOM XSS, prototype pollution, insecure token storage, open redirects, missing CSP/SRI, postMessage misuse, dangerous innerHTML), server-side vulnerabilities (SQL injection incl. ORM raw queries, command injection, NoSQL injection, SSRF across all HTTP clients, path traversal, unsafe deserialization, weak crypto, missing CSRF/Helmet, hardcoded credentials, IDOR, XXE, mass assignment, server-side open redirect, server-side template injection / SSTI), and container/deployment misconfigurations (root user, latest tag, hardcoded secrets in ENV, ADD vs COPY, privileged compose service, host network, docker.sock mount, unsafe apt-get). Unlike file-based SAST tools, this skill focuses on the changeset itself — it sees only what is being added, modified, or removed in a diff, which eliminates legacy-code noise and lets the LLM reason about the intent of the change. Maps each finding to an OWASP Top 10 (2021) category and a CWE ID, computes a CVSS-like risk score (0-10), assigns a verdict (TRUE_POSITIVE / LIKELY_TP / NEEDS_HUMAN / FALSE_POSITIVE), and produces output in multiple formats (markdown PR comment, SARIF 2.1.0, CLI JSON). Use when the user asks to audit, review, scan, or check the security of a pull request, a commit, a diff, or recent code changes. Trigger phrases include "review this PR", "audit this commit", "security review on diff", "check this changeset for vulnerabilities", "is this PR safe to merge", "scan staged changes", "OWASP review of my branch". Implemented as a Node.js agent that extracts diffs via `git diff`, dispatches to a provider adapter (`scripts/providers/anthropic.mjs` using the Anthropic SDK with prompt-caching, or `scripts/providers/openai.mjs` using the OpenAI SDK with JSON-object response mode and automatic prefix caching), validates structured JSON output against a schema, and formats results for the chosen output channel. Grounding knowledge lives in `references/owasp-rules.md` (35 vulnerability patterns), `references/owasp-mapping.md` (OWASP→CWE), and `references/report-schema.md` (output schema). Optimized for TypeScript/JavaScript/TSX/JSX/Dockerfile/docker-compose stacks.
---

# Security Audit Skill — diff-mode LLM agent

Дитермінований pipeline для аудиту безпеки **git diff-ів** (pull request, pre-commit, arbitrary diff) на основі LLM як primary analyzer, з мапінгом до OWASP Top 10 (2021) і CWE.

**Provider-agnostic**: вбудовані адаптери для Anthropic Claude і OpenAI GPT. Вибирається через `--provider=auto|anthropic|openai` або автоматично з наявного env key. Той самий prompt, schema, output формати — незалежно від провайдера.

## Призначення

На відміну від file-based SAST (Semgrep, ESLint plugin-security), цей скіл аналізує **тільки те, що змінилось у коді**:

- LLM розуміє **намір** зміни, а не лише статичні patterns
- Не реєструє legacy-noise (старі вразливості, які існували до PR — не його провина)
- Малі diffs → дешеві LLM-калли (~$0.03 на середній PR)
- Знаходить semantic flaws (IDOR без authz check, mass-assignment intent), які AST-патерни пропускають

Кожна знахідка має:
- `rule_id` — `R-XX` (FE), `B-XX` (BE), `D-XX` (Docker) з catalogу, або `NEW_PATTERN` якщо нова
- `owasp_id` — категорія OWASP Top 10 Web (2021), напр. `A03:2021`
- `cwe_id` — CWE-ID, напр. `CWE-79`
- `severity` — `critical | high | medium | low | info`
- `confidence` — `high | medium | low`
- `risk_score` — число 0.0–10.0 (CVSS-like)
- `verdict` — `TRUE_POSITIVE | LIKELY_TP | NEEDS_HUMAN | FALSE_POSITIVE`
- `file:line` — точне розташування у новій версії коду
- `evidence` — фрагмент diff
- `remediation` — конкретна правка + посилання на OWASP Cheat Sheet

## Workflow (4 фази)

### Фаза 1 — Trigger detection та scope

Зчитати, що саме треба аудитувати:

1. **GitHub Action mode** (за замовчуванням у CI): event `pull_request` → diff = `git diff origin/<base>...HEAD`
2. **Pre-commit mode** (локально): diff = `git diff --cached`
3. **CLI mode** (manual): `--against=<ref>` або `--diff=<file>`
4. **Skill mode** (всередині Claude Code): користувач питає "перевір цей PR" → агент сам викликає extract_diff

### Фаза 2 — Diff extraction

```sh
node ${SKILL_DIR}/scripts/extract_diff.mjs --against=main --context=10
```

Опціональні параметри:
- `--context=N` — N рядків контексту довкола кожної зміни (за замовчуванням 10)
- `--include='**/*.ts'` — обмежити патернами файлів
- `--exclude='**/*.test.ts'` — виключити патерни (за замовчуванням: tests, node_modules, dist)
- `--max-files=50` — обмежити кількість змінених файлів

Output: JSON `{files: [{path, hunks: [{old_start, old_lines, new_start, new_lines, content}]}]}`.

### Фаза 3 — LLM-driven analysis

```sh
# Anthropic Claude (default if ANTHROPIC_API_KEY set)
node ${SKILL_DIR}/scripts/llm_analyze.mjs --diff=<diff.json> --provider=anthropic --model=sonnet

# OpenAI GPT
node ${SKILL_DIR}/scripts/llm_analyze.mjs --diff=<diff.json> --provider=openai --model=best
```

Dispatcher (`scripts/llm_analyze.mjs`) обирає провайдер з `--provider` або з env (`ANTHROPIC_API_KEY` → anthropic, `OPENAI_API_KEY` → openai), потім делегує виклик у `scripts/providers/<name>.mjs`.

Кожен провайдер отримує:

1. **System prompt** (`prompts/system.md`) — OWASP/CWE framework + правила для аналізу diff
2. **References** — інлайн вміст `references/owasp-rules.md` (catalog 35 patterns) і `references/owasp-mapping.md`
3. **Few-shot** (`prompts/few_shot.md`) — 3-5 input/output прикладів для format consistency
4. **User message** — extracted diff JSON

Provider-specific деталі:
- **Anthropic** — system blocks array + `cache_control: ephemeral` на останньому блоці (90% cache read discount), JSON через prompt-engineering
- **OpenAI** — system message string + automatic prefix caching (50% discount), JSON через `response_format: {type: 'json_object'}`

Temperature: 0 для reproducibility.

Default models:
- anthropic → `claude-sonnet-4-5` (alias `sonnet`); `--model=haiku` для дешевих прогонів
- openai → `gpt-4o` (alias `best`); `--model=cheap` для gpt-4o-mini

Output: normalized JSON {`schema_version`, `findings: [...]`, `summary`, `provider`, `model`, `cost`, `latency_ms`, `usage`}.

### Фаза 4 — Validation, scoring, formatting

1. `scripts/validate_finding.mjs` — перевіряє кожен finding проти схеми (валідний OWASP_ID, CWE_ID, severity, etc.)
2. `scripts/risk_score.mjs` — обчислює CVSS-like `risk_score` з severity × confidence × verdict
3. Формат — за вибором:
   - `format_pr_comment.mjs` — markdown для GitHub PR (default у Action mode)
   - `format_sarif.mjs` — SARIF 2.1.0 для GitHub Code Scanning
   - `format_cli.mjs` — human-readable terminal output (default у CLI mode)
4. Exit code:
   - `0` — no findings вище порога
   - `1` — findings знайдено, але severity нижче `--fail-on`
   - `2` — є finding ≥ `--fail-on` (default `critical`)
   - `3` — помилка інструмента

## Принципи

- **LLM як primary analyzer**: вердикт виносить Claude, не AST-правила. AST — опціональна verification layer (`scripts/verify_with_ast.mjs`, future work).
- **Diff-focused**: рекомендуємо знахідки тільки на додані/змінені рядки. Контекст (`-U10`) — для розуміння, не для звітування.
- **Grounded reasoning**: кожне твердження має мапитись на rule з `references/owasp-rules.md` або позначатись `NEW_PATTERN`.
- **Structured output**: JSON schema-validated, formatters — детерміновані.
- **Verdict transparency**: `NEEDS_HUMAN` краще за впевнений `FALSE_POSITIVE` — не ховаємо невпевненість.
- **Progressive disclosure**: маленькі diffs → коротка system prompt без full catalog inlined; великі diffs → catalog inlined для grounding.

## Структура скіла

```
security-audit/
  SKILL.md                          ← цей файл
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
    owasp-rules.md                  ← 35 vulnerability patterns (LLM grounding)
    owasp-mapping.md                ← OWASP→CWE map
    report-schema.md                ← finding JSON schema
  ci/
    github-action.yml               ← workflow template for users
    pre-commit-hook.sh
    setup.md                        ← integration guide
  benchmark/
    diff_corpus/                    ← synthetic diffs + ground truth
    run_benchmark.mjs
    compare_baselines.mjs
    results.md
  examples/                         ← representative vulnerable/safe samples
  .github/workflows/
    test.yml                        ← CI for the tool itself
    release.yml
```

## Обмеження

- Покриває JS/TS/TSX/JSX (FE: React/Vue/Svelte components; BE: Express/Koa/NestJS/Fastify) + Dockerfile + docker-compose YAML. Інші мови (Go, Python, Rust) — поза scope.
- Аналізує **тільки diff**, не повний контекст файлу. Якщо вразливість залежить від глобального стану який не у diff — може пропуститись. Mitigation: `--include-file-context` flag завантажує повний файл для critical hunks.
- Не замінює DAST. Тільки статичний аналіз diff.
- LLM має inherent variance — для повної reproducibility встановлюється `temperature: 0`, але невелика стохастичність зберігається. Для deterministic CI використовуйте cached responses через `--cache-dir`.
- Token cost масштабується з розміром diff. Великі PR (>500 рядків змін) — chunked у файли і агреговано.
- Потребує `ANTHROPIC_API_KEY` (paid Anthropic) **або** `OPENAI_API_KEY` (paid OpenAI). Self-hosted моделі (Ollama, vLLM, LiteLLM) — поза scope; можна додати як новий провайдер у `scripts/providers/`.

## Посилання

- OWASP Top 10 (2021): https://owasp.org/Top10/
- CWE: https://cwe.mitre.org/
- OWASP Cheat Sheets: https://cheatsheetseries.owasp.org/
- SARIF 2.1.0 specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
- Anthropic SDK: https://github.com/anthropics/anthropic-sdk-typescript
