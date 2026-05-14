# Changelog

All notable changes to this project are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `--max-cost=<usd>` CLI flag — refuses scans whose reported cost exceeds the cap; exits 3 with a clear message.
- `SECURITY.md` with threat model, reporting policy, and explicit trust boundaries.
- `docs/adr/` — Architecture Decision Records (ADR-001 through ADR-005) documenting the rationale for diff-only analysis, LLM-as-primary-analyzer, provider-agnostic dispatch, catalog-as-grounding, and exploit-trace calibration.
- `CONTRIBUTING.md` with development setup, testing, and release process.
- Prompt-injection hardening section in `prompts/system.md`: model is told to treat `<diff>...</diff>` content as data, and to surface injection attempts in `non_security_observations`.
- `exploit_trace` is now a required-when-present, validated field on every finding. Calibrates `confidence` against the trace length (3/2/≤1 → high/medium/low).
- `calibrateConfidence()` post-processor with `confidence_downgraded_from` annotation surfaced through CLI/SARIF.
- Operational verdict criteria in system prompt — replaces descriptive verdict definitions with a first-match decision table.
- Self-critique pass (mandatory) in system prompt with four explicit questions before emitting JSON.
- `redactReportSecrets()` — secrets are now stripped from findings **before** they reach the file cache, not just before output channels.
- 4 edge-case example diffs: Dockerfile root-user regression (D-01), renamed file with SQL-injection regression (B-01), deleted file with embedded backdoor (true-negative), binary file (no-op).
- Catalog drift detector (`catalog_drift.test.mjs`) — fails CI if any `rule_id` in `owasp-mapping.md` or `benchmark/expected/*.json` is missing from `owasp-rules.md`.
- ESLint flat-config (`eslint.config.mjs`) + CI `lint` job.
- Plugin manifest at `.claude-plugin/plugin.json` for future `/plugins install` integration.

### Changed
- `prompts/system.md`, `references/owasp-mapping.md`, `references/report-schema.md`, `SKILL.md` — fully English (previously mixed UA/EN).
- `format_pr_comment.mjs`: `escapeMd` now emits HTML entities (`&lt;`, `&gt;`, `&amp;`) instead of backslash-escapes, which are not honoured by CommonMark for `<` / `>`.
- `format_pr_comment.mjs`: evidence code blocks now use `pickFence()` to scale the fence length above any internal backtick run — prevents markdown injection if a malicious diff contains literal `` ``` ``.
- `withTimeout` (in `providers/_common.mjs`): timeout firing now rejects the race **before** signalling abort, so the surfaced error is `TimeoutError`, not the SDK's `AbortError`.
- JWT redaction regex tightened from `eyJ.\+\.\+\.\+` to `\beyJ[h0r]…\.eyJ…\.…\b` — recognises `alg`, `typ`, `kid` JWT headers but no longer false-positives on short base64-JSON.
- README severity table now mirrors the actual catalog (11 R-, 15 B-, 8 D-; was incorrectly listed as 15/13/6).
- `vitest.config.mjs` coverage thresholds calibrated to 75/70/75/70 % (lines/functions/statements/branches) — reflects current realistic test coverage and excludes CLI orchestrator + SDK wrappers.

### Fixed
- `globToRegex` (in `extract_diff.mjs` and `suppression.mjs`): pattern `**/foo` now correctly matches top-level `foo` (previously required a leading path segment, leading to silently-ignored exclude rules).
- `--timeout=foo`, `--max-cost=foo`: previously parsed as `NaN` and silently disabled the guard; now validated and exit with code 3 and a clear message.
- `--include-file-context` now emits a stderr warning when used with `--diff=<file>` (no git tree → no effect), instead of silently no-op-ing.
- `f1_table.md` and `benchmark/expected/01_dom_xss_introduction.json` aligned with the actual diff (R-02 `innerHTML`, not R-01 `dangerouslySetInnerHTML`); R-01 is preserved as `accept_alternatives`.
- Removed historical references to non-existent `R-12` (deps CVE — out of scope) and `R-15` (sanitizer-removed — replaced by R-01) from documentation and ground truth.
- Documentation typos: "Дитермінований" → "Детермінований" (`SKILL.md`); useless escape characters in connection-string and Stripe regex.

### Security
- Cache files (`.security-audit-cache/`) are now pre-redacted: secrets are stripped from `evidence`, `rationale`, and `remediation` before persistence. Previously the cache could retain raw secret matches in `evidence` even though the output channels were sanitised.
- System prompt rejects prompt injection attempts originating from diff content; injection patterns are recorded in `non_security_observations` rather than influencing verdicts.

## [0.1.0] — pre-release (rolling)

Initial development release. Diff-only LLM security review pipeline:

- 34 OWASP Top 10 (2021) — mapped patterns covering frontend (R-01…R-11), backend (B-01…B-15), and Docker/compose (D-01…D-08).
- Anthropic Claude and OpenAI GPT providers with prompt caching.
- Three output formats: CLI (colourised), PR comment (Markdown), SARIF 2.1.0.
- Inline suppression directives + repo-level `.security-audit-ignore`.
- Anti-hallucination: file/line/evidence cross-check against the diff; auto-correction of context-line mis-numbering.
- Secret redaction across 9 secret families + connection strings.
- 5 reference example diffs with expected ground-truth for smoke benchmarking.
- GitHub Action, CLI, and Claude Code Skill entry points.
