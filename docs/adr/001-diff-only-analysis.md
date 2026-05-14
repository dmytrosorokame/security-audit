# ADR-001 — Diff-only analysis as the primary input

**Status:** Accepted (2026-05-13)

## Context

Most static analysis tools (Semgrep, ESLint plugin-security, Snyk Code) operate on **whole files**. A pull-request review surfaces all findings in the touched files, including ones that existed before the PR — the reviewer must then decide which findings to attribute to the change.

This produces two recurring problems on real PRs:

1. **Legacy noise.** A 200-line PR in a 50K-line codebase emits dozens of findings on code the PR author never touched. Reviewers learn to ignore the tool.
2. **Misattributed regressions.** When a refactor accidentally drops a sanitizer, a file-based tool may not flag the change because the sink existed beforehand — it only fires on the call site, which already had the issue *before* the diff.

## Decision

Analyse **only the lines that the diff changes** (`+` added, `-` removed) plus a configurable hunk context (`-U10`). Vulnerabilities are reported only when they map to changed lines. Context lines are used to disambiguate intent but never become the report target.

## Alternatives considered

1. **Full-file SAST with PR-aware filtering.** Run a normal SAST and post-process findings to those whose line numbers intersect the diff. Rejected: this still requires the full file to be parsed (slow for large monorepos), and the LLM-based variant would face a prohibitively expensive prompt.
2. **Tree-sitter incremental parser.** Use `git diff --raw` plus an AST that knows what changed. Rejected: this re-implements `git diff` and forces a language-specific parser path. The diff already encodes "what changed" canonically.
3. **Whole-file LLM analysis with diff highlighted.** Send the LLM the full file with diff markers. Rejected: 10–50× the token cost for the same signal, and the LLM still tends to comment on pre-existing issues.

## Consequences

**Positive.**
- Cost is linear in PR size, not file size. Average scan ~$0.003 on gpt-4o-mini.
- Reviewers see only PR-attributable findings → less noise → tool gets used.
- Cache key is the diff content, so re-running on the same PR is free.

**Negative.**
- Vulnerabilities that depend on **state outside the diff** can be missed. SSRF without an allowlist is fine to detect because the missing allowlist is *visible* in a deletion; an IDOR that relies on a route-level auth middleware *outside* the diff is not.
- We added `--include-file-context` as an opt-in mitigation (full-file content for critical hunks), and `NEEDS_HUMAN` verdict as an explicit "I cannot tell from the diff alone" signal — but neither fully closes the gap.

**Mitigation.** Document the limitation in `README.md > Limitations` and surface `NEEDS_HUMAN` verdicts prominently so reviewers know to drill in.
