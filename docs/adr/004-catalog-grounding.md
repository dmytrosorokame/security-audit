# ADR-004 — OWASP/CWE catalog as LLM grounding, not as a filter

**Status:** Accepted (2026-05-13)

## Context

Two ways to use a vulnerability catalog with an LLM:

1. **As a filter.** Pre-classify the diff with regex/AST patterns, then ask the LLM to confirm. The catalog defines what *can* be detected.
2. **As grounding.** Embed the catalog into the LLM's context window and let the model both recognise patterns and ground each finding in a specific `rule_id`. The catalog defines what the LLM *expects to see* — and therefore what it can detect or flag as new.

## Decision

Use the catalog as **grounding**. The full `references/owasp-rules.md` (≈45 KB) is inlined into every prompt as a system block with `cache_control: ephemeral` (Anthropic) or as part of the auto-cached prefix (OpenAI). The LLM is required to reference a `rule_id` per finding or use `NEW_PATTERN`.

## Alternatives considered

- **Filter approach.** Rejected: requires per-language pattern code, which conflicts with ADR-002. Also limits the tool to patterns we predefined; LLM cannot find a vulnerability the catalog didn't anticipate.
- **No catalog, free-form classification.** Rejected: leads to inconsistent rule IDs ("XSS in Comment.tsx" vs "Cross-Site Scripting on user-supplied innerHTML") and makes deduplication, severity gating, and remediation linking unreliable.
- **Smaller catalog (top 10 rules only).** Rejected: defeats the purpose of grounding — we want the LLM to **recognise** the long tail (e.g., D-08 unsafe apt-get without pinning).

## Consequences

**Positive.**
- Output is consistent: every finding has a stable `rule_id` that maps to a documented severity, OWASP/CWE, and remediation link.
- Catalog is **version-controlled**. A diff to `owasp-rules.md` invalidates the prompt cache (via the prompt hash) and is testable (`catalog_drift.test.mjs` ensures no orphan IDs).
- Recall is bounded by catalog completeness — but **measurable**. We know exactly which patterns the LLM has been told to look for.
- `NEW_PATTERN` lets the model surface novel issues without forcing every contributor to extend the catalog before reporting a real finding.

**Negative.**
- **Token cost.** ~12 K tokens of grounding per call. Mitigated by prompt caching (90% read discount on Anthropic, 50% on OpenAI prefix cache) — the cache makes the per-call cost negligible after the first warm-up.
- **Recall ceiling.** Vulnerabilities outside the catalog (e.g. race conditions, business-logic bugs, complex protocol flaws) depend on the model recognising them as `NEW_PATTERN`. This is a real weakness; documented in `SKILL.md > Limitations`.
- **Catalog maintenance.** Catalog must be reviewed annually against OWASP/CWE updates. Drift detector unit test (`catalog_drift.test.mjs`) catches accidental orphan IDs in mapping/expected JSON.
