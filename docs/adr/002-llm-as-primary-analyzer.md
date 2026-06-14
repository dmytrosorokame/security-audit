# ADR-002 — LLM as the primary analyzer, no AST verification layer

**Status:** Accepted (2026-05-13)

## Context

There are three plausible architectures for an LLM-based SAST:

1. **AST-first, LLM-second.** Static patterns produce candidate findings; the LLM filters false positives. (How CodeQL+LLM proposals typically work.)
2. **LLM-first, AST-second.** The LLM produces findings; an AST pass verifies that the cited lines/identifiers exist and that the pattern is real.
3. **LLM-only with deterministic post-processing.** The LLM is the sole reasoner; a non-AST validator (`validate_finding.mjs`) checks structure, evidence cross-references the diff, and secrets are redacted.

## Decision

Architecture (3): the LLM produces findings, and post-processing is **deterministic but not AST-based**.

## Alternatives considered

- (1) **AST-first.** Rejected for cost and complexity: requires a per-language parser (Babel for JS/TSX, Tree-sitter for Dockerfile, custom for compose YAML). Drops the "diff-only" property because AST patterns typically operate on the file.
- (2) **LLM-first + AST verification.** Rejected as **premature optimisation.** We have no measurement showing AST verification reduces false positives over what `validate_finding.mjs` already catches. The cost (per-language AST + maintenance) is not justified by an unmeasured benefit.

## Consequences

**Positive.**
- One language stack to maintain (Node ESM) — no AST library per target language.
- Adding a new target (Python, Go) requires only catalog + few-shot extensions, not a new parser.
- `validate_finding.mjs` is small (~280 lines), unit-testable, and language-agnostic.

**Negative.**
- We have no second-source verification of LLM claims. If the LLM hallucinates a finding *and* hallucinates evidence that happens to appear in the diff verbatim, the post-processor will accept it. This has not been observed in practice but is theoretically possible.
- Recall depends entirely on prompt + catalog quality, with no fallback signal.

**Mitigation.**
- The catalog grounding (ADR-004) and `exploit_trace` calibration (ADR-005) provide structural cross-checks: every finding must reference a known rule and ship a 3-element trace whose elements must be quotable from the diff.
- `verify_with_ast.mjs` is explicitly **out of scope** per SKILL.md — not a planned feature without measurement showing it would help.
