# Architecture Decision Records

Each ADR captures one architectural decision, its context, the alternatives considered, the choice made, and the consequences (positive and negative). New ADRs are appended; old ones are superseded but not deleted.

| # | Title | Status |
|---|-------|--------|
| [ADR-001](001-diff-only-analysis.md) | Diff-only analysis as the primary input | Accepted |
| [ADR-002](002-llm-as-primary-analyzer.md) | LLM as the primary analyzer, no AST verification | Accepted |
| [ADR-003](003-provider-agnostic-dispatch.md) | Provider-agnostic dispatch (Anthropic + OpenAI) | Accepted |
| [ADR-004](004-catalog-grounding.md) | OWASP/CWE catalog as LLM grounding, not as filter | Accepted |
| [ADR-005](005-exploit-trace-calibration.md) | Confidence calibration via mandatory `exploit_trace` | Accepted |

Format follows Michael Nygard's lightweight ADR style.
