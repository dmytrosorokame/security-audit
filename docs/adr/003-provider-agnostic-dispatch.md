# ADR-003 — Provider-agnostic dispatch (Anthropic + OpenAI)

**Status:** Accepted (2026-05-13)

## Context

The choice of LLM provider affects price, latency, output style, and caching mechanics. Locking the tool to one provider would:

- couple users to one vendor's pricing decisions (Anthropic doubled output cost in 2024-Q4 with no notice);
- block teams whose security policy permits one provider but not another;
- make a head-to-head quality comparison impossible.

## Decision

Build a thin dispatcher (`scripts/llm_analyze.mjs`) that picks a provider from an env key or `--provider` flag, and delegate the call to `scripts/providers/<name>.mjs`. Each provider implements a single function:

```js
analyze({ groundingBlocks, userMessage, model, apiKey, timeoutMs }) → normalized envelope
```

The normalized envelope is the **single source of truth** for the rest of the pipeline. Provider-specific details (Anthropic's `system` blocks + `cache_control`, OpenAI's `response_format: json_object`) live behind the adapter.

## Alternatives considered

1. **OpenAI-only.** Rejected: locks to one vendor.
2. **OpenAI-compatible API only (vLLM, Ollama, etc.).** Rejected for v0.1.0: most users have a hosted-model key already; OpenAI-compatible self-hosted is a roadmap item.
3. **LiteLLM proxy.** Rejected: adds a 3-line install for end users plus a maintenance dependency. Easier to maintain two thin adapters.

## Consequences

**Positive.**
- Same prompts, same schema, same outputs regardless of provider. Test/dev can use the cheaper provider (`--model=cheap` on OpenAI = $0.15/1M input).
- Adding a third provider (Gemini, Mistral, or a self-hosted OpenAI-compatible endpoint) is ~120 lines: one new file in `scripts/providers/` plus a registry entry in `llm_analyze.mjs`. No other code touches.
- We get to compare providers on the same benchmark (`run_benchmark.mjs --provider=anthropic` vs `--provider=openai`).

**Negative.**
- Two SDKs in `dependencies`. `pnpm install` pulls both (~15 MB total). Marginal cost.
- Provider-specific caching differs (Anthropic explicit cache_control = 90% read discount, OpenAI auto-prefix = 50%). Documented in `README.md > Provider auto-detection`.
- The "auto" provider selection has to break a tie when both keys are set. We chose Anthropic (cheaper with caching) and emit a stderr notice. Documented in code and README.

**Default tie-break: Anthropic.** Rationale documented at `pickProvider` JSDoc in `llm_analyze.mjs`.
