/**
 * Shared utilities used by all provider adapters.
 *
 * Providers return a normalized envelope of shape:
 *   {
 *     findings: [...],
 *     summary: { total, by_severity, by_owasp },
 *     non_security_observations: [...],
 *     usage: { input_tokens, output_tokens, cache_creation_input_tokens, cache_read_input_tokens },
 *     cost_usd: number,
 *     latency_ms: number,
 *     model: string,
 *     provider: 'anthropic' | 'openai',
 *   }
 *
 * The dispatcher (llm_analyze.mjs) merges these fields into the final report.
 */

/**
 * Robust JSON extraction from a model's free-form text output.
 *
 * Handles: bare JSON, JSON wrapped in ```json fences, leading/trailing whitespace.
 * Throws a descriptive error with a head snippet if parsing fails.
 */
export function extractJsonFromText(text, context = 'LLM') {
  const trimmed = (text || '').trim();
  if (!trimmed) {
    throw new Error(`${context} returned empty response`);
  }
  const fence = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```\s*$/);
  const candidate = fence ? fence[1] : trimmed;
  try {
    return JSON.parse(candidate);
  } catch (e) {
    const head = candidate.slice(0, 800);
    throw new Error(`${context} did not return valid JSON.\nParser error: ${e.message}\nFirst 800 chars:\n${head}`);
  }
}

/**
 * Round a USD amount to 6 decimals (micro-cent precision) — good enough for
 * benchmark telemetry and small enough to fit in JSON cleanly.
 */
export function roundCost(usd) {
  return Number(usd.toFixed(6));
}

/**
 * Build the canonical user message text from a structured diff JSON.
 * Same format across providers so prompts stay portable.
 */
export function buildUserMessage(diffJson) {
  return `Analyze the following git diff for security vulnerabilities. Follow every rule in the system prompt — especially: ground each finding in the OWASP catalog (or use NEW_PATTERN), verify file/line attribution against the diff, and return strict JSON only (no markdown fences, no preamble).

<diff>
${JSON.stringify(diffJson, null, 2)}
</diff>`;
}

/**
 * Construct the four-block grounding payload from raw grounding strings.
 * Providers will splice these into their native message shapes.
 */
export function buildGroundingBlocks({ system, fewShot, owaspRules, owaspMapping }) {
  return [
    {
      label: 'system',
      text: system,
    },
    {
      label: 'owasp-rules',
      text: '# OWASP Vulnerability Pattern Catalog (LLM grounding)\n\nUse this as ground truth for `rule_id`, `owasp_id`, `cwe_id`, and `severity`. If a pattern matches an entry below, use that rule_id. Otherwise use `NEW_PATTERN`.\n\n---\n\n' + owaspRules,
    },
    {
      label: 'owasp-mapping',
      text: '# OWASP Top 10 → CWE → Manifestation map\n\n---\n\n' + owaspMapping,
    },
    {
      label: 'few-shot',
      text: '# Few-shot examples\n\nUse these to anchor your output format and verdict discipline.\n\n---\n\n' + fewShot,
    },
  ];
}

/**
 * Common error shape — providers throw these with a friendly message instead
 * of leaking raw SDK exceptions to the user. The dispatcher catches and prints.
 */
export class ProviderError extends Error {
  constructor(provider, kind, message, cause) {
    super(`[${provider}] ${kind}: ${message}`);
    this.provider = provider;
    this.kind = kind;
    this.cause = cause;
  }
}
