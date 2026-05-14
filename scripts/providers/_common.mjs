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
 * Handles (in order):
 *   1. bare JSON (the easy path)
 *   2. ```json ... ``` fenced block (anywhere in the output, not just whole-string)
 *   3. prose-wrapped JSON: find first `{` and last matching `}` and slice
 *
 * Throws a descriptive error with a head snippet if all strategies fail.
 *
 * OpenAI's `response_format: json_object` mode forces strategy 1 to work.
 * Anthropic (no native JSON mode) sometimes produces strategy 2 or 3; this
 * function recovers gracefully without a re-prompt.
 */
export function extractJsonFromText(text, context = 'LLM') {
  const trimmed = (text || '').trim();
  if (!trimmed) {
    throw new Error(`${context} returned empty response`);
  }

  // Strategy 1: bare JSON
  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    try { return JSON.parse(trimmed); } catch { /* fall through */ }
  }

  // Strategy 2: ```json fence (anywhere, not anchored)
  const fence = trimmed.match(/```(?:json)?\s*([\s\S]*?)\s*```/);
  if (fence) {
    try { return JSON.parse(fence[1].trim()); } catch { /* fall through */ }
  }

  // Strategy 3: prose-wrapped — slice from first `{` to last `}` and try
  const firstBrace = trimmed.indexOf('{');
  const lastBrace = trimmed.lastIndexOf('}');
  if (firstBrace !== -1 && lastBrace > firstBrace) {
    const slice = trimmed.slice(firstBrace, lastBrace + 1);
    try { return JSON.parse(slice); } catch { /* fall through */ }
  }

  // All strategies exhausted — produce an actionable error.
  const head = trimmed.slice(0, 800);
  throw new Error(`${context} did not return parseable JSON. First 800 chars:\n${head}`);
}

/**
 * Round a USD amount to 6 decimals (micro-cent precision) — good enough for
 * benchmark telemetry and small enough to fit in JSON cleanly. Returns null
 * for null/undefined input so cost can be reported as "unknown" cleanly.
 */
export function roundCost(usd) {
  if (usd == null || Number.isNaN(usd)) return null;
  return Number(Number(usd).toFixed(6));
}

/**
 * Build the canonical user message text from a structured diff JSON.
 * Same format across providers so prompts stay portable.
 *
 * Important: strips volatile fields (`extracted_at` and other timestamps) so
 * the user message is a deterministic function of the diff content alone.
 * Without this the cache key (sha256 of the user message) churns every run
 * even when the diff is identical, and every cache hit becomes a cache miss.
 */
export function buildUserMessage(diffJson) {
  // Whitelist stable fields. mode/base/head can be informative for the LLM
  // (e.g. distinguishing --staged from a PR diff), but `extracted_at` is
  // pure noise from a caching standpoint and adds nothing for the model.
  const stable = {
    schema_version: diffJson?.schema_version,
    mode: diffJson?.mode,
    base: diffJson?.base,
    head: diffJson?.head,
    stats: diffJson?.stats,
    files: diffJson?.files,
  };
  return `Analyze the following git diff for security vulnerabilities. Follow every rule in the system prompt — especially: ground each finding in the OWASP catalog (or use NEW_PATTERN), verify file/line attribution against the diff, and return strict JSON only (no markdown fences, no preamble).

<diff>
${JSON.stringify(stable, null, 2)}
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

/**
 * Accept common "truthy" forms of an env var: 1 / true / yes / on / y / t
 * (case-insensitive). Anything else — including unset — is false.
 *
 * Used for boolean env switches like SECURITY_AUDIT_DEBUG. Without this users
 * setting SECURITY_AUDIT_DEBUG=true silently get the false branch.
 */
export function envBool(name) {
  const v = (process.env[name] || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on' || v === 'y' || v === 't';
}

/**
 * Exponential-backoff retry helper for transient API failures.
 *
 * `shouldRetry(err)` decides whether to retry on a given error. Defaults
 * to true (retry everything once); providers pass a predicate that returns
 * true only for 429 / 5xx / network errors.
 *
 * Backoff schedule (with jitter): 500ms, 1500ms, 4500ms ± 30%. The 3-attempt
 * default fits inside a typical 30s CI step budget while still riding out a
 * single 429 burst.
 */
export async function withRetry(fn, { attempts = 3, baseDelayMs = 500, shouldRetry = () => true, onRetry } = {}) {
  let lastErr;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (i === attempts - 1 || !shouldRetry(err)) throw err;
      const exp = baseDelayMs * Math.pow(3, i);
      const jitter = exp * (0.7 + Math.random() * 0.6);  // ±30%
      if (onRetry) onRetry(err, i + 1, Math.round(jitter));
      await new Promise(r => setTimeout(r, jitter));
    }
  }
  throw lastErr;
}

/**
 * Race a promise against a wall-clock timeout. Aborts the underlying request
 * (via the signal returned to `fn`) and rejects with a `TimeoutError` if the
 * promise doesn't resolve within `timeoutMs`.
 *
 * Both Anthropic SDK and OpenAI SDK accept `{ signal: AbortSignal }` in their
 * request options, so callers can forward `controller.signal` to abort the
 * in-flight HTTP request — not just stop awaiting it.
 *
 * Pass `timeoutMs <= 0` to disable (returns the unwrapped promise).
 *
 * @template T
 * @param {(signal: AbortSignal) => Promise<T>} fn
 * @param {number} timeoutMs
 * @returns {Promise<T>}
 */
export async function withTimeout(fn, timeoutMs) {
  if (!timeoutMs || timeoutMs <= 0) {
    return fn(new AbortController().signal);
  }
  const controller = new AbortController();
  let timer;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      // Order matters: reject the race FIRST so the timeout wins, then signal
      // the underlying fn to abort its in-flight request. If we called abort()
      // first, the SDK's abort listener would reject fn's promise synchronously
      // (with an AbortError/DOMException), and that error — not our
      // TimeoutError — would surface to the caller through Promise.race.
      const err = new Error(`LLM call exceeded timeout of ${timeoutMs}ms`);
      err.name = 'TimeoutError';
      err.code = 'ETIMEDOUT';
      reject(err);
      controller.abort();
    }, timeoutMs);
  });
  try {
    return await Promise.race([fn(controller.signal), timeoutPromise]);
  } finally {
    clearTimeout(timer);
  }
}
