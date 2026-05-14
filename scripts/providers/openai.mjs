/**
 * OpenAI GPT provider.
 *
 * Features used:
 *   - response_format: { type: 'json_object' } — guarantees valid JSON output
 *     (less strict than the json_schema mode but compatible with our looser
 *     summary shape; system prompt + few-shot enforce structure).
 *   - Automatic prompt caching kicks in for stable prefixes ≥1024 tokens.
 *     OpenAI returns cached_tokens in usage.prompt_tokens_details (50% input
 *     discount on cached portion). No manual cache_control markers needed.
 *   - temperature=0 for near-deterministic output.
 *
 * OpenAI message shape uses one big `system` string (no blocks array), so we
 * concatenate all four grounding sections with clear separators. The diff
 * lives in the user message after the cache breakpoint, exactly like
 * Anthropic.
 *
 * Pricing (per 1M tokens, USD), source: OpenAI public pricing as of 2026-04.
 *   gpt-4o:        $2.50 input  / $10.00 output  (cached: $1.25)
 *   gpt-4o-mini:   $0.15 input  / $0.60  output  (cached: $0.075)
 *   gpt-4-turbo:   $10.00 input / $30.00 output  (legacy, no auto-cache)
 *   o1:            $15.00 input / $60.00 output  (reasoning)
 *   o3-mini:       $1.10 input  / $4.40  output  (reasoning, cheaper)
 */

import OpenAI from 'openai';
import { extractJsonFromText, roundCost, ProviderError, withRetry, withTimeout } from './_common.mjs';

export const NAME = 'openai';
export const ENV_KEY = 'OPENAI_API_KEY';
export const DEFAULT_MODEL_ALIAS = 'gpt-4o';

const ALIASES = {
  best:        'gpt-4o',
  cheap:       'gpt-4o-mini',
  '4o':        'gpt-4o',
  'gpt4o':     'gpt-4o',
  'gpt-4o':    'gpt-4o',
  'mini':      'gpt-4o-mini',
  '4o-mini':   'gpt-4o-mini',
  'gpt-4o-mini': 'gpt-4o-mini',
  'turbo':     'gpt-4-turbo',
  'gpt-4-turbo': 'gpt-4-turbo',
  'o1':        'o1',
  'o3-mini':   'o3-mini',
  'o3':        'o3',
  'o4-mini':   'o4-mini',
};

const PRICING_PER_1M = {
  'gpt-4o':       { input: 2.50,  output: 10.00, cached: 1.25 },
  'gpt-4o-mini':  { input: 0.15,  output: 0.60,  cached: 0.075 },
  'gpt-4-turbo':  { input: 10.00, output: 30.00, cached: null },
  'o1':           { input: 15.00, output: 60.00, cached: 7.50 },
  'o3-mini':      { input: 1.10,  output: 4.40,  cached: 0.55 },
  'o3':           { input: 10.00, output: 40.00, cached: 2.50 },
  'o4-mini':      { input: 1.10,  output: 4.40,  cached: 0.275 },
};

export function resolveModel(input) {
  if (!input) return ALIASES[DEFAULT_MODEL_ALIAS];
  return ALIASES[input] || input;
}

export function listModels() {
  return Object.keys(PRICING_PER_1M);
}

function computeCost(model, usage) {
  const p = PRICING_PER_1M[model];
  if (!p) return null;
  const M = 1_000_000;

  const promptTokens = usage.prompt_tokens || 0;
  const cachedTokens = usage.prompt_tokens_details?.cached_tokens || 0;
  const uncachedInput = Math.max(0, promptTokens - cachedTokens);
  const completionTokens = usage.completion_tokens || 0;

  const inputCost = uncachedInput * p.input / M;
  const cachedCost = p.cached != null ? cachedTokens * p.cached / M : cachedTokens * p.input / M;
  const outputCost = completionTokens * p.output / M;

  return roundCost(inputCost + cachedCost + outputCost);
}

/**
 * Concatenate the 4 grounding blocks into one OpenAI-compatible system string.
 * Order is identical to Anthropic blocks: instructions → catalog → mapping → few-shot.
 * OpenAI's auto-caching prefix-matches the whole system message, so this is
 * effectively cached just like Anthropic's blocks (different discount rate).
 */
function buildSystemMessage(groundingBlocks) {
  return groundingBlocks
    .map(b => b.text)
    .join('\n\n' + '═'.repeat(72) + '\n\n');
}

/**
 * @param {Object} params
 * @param {Array<{label,text}>} params.groundingBlocks
 * @param {string} params.userMessage
 * @param {string} [params.model]    — alias (best|cheap|4o|mini) or exact id
 * @param {string} [params.apiKey]   — defaults to OPENAI_API_KEY env
 * @param {number} [params.timeoutMs] — abort the LLM call after N ms (0 = no timeout)
 */
export async function analyze({ groundingBlocks, userMessage, model, apiKey, timeoutMs = 0 }) {
  const resolvedModel = resolveModel(model);
  const key = apiKey || process.env.OPENAI_API_KEY;
  if (!key) {
    throw new ProviderError(NAME, 'config', 'OPENAI_API_KEY not set');
  }

  const client = new OpenAI({ apiKey: key });
  const startedAt = Date.now();

  // o-series reasoning models have different parameter requirements:
  //   - no `temperature` (always 1 internally)
  //   - `max_completion_tokens` instead of `max_tokens`
  //   - `response_format: json_object` support varies — o1-mini historically
  //     did not support it. Safer to omit and rely on prompt discipline +
  //     the post-hoc JSON extractor in _common.mjs (it now handles prose
  //     prefix/suffix and fenced blocks too).
  // For non-reasoning models (gpt-4o family) we use json_object mode which
  // guarantees valid JSON output via OpenAI's grammar-constrained decoding.
  const isReasoning = /^o\d/.test(resolvedModel);

  const requestBody = {
    model: resolvedModel,
    messages: [
      { role: 'system', content: buildSystemMessage(groundingBlocks) },
      { role: 'user',   content: userMessage },
    ],
    ...(isReasoning
      ? { max_completion_tokens: 8000 }
      : { temperature: 0, max_tokens: 8000, response_format: { type: 'json_object' } }),
  };

  let response;
  try {
    response = await withRetry(
      () => withTimeout(
        (signal) => client.chat.completions.create(requestBody, { signal }),
        timeoutMs,
      ),
      {
        attempts: 3,
        shouldRetry: (e) => {
          if (e?.name === 'TimeoutError' || e?.name === 'AbortError') return false;
          // Retry transient: 429 (rate limit) and 5xx. Auth/bad-request errors
          // are permanent — fail fast.
          const s = e?.status;
          return s === 429 || (s >= 500 && s < 600);
        },
        onRetry: (err, attempt, delayMs) => {
          if (process.stderr.isTTY) {
            process.stderr.write(`[openai] transient ${err?.status || 'error'} (attempt ${attempt}/3) — retrying in ${delayMs}ms\n`);
          }
        },
      },
    );
  } catch (err) {
    if (err?.name === 'TimeoutError') throw new ProviderError(NAME, 'timeout', err.message, err);
    const status = err?.status;
    if (status === 401) throw new ProviderError(NAME, 'auth', 'API key rejected', err);
    if (status === 429) throw new ProviderError(NAME, 'rate_limit', err.message, err);
    if (status === 400) throw new ProviderError(NAME, 'bad_request', err.message, err);
    throw new ProviderError(NAME, 'api', err?.message || String(err), err);
  }

  const latencyMs = Date.now() - startedAt;

  const choice = response.choices?.[0];
  if (!choice) {
    throw new ProviderError(NAME, 'empty', 'no choices in response');
  }
  if (choice.finish_reason === 'length') {
    // Output truncated; warn but still try to parse
    process.stderr.write(`[openai] warning: response hit max_tokens (truncated)\n`);
  }
  const rawText = choice.message?.content;
  if (!rawText) {
    throw new ProviderError(NAME, 'empty', `no content in choice; finish_reason=${choice.finish_reason}`);
  }

  const parsed = extractJsonFromText(rawText, 'OpenAI');

  // Normalize usage shape to the common envelope. OpenAI reports:
  //   prompt_tokens (incl. cached portion)
  //   completion_tokens
  //   prompt_tokens_details.cached_tokens (subset of prompt_tokens served from cache)
  const usage = response.usage || {};
  const cachedTokens = usage.prompt_tokens_details?.cached_tokens || 0;
  const promptTokens = usage.prompt_tokens || 0;
  const uncachedInput = Math.max(0, promptTokens - cachedTokens);

  return {
    ...parsed,
    provider: NAME,
    model: resolvedModel,
    latency_ms: latencyMs,
    cost_usd: computeCost(resolvedModel, usage),
    usage: {
      input_tokens: uncachedInput,
      output_tokens: usage.completion_tokens || 0,
      // Mirror Anthropic envelope: cache_read_input_tokens carries the cached
      // portion. cache_creation_input_tokens is 0 because OpenAI's auto-cache
      // doesn't charge a write premium.
      cache_creation_input_tokens: 0,
      cache_read_input_tokens: cachedTokens,
    },
  };
}
