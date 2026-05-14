/**
 * Anthropic Claude provider.
 *
 * Features used:
 *   - System blocks array with `cache_control: ephemeral` on the last block,
 *     which caches all four grounding blocks together (~90% read discount,
 *     5-min TTL by default). The diff (volatile per-call) lives in the user
 *     message, after the cache breakpoint.
 *   - temperature=0 for near-deterministic output (LLM still has slight
 *     variance across model versions).
 *   - Structured JSON output via system-prompt discipline + few-shot. Anthropic
 *     does not have a native strict-schema mode for Messages API at the time
 *     of writing, so we rely on prompt engineering + post-hoc validation.
 *
 * Pricing source: shared/models.md, current as of 2026-04.
 * Cache write = 1.25× input. Cache read = 0.1× input.
 */

import Anthropic from '@anthropic-ai/sdk';
import { extractJsonFromText, roundCost, ProviderError, withRetry, withTimeout } from './_common.mjs';

export const NAME = 'anthropic';
export const ENV_KEY = 'ANTHROPIC_API_KEY';
export const DEFAULT_MODEL_ALIAS = 'sonnet';

const ALIASES = {
  sonnet: 'claude-sonnet-4-5',
  'sonnet-4-5': 'claude-sonnet-4-5',
  'sonnet-4-6': 'claude-sonnet-4-6',
  haiku: 'claude-haiku-4-5',
  'haiku-4-5': 'claude-haiku-4-5',
  opus: 'claude-opus-4-7',
  'opus-4-7': 'claude-opus-4-7',
  'opus-4-6': 'claude-opus-4-6',
};

const PRICING_PER_1M = {
  'claude-sonnet-4-5': { input: 3.0, output: 15.0 },
  'claude-sonnet-4-6': { input: 3.0, output: 15.0 },
  'claude-haiku-4-5':  { input: 1.0, output: 5.0 },
  'claude-opus-4-7':   { input: 5.0, output: 25.0 },
  'claude-opus-4-6':   { input: 5.0, output: 25.0 },
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
  const inputCost = (usage.input_tokens || 0) * p.input / M;
  const cacheWriteCost = (usage.cache_creation_input_tokens || 0) * p.input * 1.25 / M;
  const cacheReadCost = (usage.cache_read_input_tokens || 0) * p.input * 0.1 / M;
  const outputCost = (usage.output_tokens || 0) * p.output / M;
  return roundCost(inputCost + cacheWriteCost + cacheReadCost + outputCost);
}

function buildSystem(groundingBlocks) {
  // Caching: prefix-match. The marker on the LAST block caches all blocks
  // before it (Anthropic renders tools→system→messages, so this caches all
  // system blocks). Diff goes into the user message — not cached.
  return groundingBlocks.map((block, i) => ({
    type: 'text',
    text: block.text,
    ...(i === groundingBlocks.length - 1 ? { cache_control: { type: 'ephemeral' } } : {}),
  }));
}

/**
 * @param {Object} params
 * @param {Array<{label,text}>} params.groundingBlocks  — output of buildGroundingBlocks
 * @param {string} params.userMessage                   — the diff payload
 * @param {string} [params.model]                       — alias or exact model ID
 * @param {string} [params.apiKey]                      — defaults to ANTHROPIC_API_KEY env
 * @param {number} [params.timeoutMs]                   — abort the request after N ms (0 = no timeout)
 * @returns {Promise<Object>}                            — normalized envelope
 */
export async function analyze({ groundingBlocks, userMessage, model, apiKey, timeoutMs = 0 }) {
  const resolvedModel = resolveModel(model);
  const key = apiKey || process.env.ANTHROPIC_API_KEY;
  if (!key) {
    throw new ProviderError(NAME, 'config', 'ANTHROPIC_API_KEY not set');
  }

  const client = new Anthropic({ apiKey: key });
  const startedAt = Date.now();

  let response;
  try {
    response = await withRetry(
      () => withTimeout(
        (signal) => client.messages.create(
          {
            model: resolvedModel,
            max_tokens: 8000,
            temperature: 0,
            system: buildSystem(groundingBlocks),
            messages: [{ role: 'user', content: userMessage }],
          },
          { signal },
        ),
        timeoutMs,
      ),
      {
        attempts: 3,
        shouldRetry: (e) => {
          // Timeout / abort: don't retry (the user-supplied budget is already spent).
          if (e?.name === 'TimeoutError' || e?.name === 'AbortError') return false;
          // RateLimitError + 5xx are transient; auth/bad_request are permanent.
          if (e instanceof Anthropic.RateLimitError) return true;
          const s = e?.status;
          return s >= 500 && s < 600;
        },
        onRetry: (err, attempt, delayMs) => {
          if (process.stderr.isTTY) {
            const kind = err instanceof Anthropic.RateLimitError ? 'rate_limit' : `${err?.status || 'error'}`;
            process.stderr.write(`[anthropic] transient ${kind} (attempt ${attempt}/3) — retrying in ${delayMs}ms\n`);
          }
        },
      },
    );
  } catch (err) {
    if (err?.name === 'TimeoutError') {
      throw new ProviderError(NAME, 'timeout', err.message, err);
    }
    if (err instanceof Anthropic.RateLimitError) {
      throw new ProviderError(NAME, 'rate_limit', err.message, err);
    }
    if (err instanceof Anthropic.AuthenticationError) {
      throw new ProviderError(NAME, 'auth', 'API key rejected', err);
    }
    if (err instanceof Anthropic.BadRequestError) {
      throw new ProviderError(NAME, 'bad_request', err.message, err);
    }
    throw new ProviderError(NAME, 'api', err.message || String(err), err);
  }

  const latencyMs = Date.now() - startedAt;
  const textBlocks = response.content.filter(b => b.type === 'text');
  if (textBlocks.length === 0) {
    throw new ProviderError(NAME, 'empty', `no text blocks; got types: ${response.content.map(b => b.type).join(',')}`);
  }
  const rawText = textBlocks.map(b => b.text).join('');
  const parsed = extractJsonFromText(rawText, 'Anthropic');

  return {
    ...parsed,
    provider: NAME,
    model: resolvedModel,
    latency_ms: latencyMs,
    cost_usd: computeCost(resolvedModel, response.usage),
    usage: {
      input_tokens: response.usage.input_tokens,
      output_tokens: response.usage.output_tokens,
      cache_creation_input_tokens: response.usage.cache_creation_input_tokens || 0,
      cache_read_input_tokens: response.usage.cache_read_input_tokens || 0,
    },
  };
}
