#!/usr/bin/env node
/**
 * llm_analyze.mjs — sends a structured diff to Claude for security analysis.
 *
 * Reads diff JSON (from extract_diff.mjs) on stdin or --diff=<file>.
 * Loads grounding (system prompt + OWASP rules + OWASP mapping + few-shot) and
 * sends a single message to claude-sonnet-4-5 (or claude-haiku-4-5 via --model=haiku).
 *
 * Uses **prompt caching** on the system blocks — system + references + few-shot
 * are stable across calls, so they're cached. Only the diff (user message) is
 * volatile. On the second+ call within 5 minutes, cache_read drops cost ~90%.
 *
 * Outputs a security-audit report JSON to stdout, augmented with cost, latency,
 * and token-usage telemetry.
 *
 * Usage:
 *   ANTHROPIC_API_KEY=sk-... node llm_analyze.mjs --diff=diff.json
 *   node extract_diff.mjs --against=main | node llm_analyze.mjs
 *   node llm_analyze.mjs --diff=diff.json --model=haiku   # cheaper, faster
 *   node llm_analyze.mjs --diff=diff.json --dry-run       # don't call API; emit assembled prompt
 *   node llm_analyze.mjs --diff=diff.json --model=claude-sonnet-4-6  # explicit override
 */

import Anthropic from '@anthropic-ai/sdk';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SKILL_ROOT = path.resolve(__dirname, '..');

const TOOL_NAME = 'security-audit';
const TOOL_VERSION = '0.1.0';

// Model aliases (CLI shortcuts). Pass the full model id via --model=<exact-id>
// to use anything else. Verified IDs from Anthropic Models catalogue.
const MODEL_ALIASES = {
  sonnet: 'claude-sonnet-4-5',  // user's chosen default (active model)
  'sonnet-4-5': 'claude-sonnet-4-5',
  'sonnet-4-6': 'claude-sonnet-4-6',
  haiku: 'claude-haiku-4-5',
  'haiku-4-5': 'claude-haiku-4-5',
  opus: 'claude-opus-4-7',
};

// Pricing per 1M tokens (USD), source: shared/models.md as of 2026-04.
// Cache write = 1.25 × input (5-min TTL). Cache read = 0.1 × input.
const PRICING_PER_1M = {
  'claude-sonnet-4-5': { input: 3.0, output: 15.0 },   // estimated same as 4-6 tier
  'claude-sonnet-4-6': { input: 3.0, output: 15.0 },
  'claude-haiku-4-5':  { input: 1.0, output: 5.0 },
  'claude-opus-4-7':   { input: 5.0, output: 25.0 },
  'claude-opus-4-6':   { input: 5.0, output: 25.0 },
};

function loadGroundingDocs() {
  return {
    system: fs.readFileSync(path.join(SKILL_ROOT, 'prompts/system.md'), 'utf8'),
    fewShot: fs.readFileSync(path.join(SKILL_ROOT, 'prompts/few_shot.md'), 'utf8'),
    owaspRules: fs.readFileSync(path.join(SKILL_ROOT, 'references/owasp-rules.md'), 'utf8'),
    owaspMapping: fs.readFileSync(path.join(SKILL_ROOT, 'references/owasp-mapping.md'), 'utf8'),
  };
}

/**
 * Build the `system` array sent to Claude.
 *
 * The order is stability-first: instructions → grounding catalog → few-shot.
 * One cache_control marker on the LAST block caches all blocks above it
 * together (prompt caching is prefix-match — see shared/prompt-caching.md).
 *
 * The diff itself (volatile) goes into the user message, *after* the cache
 * breakpoint, so each invocation only writes the diff to the model.
 */
function buildSystem(grounding) {
  return [
    {
      type: 'text',
      text: grounding.system,
    },
    {
      type: 'text',
      text: '# OWASP Vulnerability Pattern Catalog (LLM grounding)\n\nUse this as ground truth for `rule_id`, `owasp_id`, `cwe_id`, and `severity`. If a pattern matches an entry below, use that rule_id. Otherwise use `NEW_PATTERN`.\n\n---\n\n' + grounding.owaspRules,
    },
    {
      type: 'text',
      text: '# OWASP Top 10 → CWE → Manifestation map\n\n---\n\n' + grounding.owaspMapping,
    },
    {
      type: 'text',
      text: '# Few-shot examples\n\nUse these to anchor your output format and verdict discipline.\n\n---\n\n' + grounding.fewShot,
      // Cache up to and including this block. Prompt cache prefix-matches in
      // order tools→system→messages, so this marker caches all four blocks.
      cache_control: { type: 'ephemeral' },
    },
  ];
}

function buildUserMessage(diffJson) {
  // Inline the diff as JSON. The model is fluent in unified diff and structured
  // representations alike; the structured form makes file/line attribution
  // unambiguous and lets the model reason about hunks individually.
  return `Analyze the following git diff for security vulnerabilities. Follow every rule in the system prompt — especially: ground each finding in the OWASP catalog (or use NEW_PATTERN), verify file/line attribution against the diff, and return strict JSON only (no markdown fences, no preamble).

<diff>
${JSON.stringify(diffJson, null, 2)}
</diff>`;
}

function extractJsonFromText(text) {
  const trimmed = text.trim();
  // Tolerate markdown code fences just in case the model wraps output.
  const fenceMatch = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```\s*$/);
  const candidate = fenceMatch ? fenceMatch[1] : trimmed;
  try {
    return JSON.parse(candidate);
  } catch (e) {
    const head = candidate.slice(0, 800);
    throw new Error(`LLM did not return valid JSON.\nParser error: ${e.message}\nFirst 800 chars of response:\n${head}`);
  }
}

function computeCost(model, usage) {
  const p = PRICING_PER_1M[model];
  if (!p) return null;
  const M = 1_000_000;
  const inputCost = (usage.input_tokens || 0) * p.input / M;
  const cacheWriteCost = (usage.cache_creation_input_tokens || 0) * p.input * 1.25 / M;
  const cacheReadCost = (usage.cache_read_input_tokens || 0) * p.input * 0.1 / M;
  const outputCost = (usage.output_tokens || 0) * p.output / M;
  return Number((inputCost + cacheWriteCost + cacheReadCost + outputCost).toFixed(6));
}

export async function analyzeDiff(diffJson, options = {}) {
  const modelInput = options.model || 'sonnet';
  const model = MODEL_ALIASES[modelInput] || modelInput;

  const grounding = loadGroundingDocs();
  const system = buildSystem(grounding);
  const userMessage = buildUserMessage(diffJson);

  if (options.dryRun) {
    return {
      dry_run: true,
      model,
      system_blocks: system.length,
      system_chars: system.reduce((n, b) => n + b.text.length, 0),
      user_chars: userMessage.length,
      preview: {
        system_first_block_head: system[0].text.slice(0, 300),
        user_head: userMessage.slice(0, 300),
      },
    };
  }

  const apiKey = options.apiKey || process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error('ANTHROPIC_API_KEY not set in environment. Use --dry-run to skip API call.');
  }

  const client = new Anthropic({ apiKey });
  const startedAt = Date.now();

  let response;
  try {
    response = await client.messages.create({
      model,
      max_tokens: 8000,
      temperature: 0,
      system,
      messages: [{ role: 'user', content: userMessage }],
    });
  } catch (err) {
    if (err instanceof Anthropic.RateLimitError) {
      throw new Error(`Anthropic rate limit hit: ${err.message}. Retry with --model=haiku or wait.`);
    }
    if (err instanceof Anthropic.AuthenticationError) {
      throw new Error('Anthropic authentication failed. Check ANTHROPIC_API_KEY.');
    }
    if (err instanceof Anthropic.BadRequestError) {
      throw new Error(`Anthropic rejected request: ${err.message}`);
    }
    throw err;
  }

  const latencyMs = Date.now() - startedAt;

  const textBlocks = response.content.filter(b => b.type === 'text');
  if (textBlocks.length === 0) {
    throw new Error('LLM response contained no text blocks; got: ' + JSON.stringify(response.content.map(b => b.type)));
  }
  const rawText = textBlocks.map(b => b.text).join('');

  const parsed = extractJsonFromText(rawText);
  const cost = computeCost(model, response.usage);

  return {
    ...parsed,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    model,
    scanned_at: new Date().toISOString(),
    cost,
    latency_ms: latencyMs,
    usage: {
      input_tokens: response.usage.input_tokens,
      output_tokens: response.usage.output_tokens,
      cache_creation_input_tokens: response.usage.cache_creation_input_tokens || 0,
      cache_read_input_tokens: response.usage.cache_read_input_tokens || 0,
    },
  };
}

async function readStdin() {
  let data = '';
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

async function main() {
  const { values } = parseArgs({
    options: {
      diff: { type: 'string' },
      model: { type: 'string', default: 'sonnet' },
      'dry-run': { type: 'boolean', default: false },
      help: { type: 'boolean', default: false },
    },
    strict: true,
  });

  if (values.help) {
    process.stdout.write(`Usage: node llm_analyze.mjs [--diff=path] [--model=sonnet|haiku|<exact-id>] [--dry-run]

Reads diff JSON from --diff=<file> or stdin.
Sends to Claude with cached grounding (OWASP rules + mapping + few-shot).
Writes augmented security-audit report to stdout.

Requires ANTHROPIC_API_KEY env var (unless --dry-run).
`);
    process.exit(0);
  }

  let diffJson;
  if (values.diff) {
    diffJson = JSON.parse(fs.readFileSync(values.diff, 'utf8'));
  } else {
    const raw = await readStdin();
    if (!raw.trim()) {
      console.error('llm_analyze: empty input. Provide --diff=<file> or pipe extract_diff.mjs output.');
      process.exit(1);
    }
    diffJson = JSON.parse(raw);
  }

  const result = await analyzeDiff(diffJson, {
    model: values.model,
    dryRun: values['dry-run'],
  });

  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(err => {
    console.error('llm_analyze error:', err.message);
    process.exit(2);
  });
}
