#!/usr/bin/env node
/**
 * llm_analyze.mjs — provider-agnostic dispatcher.
 *
 * Loads grounding (system prompt + OWASP rules + OWASP mapping + few-shot),
 * picks a provider (auto-detected from env, or forced via --provider), and
 * delegates the actual LLM call to scripts/providers/<name>.mjs.
 *
 * Providers currently supported: anthropic, openai.
 * (Gemini is wired into the dispatcher shape but not implemented yet.)
 *
 * Usage:
 *   ANTHROPIC_API_KEY=sk-...  node llm_analyze.mjs --diff=diff.json
 *   OPENAI_API_KEY=sk-...     node llm_analyze.mjs --diff=diff.json --provider=openai
 *   node extract_diff.mjs --against=main | node llm_analyze.mjs --provider=openai --model=cheap
 *   node llm_analyze.mjs --diff=diff.json --provider=anthropic --model=haiku
 *   node llm_analyze.mjs --diff=diff.json --dry-run
 *   node llm_analyze.mjs --list-models    # show what each provider knows
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { buildGroundingBlocks, buildUserMessage, ProviderError } from './providers/_common.mjs';
import * as anthropic from './providers/anthropic.mjs';
import * as openai from './providers/openai.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SKILL_ROOT = path.resolve(__dirname, '..');

const TOOL_NAME = 'security-audit';
const TOOL_VERSION = '0.1.0';

// Provider registry — adding Gemini later means importing + adding here.
const PROVIDERS = {
  anthropic,
  openai,
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
 * Resolve which provider to use. Order:
 *   1. Explicit `--provider=X` (or options.provider, or SECURITY_AUDIT_PROVIDER env)
 *   2. Auto-detect from env keys:
 *        - if BOTH ANTHROPIC_API_KEY and OPENAI_API_KEY are set, prefer Anthropic
 *          (rationale below) and emit a one-line stderr notice so the choice is
 *          visible. Set --provider= explicitly to override permanently.
 *        - otherwise use whichever single key is set.
 *   3. Throw with a helpful message if no key is set.
 *
 * Why Anthropic wins ties:
 *   - Anthropic's explicit `cache_control` markers give ~90% cache-read discount,
 *     versus OpenAI's auto-prefix caching at ~50%. For our grounding-heavy
 *     workload (~12K stable tokens per call) that is a 2× cost difference once
 *     the cache is warm.
 *   - This is a heuristic, not a quality claim. Either provider produces valid
 *     output. Users who prefer OpenAI should pin --provider=openai (or
 *     SECURITY_AUDIT_PROVIDER=openai) to avoid the stderr notice.
 */
export function pickProvider(explicit) {
  if (explicit && explicit !== 'auto') {
    const p = PROVIDERS[explicit];
    if (!p) {
      throw new Error(`Unknown provider: '${explicit}'. Available: ${Object.keys(PROVIDERS).join(', ')}`);
    }
    return p;
  }
  const hasAnthropic = !!process.env.ANTHROPIC_API_KEY;
  const hasOpenAI = !!process.env.OPENAI_API_KEY;
  if (hasAnthropic && hasOpenAI) {
    // Quiet by default during dry-runs / tests; visible during real CLI use.
    if (process.stderr.isTTY || process.env.SECURITY_AUDIT_DEBUG === '1') {
      process.stderr.write(
        "[security-audit] Both ANTHROPIC_API_KEY and OPENAI_API_KEY are set — using anthropic by default " +
        "(cheaper with prompt caching). Pass --provider=openai or set SECURITY_AUDIT_PROVIDER=openai to override.\n"
      );
    }
    return anthropic;
  }
  if (hasAnthropic) return anthropic;
  if (hasOpenAI) return openai;
  throw new Error(
    'No provider API key found in environment. Set one of:\n' +
    '  ANTHROPIC_API_KEY  (use Claude; preferred when both are set, see pickProvider docs)\n' +
    '  OPENAI_API_KEY     (use GPT)\n' +
    'Or pass --dry-run to skip the API call.'
  );
}

/**
 * Core analyzer. Builds grounding payload once, then asks the chosen provider
 * to call the LLM. Returns a normalized report with provider/model/cost meta.
 *
 * @param {Object} diffJson           — output of extract_diff.mjs
 * @param {Object} [options]
 * @param {string} [options.provider] — 'anthropic' | 'openai' | 'auto'
 * @param {string} [options.model]    — alias or exact model id (passed to provider)
 * @param {string} [options.apiKey]   — overrides env (provider-specific)
 * @param {boolean} [options.dryRun]  — skip API call, return assembled prompt summary
 */
export async function analyzeDiff(diffJson, options = {}) {
  const grounding = loadGroundingDocs();
  const groundingBlocks = buildGroundingBlocks({
    system: grounding.system,
    fewShot: grounding.fewShot,
    owaspRules: grounding.owaspRules,
    owaspMapping: grounding.owaspMapping,
  });
  const userMessage = buildUserMessage(diffJson);

  if (options.dryRun) {
    const provider = options.provider && options.provider !== 'auto' ? options.provider : 'auto';
    return {
      dry_run: true,
      provider,
      model_input: options.model || '(provider default)',
      grounding_blocks: groundingBlocks.length,
      grounding_chars: groundingBlocks.reduce((n, b) => n + b.text.length, 0),
      user_chars: userMessage.length,
      preview: {
        first_block_head: groundingBlocks[0].text.slice(0, 300),
        user_head: userMessage.slice(0, 300),
      },
    };
  }

  const provider = pickProvider(options.provider);
  const result = await provider.analyze({
    groundingBlocks,
    userMessage,
    model: options.model,
    apiKey: options.apiKey,
  });

  return {
    ...result,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    scanned_at: new Date().toISOString(),
    // Mirror cost_usd → cost (back-compat) and keep cost_usd as canonical
    cost: result.cost_usd,
  };
}

// =============================================================================
// CLI
// =============================================================================

async function readStdin() {
  let data = '';
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

async function main() {
  const { values } = parseArgs({
    options: {
      diff: { type: 'string' },
      provider: { type: 'string', default: 'auto' },
      model: { type: 'string' },
      'dry-run': { type: 'boolean', default: false },
      'list-models': { type: 'boolean', default: false },
      help: { type: 'boolean', default: false },
    },
    strict: true,
  });

  if (values.help) {
    process.stdout.write(`Usage: node llm_analyze.mjs [--diff=path] [--provider=auto|anthropic|openai] [--model=ALIAS|ID] [--dry-run]

Provider selection (default: auto):
  --provider=anthropic        Use Claude (ANTHROPIC_API_KEY required)
  --provider=openai           Use GPT      (OPENAI_API_KEY required)
  --provider=auto             Pick first provider whose env key is set

Model aliases:
  anthropic:  sonnet (default), haiku, opus, or any claude-* id
  openai:     best (gpt-4o, default), cheap (gpt-4o-mini), 4o, mini, o1, o3-mini, ...

Other:
  --list-models               Show all model aliases known per provider
  --dry-run                   Don't call API; emit assembled prompt summary
  --help                      This message
`);
    process.exit(0);
  }

  if (values['list-models']) {
    for (const [name, p] of Object.entries(PROVIDERS)) {
      process.stdout.write(`${name} (env: ${p.ENV_KEY}, default alias: ${p.DEFAULT_MODEL_ALIAS}):\n`);
      for (const m of p.listModels()) process.stdout.write(`  ${m}\n`);
      process.stdout.write('\n');
    }
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

  try {
    const result = await analyzeDiff(diffJson, {
      provider: values.provider,
      model: values.model,
      dryRun: values['dry-run'],
    });
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } catch (err) {
    if (err instanceof ProviderError) {
      console.error(`llm_analyze: ${err.message}`);
    } else {
      console.error(`llm_analyze: ${err.message}`);
    }
    process.exit(2);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main();
