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

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

import { buildGroundingBlocks, buildUserMessage, ProviderError, envBool } from './providers/_common.mjs';
import { redactSecrets } from './validate_finding.mjs';
import * as anthropic from './providers/anthropic.mjs';
import * as openai from './providers/openai.mjs';
import { TOOL_NAME, TOOL_VERSION } from './version.mjs';

// Cache entries older than this are treated as missing. 24h is long enough to
// span a working session (so re-runs while iterating on suppressions are free)
// but short enough that grounding catalog changes propagate within a day.
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SKILL_ROOT = path.resolve(__dirname, '..');

// Provider registry — adding Gemini later means importing + adding here.
const PROVIDERS = {
  anthropic,
  openai,
};

// Grounding docs are stable across calls within a process (they're tracked
// files in the install dir). Cache at module load so batch invocations don't
// re-read 50K+ chars of markdown for every single PR.
let _groundingCache = null;
function loadGroundingDocs() {
  if (_groundingCache) return _groundingCache;
  _groundingCache = {
    system: fs.readFileSync(path.join(SKILL_ROOT, 'prompts/system.md'), 'utf8'),
    fewShot: fs.readFileSync(path.join(SKILL_ROOT, 'prompts/few_shot.md'), 'utf8'),
    owaspRules: fs.readFileSync(path.join(SKILL_ROOT, 'references/owasp-rules.md'), 'utf8'),
    owaspMapping: fs.readFileSync(path.join(SKILL_ROOT, 'references/owasp-mapping.md'), 'utf8'),
  };
  return _groundingCache;
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
    if (process.stderr.isTTY || envBool('SECURITY_AUDIT_DEBUG')) {
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
 * @param {Object} diffJson            — output of extract_diff.mjs
 * @param {Object} [options]
 * @param {string} [options.provider]   — 'anthropic' | 'openai' | 'auto'
 * @param {string} [options.model]      — alias or exact model id (passed to provider)
 * @param {string} [options.apiKey]     — overrides env (provider-specific)
 * @param {boolean} [options.dryRun]    — skip API call, return assembled prompt summary
 * @param {number}  [options.timeoutMs] — abort LLM call after N ms (0 = no timeout)
 * @param {string|null} [options.cacheDir] — file-based cache directory; null disables
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

  // === Cache lookup (file-based) ============================================
  // Cache key = sha256(provider.NAME | model | grounding_hash | userMessage).
  // grounding_hash captures system prompt + catalog + mapping + few-shot so any
  // edit to those invalidates all prior results. The diff text is in
  // userMessage so different PRs hit different keys.
  const cacheKey = options.cacheDir
    ? computeCacheKey(provider.NAME, provider.resolveModel(options.model), groundingBlocks, userMessage)
    : null;
  if (options.cacheDir && cacheKey) {
    const hit = readCache(options.cacheDir, cacheKey);
    if (hit) {
      return {
        ...hit,
        tool: { name: TOOL_NAME, version: TOOL_VERSION },
        scanned_at: new Date().toISOString(),
        cache_hit: true,
        cost: hit.cost_usd ?? hit.cost ?? 0,
      };
    }
  }

  const result = await provider.analyze({
    groundingBlocks,
    userMessage,
    model: options.model,
    apiKey: options.apiKey,
    timeoutMs: options.timeoutMs || 0,
  });

  if (options.cacheDir && cacheKey) {
    // Redact secrets BEFORE persisting the LLM response. The cache file is
    // long-lived (24h TTL) and may be read by anyone with filesystem access;
    // we treat it as a public-readable artefact and strip secret material
    // pro-actively rather than relying on downstream redaction (which only
    // protects the output channel, not the cache itself).
    writeCache(options.cacheDir, cacheKey, redactReportSecrets(result));
  }

  return {
    ...result,
    tool: { name: TOOL_NAME, version: TOOL_VERSION },
    scanned_at: new Date().toISOString(),
    cache_hit: false,
    // Mirror cost_usd → cost (back-compat) and keep cost_usd as canonical
    cost: result.cost_usd,
  };
}

/**
 * Strip secrets from every finding's prose fields before persisting to the
 * file cache. Mirrors `normalizeFinding` redaction but is independent from it
 * — we want defence-in-depth: even if normalisation is skipped or the cache
 * is read by a different code path, secrets stay out of the on-disk artefact.
 *
 * Only the strings the user might recognise as exfiltration vectors are
 * touched (evidence, rationale, remediation). Metadata stays as-is.
 *
 * @param {object} report
 * @returns {object} a shallow copy with redacted findings + suppressed_findings
 */
export function redactReportSecrets(report) {
  if (!report || typeof report !== 'object') return report;
  const scrub = (f) => {
    if (!f || typeof f !== 'object') return f;
    const out = { ...f };
    if (typeof out.evidence === 'string')    out.evidence    = redactSecrets(out.evidence);
    if (typeof out.rationale === 'string')   out.rationale   = redactSecrets(out.rationale);
    if (typeof out.remediation === 'string') out.remediation = redactSecrets(out.remediation);
    return out;
  };
  return {
    ...report,
    findings: Array.isArray(report.findings) ? report.findings.map(scrub) : report.findings,
    suppressed_findings: Array.isArray(report.suppressed_findings)
      ? report.suppressed_findings.map(scrub)
      : report.suppressed_findings,
  };
}

export function computeCacheKey(providerName, model, groundingBlocks, userMessage) {
  const groundingHash = crypto.createHash('sha256');
  for (const b of groundingBlocks) groundingHash.update(b.text);
  const userHash = crypto.createHash('sha256').update(userMessage).digest('hex');
  return crypto
    .createHash('sha256')
    .update(`${providerName}|${model}|${groundingHash.digest('hex')}|${userHash}`)
    .digest('hex');
}

export function readCache(cacheDir, key) {
  const file = path.join(cacheDir, key + '.json');
  try {
    if (!fs.existsSync(file)) return null;
    const stat = fs.statSync(file);
    if (Date.now() - stat.mtimeMs > CACHE_TTL_MS) return null;
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    // Corrupt cache entry: silently miss rather than crash the scan, but
    // surface the why under DEBUG so a confused user (e.g. "why is
    // --seeds=3 burning N API calls instead of 1?") can trace the cause
    // instead of staring at a tidy "cache_hit: false" with no signal.
    if (envBool('SECURITY_AUDIT_DEBUG')) {
      process.stderr.write(`[security-audit] cache read failed for ${path.basename(file)} (${e.message}); treating as miss.\n`);
    }
    return null;
  }
}

export function writeCache(cacheDir, key, value) {
  try {
    fs.mkdirSync(cacheDir, { recursive: true });
    // Atomic write: tmp file + rename. Prevents partial reads if a concurrent
    // process opens the file mid-write (rare but possible in parallel scans).
    //
    // The tmp filename MUST be unique per writer — a shared `${key}.tmp` (the
    // previous implementation) races when two processes compute the same
    // cache key (same diff, same provider, same model, e.g. `--seeds=N` in
    // parallel shells). Both call writeFileSync on the same path, the second
    // overwrites the first mid-flush, and the surviving rename publishes a
    // corrupt or partial body. `rename` itself is atomic per *name*, not per
    // *content* — uniqueness on the source path is what gives us safety.
    const tmp = path.join(cacheDir, `${key}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`);
    const final = path.join(cacheDir, key + '.json');
    fs.writeFileSync(tmp, JSON.stringify(value, null, 2));
    fs.renameSync(tmp, final);
  } catch (e) {
    if (envBool('SECURITY_AUDIT_DEBUG')) {
      process.stderr.write(`[security-audit] cache write failed (${e.message}); continuing without cache.\n`);
    }
  }
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
      timeout: { type: 'string' },
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
  --timeout=N                 Abort the LLM call after N seconds (default: no timeout)
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
    let timeoutMs = 0;
    if (values.timeout != null && values.timeout !== '') {
      const parsed = Number(values.timeout);
      if (!Number.isFinite(parsed) || parsed < 0 || !Number.isInteger(parsed)) {
        console.error(`llm_analyze: invalid --timeout=${values.timeout} (expected a non-negative integer of seconds)`);
        process.exit(2);
      }
      timeoutMs = parsed * 1000;
    }
    const result = await analyzeDiff(diffJson, {
      provider: values.provider,
      model: values.model,
      dryRun: values['dry-run'],
      timeoutMs,
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
