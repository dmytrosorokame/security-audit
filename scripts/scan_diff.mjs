#!/usr/bin/env node
/**
 * scan_diff.mjs — main entry point.
 *
 * Pipeline:
 *   1. Extract diff (git diff vs base / staged / from file)
 *   2. Analyze diff with Claude (cached grounding + diff)
 *   3. Validate + normalize findings (schema, risk_score)
 *   4. Format output (cli | pr | sarif | json)
 *   5. Exit with code based on severity gate
 *
 * Exit codes:
 *   0 — no findings, or findings below --fail-on threshold
 *   1 — findings present but none meet --fail-on threshold (reserved for future)
 *   2 — at least one finding at or above --fail-on threshold (blocks CI)
 *   3 — tool error (extraction failed, API down, schema invalid)
 *
 * Usage:
 *   scan-diff --against=main
 *   scan-diff --staged --fail-on=critical
 *   scan-diff --diff=path/to.diff --format=sarif --output=report.sarif
 *   scan-diff --against=main --format=pr --commit-sha=$GITHUB_SHA
 *   scan-diff --against=main --dry-run    # don't call Claude
 *
 * Env vars:
 *   ANTHROPIC_API_KEY     — required for live runs
 *   SECURITY_AUDIT_MODEL  — overrides --model
 *   SECURITY_AUDIT_DEBUG  — '1' to print intermediate stages to stderr
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import { parseArgs } from 'node:util';

import { analyzeDiff } from './llm_analyze.mjs';
import { validateReport, validateFinding, normalizeFinding, correctFindingLine } from './validate_finding.mjs';
import { applySuppression } from './suppression.mjs';
import { formatReport as formatCli } from './format_cli.mjs';
import { formatPrComment } from './format_pr_comment.mjs';
import { formatSarif } from './format_sarif.mjs';
import { envBool } from './providers/_common.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const EXTRACT_DIFF = path.join(__dirname, 'extract_diff.mjs');

// `none` is a sentinel that never matches (Number.POSITIVE_INFINITY > every
// finding's rank), so --fail-on=none means "report only, never block".
const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4, none: Number.POSITIVE_INFINITY };

function debug(...args) {
  if (envBool('SECURITY_AUDIT_DEBUG')) {
    console.error('[scan_diff]', ...args);
  }
}

function runExtractDiff(args) {
  const out = execFileSync(process.execPath, [EXTRACT_DIFF, ...args], {
    encoding: 'utf8',
    maxBuffer: 200 * 1024 * 1024,
  });
  return JSON.parse(out);
}

/**
 * Find the git repo root from current cwd. Cached per process — repo root
 * does not change within a scan, and `git rev-parse` is a 5–20ms shell-out we
 * shouldn't pay on every batch iteration.
 *
 * Falls back to cwd if not in a repo.
 */
let _repoRootCache = null;
function findRepoRoot() {
  if (_repoRootCache !== null) return _repoRootCache;
  try {
    const out = execFileSync('git', ['rev-parse', '--show-toplevel'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    _repoRootCache = out || process.cwd();
  } catch {
    _repoRootCache = process.cwd();
  }
  return _repoRootCache;
}

function printHelp() {
  process.stdout.write(`security-audit — LLM-driven diff security review

Usage:
  scan-diff [extraction-mode] [options]

Extraction modes (pick one):
  --against=<ref>          Compare against a git ref (e.g. main, origin/main, HEAD~1)
  --staged                 Use staged changes (pre-commit mode)
  --diff=<file>            Parse an existing unified diff file

LLM options:
  --provider=<p>           auto (default) | anthropic | openai
                           auto picks based on which API key is in env
  --model=<m>              Provider-specific alias or exact model id.
                           anthropic: sonnet (default), haiku, opus, claude-*
                           openai:    best=gpt-4o (default), cheap=gpt-4o-mini, o1, ...

Output / filtering:
  --format=<fmt>           cli | pr | sarif | json (default: cli)
  --output=<file>          Write output to file (default: stdout)
  --fail-on=<sev>          critical | high | medium | low | info | none (default: critical)
                           'none' means report findings but never block (exit 0).
  --context=<n>            Lines of context around hunks (default: 10)
  --include=<glob>         File include pattern (repeatable)
  --exclude=<glob>         File exclude pattern (repeatable)
  --include-file-context   Attach full-file content for files with findings
                           (helps LLM disambiguate diffs that depend on global state)
  --max-files=<n>          Cap files in diff (default: 50)
  --commit-sha=<sha>       Commit SHA to display in PR comment
  --timeout=<sec>          Abort the LLM call after N seconds (default: no timeout)
  --max-cost=<usd>         Refuse scans whose reported cost exceeds this budget,
                           in USD (default: no cap). Useful for accidental large PRs.
  --cache-dir=<path>       File-based cache directory for LLM responses
                           (default: .security-audit-cache/ in repo root; use 'none' to disable)
  --no-cache               Disable file-based cache (alias for --cache-dir=none)
  --dry-run                Build prompt but skip API call
  --help                   Show this help

Environment (at least one required for live runs):
  ANTHROPIC_API_KEY        Use Claude
  OPENAI_API_KEY           Use GPT

Exit codes:
  0  ok                    No findings, or all below --fail-on
  2  blocked               At least one finding at/above --fail-on
  3  error                 Extraction failed, API error, etc.

Examples:
  scan-diff --against=main --format=pr --commit-sha=$GITHUB_SHA
  scan-diff --staged --fail-on=critical
  scan-diff --diff=patch.diff --provider=openai --model=cheap
  scan-diff --against=main --provider=anthropic --model=haiku
`);
}

async function main() {
  let values;
  try {
    ({ values } = parseArgs({
      options: {
        against: { type: 'string' },
        staged: { type: 'boolean', default: false },
        diff: { type: 'string' },
        format: { type: 'string', default: 'cli' },
        output: { type: 'string' },
        'fail-on': { type: 'string', default: 'critical' },
        provider: { type: 'string', default: 'auto' },
        model: { type: 'string' },
        context: { type: 'string', default: '10' },
        include: { type: 'string', multiple: true, default: [] },
        exclude: { type: 'string', multiple: true, default: [] },
        'include-file-context': { type: 'boolean', default: false },
        'max-files': { type: 'string', default: '50' },
        'commit-sha': { type: 'string' },
        'no-color': { type: 'boolean', default: false },
        'dry-run': { type: 'boolean', default: false },
        timeout: { type: 'string' },
        'max-cost': { type: 'string' },
        'cache-dir': { type: 'string' },
        'no-cache': { type: 'boolean', default: false },
        help: { type: 'boolean', default: false },
      },
      strict: true,
    }));
  } catch (e) {
    process.stderr.write(`scan_diff: ${e.message}\n`);
    process.stderr.write(`Run scan-diff --help for usage.\n`);
    process.exit(3);
  }

  if (values.help) { printHelp(); process.exit(0); }

  const failOn = values['fail-on'].toLowerCase();
  if (!(failOn in SEVERITY_RANK)) {
    process.stderr.write(`scan_diff: invalid --fail-on=${failOn}. Use one of: ${Object.keys(SEVERITY_RANK).join(', ')}\n`);
    process.exit(3);
  }

  // === 1. Extraction ===
  const extractArgs = [];
  if (values.against) extractArgs.push(`--against=${values.against}`);
  if (values.staged) extractArgs.push('--staged');
  if (values.diff) extractArgs.push(`--diff=${values.diff}`);
  extractArgs.push(`--context=${values.context}`);
  extractArgs.push(`--max-files=${values['max-files']}`);
  for (const inc of values.include || []) extractArgs.push(`--include=${inc}`);
  for (const exc of values.exclude || []) extractArgs.push(`--exclude=${exc}`);
  if (values['include-file-context']) extractArgs.push('--include-file-context');

  if (!values.against && !values.staged && !values.diff) {
    process.stderr.write('scan_diff: must specify one of --against=<ref>, --staged, or --diff=<file>\n');
    process.exit(3);
  }

  let diffJson;
  try {
    diffJson = runExtractDiff(extractArgs);
    debug('extracted', diffJson.stats);
  } catch (e) {
    process.stderr.write(`scan_diff: diff extraction failed: ${e.message}\n`);
    process.exit(3);
  }

  // Short-circuit on empty diff — no findings possible
  if (diffJson.files.length === 0) {
    const emptyReport = {
      schema_version: '1.0',
      tool: { name: 'security-audit', version: '0.1.0' },
      scanned_at: new Date().toISOString(),
      diff_stats: diffJson.stats,
      findings: [],
      summary: { total: 0, by_severity: {}, by_owasp: {} },
      non_security_observations: [],
      note: 'Diff was empty after filtering — no security review needed.',
    };
    emitReport(emptyReport, values);
    process.exit(0);
  }

  // === 2. LLM analysis ===
  const model = values.model || process.env.SECURITY_AUDIT_MODEL;
  const provider = values.provider || process.env.SECURITY_AUDIT_PROVIDER || 'auto';

  // `--timeout` must be a non-negative integer. Reject silent fallbacks: a user
  // typing `--timeout=5abc` (or `--timeout=foo`) deserves an error, not a
  // silently disabled timeout. `parseInt` accepts trailing junk, so we cross-
  // check the round-trip against the original string.
  let timeoutMs = 0;
  if (values.timeout != null && values.timeout !== '') {
    const parsed = Number(values.timeout);
    if (!Number.isFinite(parsed) || parsed < 0 || !Number.isInteger(parsed)) {
      process.stderr.write(`scan_diff: invalid --timeout=${values.timeout} (expected a non-negative integer of seconds)\n`);
      process.exit(3);
    }
    timeoutMs = parsed * 1000;
  }

  // `--no-cache` wins over `--cache-dir=...` (most specific intent: "don't cache"
  // shouldn't be silently overridden by a path env from a parent shell). Default
  // is `.security-audit-cache/` in repo root; explicit `none` also disables.
  let cacheDir = null;
  if (!values['no-cache']) {
    const requested = values['cache-dir'] ?? process.env.SECURITY_AUDIT_CACHE_DIR ?? '.security-audit-cache';
    if (requested && requested !== 'none' && requested !== 'false') {
      cacheDir = path.isAbsolute(requested) ? requested : path.join(findRepoRoot(), requested);
    }
  }

  let report;
  try {
    report = await analyzeDiff(diffJson, {
      provider,
      model,
      dryRun: values['dry-run'],
      timeoutMs,
      cacheDir,
    });
    debug('analyzed', {
      provider: report.provider,
      model: report.model,
      findings: report.findings?.length,
      cost: report.cost,
      cache_hit: report.cache_hit,
    });
  } catch (e) {
    process.stderr.write(`scan_diff: LLM analysis failed: ${e.message}\n`);
    process.exit(3);
  }

  // Budget guard: if the actual cost exceeded the user's --max-cost cap,
  // refuse to act on the report. The LLM call already happened (we can't
  // un-spend the dollars), but we surface a clear error rather than silently
  // proceeding — useful when a runaway PR (or a misconfigured loop) sends
  // an unexpectedly large diff in CI.
  if (values['max-cost'] != null && values['max-cost'] !== '') {
    const cap = Number(values['max-cost']);
    if (!Number.isFinite(cap) || cap < 0) {
      process.stderr.write(`scan_diff: invalid --max-cost=${values['max-cost']} (expected a non-negative number of USD)\n`);
      process.exit(3);
    }
    const actual = report.cost ?? report.cost_usd ?? 0;
    if (actual > cap) {
      process.stderr.write(
        `scan_diff: cost budget exceeded — actual $${actual.toFixed(6)} > cap $${cap.toFixed(6)}.\n` +
        `Output not emitted to avoid acting on results from an over-budget run. ` +
        `Use --max-cost=0 to disable the cap (not recommended).\n`,
      );
      process.exit(3);
    }
  }

  if (values['dry-run']) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    process.exit(0);
  }

  // === 3. Validate + normalize ===
  report.diff_stats = diffJson.stats;

  // 3a. Anti-hallucination pass:
  //     - Wrong file or line outside any hunk → hard-drop (real fabrication).
  //     - Evidence string not in diff content → hard-drop (LLM paraphrased
  //       and we can't trust the attribution).
  //     - Line points at a context-only row (LLM picked the wrong line within
  //       the right hunk) → auto-fix to the nearest `+` line in the same hunk.
  //       Live testing showed this is a common LLM failure mode that doesn't
  //       warrant dropping the finding.
  const sane = [];
  const hallucinated = [];
  const lineCorrected = [];
  for (let f of report.findings || []) {
    let r = validateFinding(f, { diff: diffJson });

    // Try to auto-correct line if the only anchor error is "context-only"
    const contextOnly = r.errors.find(e => e.includes('is context-only'));
    if (contextOnly) {
      const fileEntry = diffJson.files.find(x => x.path === f.file);
      const corrected = correctFindingLine(f, fileEntry);
      if (corrected && corrected !== f.line) {
        f = { ...f, line: corrected, line_corrected_from: f.line };
        // Re-validate after fix
        r = validateFinding(f, { diff: diffJson });
        lineCorrected.push(f.file + ':' + f.line);
      }
    }

    // Hard-drop conditions: file missing, line outside hunks, or evidence
    // string can't be found in the diff (LLM fabricated the quote).
    const hardDrop = r.errors.find(e =>
      e.startsWith("file '") ||
      (e.startsWith('line ') && e.includes('not in any hunk')) ||
      e.startsWith('evidence not found')
    );
    if (hardDrop) {
      hallucinated.push({ ...f, hallucination_reason: hardDrop });
    } else {
      sane.push(f);
    }
  }
  report.findings = sane.map(normalizeFinding);
  if (hallucinated.length > 0) {
    report.hallucinated_findings = hallucinated;
    debug(`dropped ${hallucinated.length} hallucinated findings`);
  }
  if (lineCorrected.length > 0) {
    report.line_corrections = lineCorrected.length;
    debug(`auto-corrected line numbers on ${lineCorrected.length} findings`);
  }

  // 3b. Full schema validation — surface the rest as warnings.
  const validation = validateReport(report, { diff: diffJson });
  if (!validation.valid) {
    debug('validation errors:', validation.errors);
    report._validation_warnings = validation.errors;
  }

  // 3c. Apply suppression: inline `// security-audit-ignore: <rule>` and
  //     repo-level .security-audit-ignore. Recomputes summary.
  const repoRoot = findRepoRoot();
  report = applySuppression(report, { diff: diffJson, repoRoot });
  if (report.suppressed_findings?.length) {
    debug(`suppressed ${report.suppressed_findings.length} findings`);
  }

  // === 4. Emit ===
  emitReport(report, values);

  // === 5. Exit code based on severity gate ===
  const failRank = SEVERITY_RANK[failOn];
  const triggers = (report.findings || []).filter(f => {
    if (f.verdict === 'FALSE_POSITIVE') return false;
    return (SEVERITY_RANK[f.severity] ?? -1) >= failRank;
  });
  if (triggers.length > 0) {
    debug(`exit 2: ${triggers.length} findings >= ${failOn}`);
    process.exit(2);
  }
  process.exit(0);
}

function emitReport(report, values) {
  const fmt = (values.format || 'cli').toLowerCase();
  let out;
  switch (fmt) {
    case 'json':
      out = JSON.stringify(report, null, 2) + '\n';
      break;
    case 'cli':
      out = formatCli(report, { color: !values['no-color'] && process.stdout.isTTY }) + '\n';
      break;
    case 'pr':
      out = formatPrComment(report, { commitSha: values['commit-sha'] }) + '\n';
      break;
    case 'sarif':
      out = JSON.stringify(formatSarif(report), null, 2) + '\n';
      break;
    default:
      process.stderr.write(`scan_diff: unknown --format=${fmt}\n`);
      process.exit(3);
  }
  if (values.output) {
    fs.writeFileSync(values.output, out);
    debug('wrote', values.output);
  } else {
    process.stdout.write(out);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(err => {
    process.stderr.write(`scan_diff: unexpected error: ${err.stack || err.message}\n`);
    process.exit(3);
  });
}
