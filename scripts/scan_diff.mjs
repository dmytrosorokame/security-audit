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
import { validateReport, normalizeFinding } from './validate_finding.mjs';
import { formatReport as formatCli } from './format_cli.mjs';
import { formatPrComment } from './format_pr_comment.mjs';
import { formatSarif } from './format_sarif.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const EXTRACT_DIFF = path.join(__dirname, 'extract_diff.mjs');

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

function debug(...args) {
  if (process.env.SECURITY_AUDIT_DEBUG === '1') {
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

function printHelp() {
  process.stdout.write(`security-audit — LLM-driven diff security review

Usage:
  scan-diff [extraction-mode] [options]

Extraction modes (pick one):
  --against=<ref>          Compare against a git ref (e.g. main, origin/main, HEAD~1)
  --staged                 Use staged changes (pre-commit mode)
  --diff=<file>            Parse an existing unified diff file

Options:
  --format=<fmt>           cli | pr | sarif | json (default: cli)
  --output=<file>          Write output to file (default: stdout)
  --fail-on=<sev>          critical | high | medium | low | info (default: critical)
  --model=<m>              sonnet (default) | haiku | <exact-model-id>
  --context=<n>            Lines of context around hunks (default: 10)
  --include=<glob>         File include pattern (repeatable)
  --exclude=<glob>         File exclude pattern (repeatable)
  --max-files=<n>          Cap files in diff (default: 50)
  --commit-sha=<sha>       Commit SHA to display in PR comment
  --dry-run                Build prompt but skip API call
  --help                   Show this help

Environment:
  ANTHROPIC_API_KEY        Required for live runs

Exit codes:
  0  ok                    No findings, or all below --fail-on
  2  blocked               At least one finding at/above --fail-on
  3  error                 Extraction failed, API error, etc.

Examples:
  scan-diff --against=main --format=pr --commit-sha=$GITHUB_SHA
  scan-diff --staged --fail-on=critical
  scan-diff --diff=patch.diff --format=sarif --output=report.sarif
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
        model: { type: 'string' },
        context: { type: 'string', default: '10' },
        include: { type: 'string', multiple: true, default: [] },
        exclude: { type: 'string', multiple: true, default: [] },
        'max-files': { type: 'string', default: '50' },
        'commit-sha': { type: 'string' },
        'no-color': { type: 'boolean', default: false },
        'dry-run': { type: 'boolean', default: false },
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
  let report;
  try {
    report = await analyzeDiff(diffJson, {
      model,
      dryRun: values['dry-run'],
    });
    debug('analyzed', { findings: report.findings?.length, cost: report.cost });
  } catch (e) {
    process.stderr.write(`scan_diff: LLM analysis failed: ${e.message}\n`);
    process.exit(3);
  }

  if (values['dry-run']) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    process.exit(0);
  }

  // === 3. Validate + normalize ===
  report.diff_stats = diffJson.stats;
  const validation = validateReport(report, { diff: diffJson });
  if (!validation.valid) {
    debug('validation errors:', validation.errors);
    // Don't hard-fail on schema issues — annotate and continue. LLM occasionally
    // returns slightly off-spec output; we still want to surface what we got.
    report._validation_warnings = validation.errors;
  }
  report.findings = (report.findings || []).map(normalizeFinding);

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
