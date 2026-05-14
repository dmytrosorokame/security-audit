#!/usr/bin/env node
/**
 * collect_oss_diffs.mjs — pull recent merged-PR diffs from a list of public
 * OSS repositories and stage them as benchmark inputs.
 *
 * What it does:
 *   1. Reads a target list (default: benchmark/oss_pilot/targets.json).
 *   2. For each repo, calls `gh pr list --state=merged --limit=N` to find
 *      recent PRs, then `gh pr diff <num>` to fetch the unified diff.
 *   3. Filters by:
 *        - --max-files: skip PRs touching too many files
 *        - --max-lines: skip PRs above changed-lines budget
 *        - --include-glob: keep only PRs that touched matching paths
 *   4. Writes each accepted PR as `benchmark/oss_pilot/diffs/<repo>__pr<N>.diff`
 *      and creates a stub expected JSON at
 *      `benchmark/oss_pilot/expected/<repo>__pr<N>.json` with `expected: []`
 *      and `expect_zero_findings: null` (UNLABELED) for the operator to fill in.
 *
 * Why this exists:
 *   The point of the OSS pilot is to test the analyzer on diffs the catalog
 *   author has never seen — true external validity. Hand-fetching PR diffs is
 *   tedious and error-prone; automating the collection (but NOT the labelling)
 *   is the right separation of concerns.
 *
 * Prerequisites:
 *   - `gh` CLI installed and authenticated (`gh auth status` must pass)
 *   - Network access to api.github.com
 *
 * Usage:
 *   node scripts/collect_oss_diffs.mjs                          # use default targets
 *   node scripts/collect_oss_diffs.mjs --targets=path/to/list.json
 *   node scripts/collect_oss_diffs.mjs --per-repo=5 --max-files=10
 *   node scripts/collect_oss_diffs.mjs --dry-run                # preview only, no writes
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const DEFAULT_TARGETS = path.join(ROOT, 'benchmark/oss_pilot/targets.json');
const OUT_DIR = path.join(ROOT, 'benchmark/oss_pilot');

function sh(cmd, args, opts = {}) {
  try {
    return execFileSync(cmd, args, { encoding: 'utf8', maxBuffer: 200 * 1024 * 1024, ...opts });
  } catch (e) {
    const msg = e.stderr?.toString() || e.message;
    throw new Error(`${cmd} ${args.join(' ')} failed: ${msg.trim()}`);
  }
}

function checkGhAuth() {
  try {
    sh('gh', ['auth', 'status'], { stdio: ['ignore', 'ignore', 'pipe'] });
  } catch (e) {
    process.stderr.write(
      '✗ gh CLI not authenticated. Run `gh auth login` first.\n' +
      `  underlying error: ${e.message}\n`,
    );
    process.exit(2);
  }
}

/**
 * Parse the diff text to count file changes and line deltas.
 * Returns { files, addedLines, removedLines }.
 */
function diffStats(text) {
  let files = 0, addedLines = 0, removedLines = 0;
  for (const line of text.split('\n')) {
    if (line.startsWith('diff --git ')) files++;
    else if (line.startsWith('+++')) continue;
    else if (line.startsWith('---')) continue;
    else if (line.startsWith('+')) addedLines++;
    else if (line.startsWith('-')) removedLines++;
  }
  return { files, addedLines, removedLines };
}

function safeSlug(s) {
  return s.replace(/[^A-Za-z0-9_.-]+/g, '_');
}

async function processRepo(repo, opts) {
  process.stderr.write(`▶ ${repo}\n`);
  const listJson = sh('gh', [
    'pr', 'list',
    '--repo', repo,
    '--state', 'merged',
    '--limit', String(opts.perRepo),
    '--json', 'number,title,mergedAt,additions,deletions,changedFiles',
  ]);
  const prs = JSON.parse(listJson);
  if (!Array.isArray(prs) || prs.length === 0) {
    process.stderr.write('  (no merged PRs found)\n');
    return [];
  }

  const accepted = [];
  for (const pr of prs) {
    const reason = filterReason(pr, opts);
    if (reason) {
      process.stderr.write(`  ✗ PR #${pr.number}: ${reason}\n`);
      continue;
    }
    let diff;
    try {
      diff = sh('gh', ['pr', 'diff', String(pr.number), '--repo', repo]);
    } catch (e) {
      process.stderr.write(`  ✗ PR #${pr.number}: diff fetch failed (${e.message.slice(0, 100)})\n`);
      continue;
    }
    const stats = diffStats(diff);
    if (stats.files > opts.maxFiles) {
      process.stderr.write(`  ✗ PR #${pr.number}: ${stats.files} files > ${opts.maxFiles} limit\n`);
      continue;
    }
    if (stats.addedLines + stats.removedLines > opts.maxLines) {
      process.stderr.write(`  ✗ PR #${pr.number}: ${stats.addedLines + stats.removedLines} lines > ${opts.maxLines} limit\n`);
      continue;
    }
    accepted.push({ repo, pr, diff, stats });
    process.stderr.write(`  ✓ PR #${pr.number}: ${stats.files} file(s), +${stats.addedLines}/-${stats.removedLines}\n`);
  }
  return accepted;
}

function filterReason(pr, opts) {
  if (opts.minAdditions != null && pr.additions < opts.minAdditions) {
    return `too small (additions=${pr.additions} < ${opts.minAdditions})`;
  }
  if (pr.changedFiles > opts.maxFiles) {
    return `too many files (${pr.changedFiles} > ${opts.maxFiles})`;
  }
  return null;
}

async function main() {
  const { values } = parseArgs({
    options: {
      targets:        { type: 'string', default: DEFAULT_TARGETS },
      'per-repo':     { type: 'string', default: '3' },
      'max-files':    { type: 'string', default: '5' },
      'max-lines':    { type: 'string', default: '200' },
      'min-additions':{ type: 'string', default: '5' },
      'dry-run':      { type: 'boolean', default: false },
      help:           { type: 'boolean', default: false },
    },
    strict: true,
  });

  if (values.help) {
    process.stdout.write(`Usage: node scripts/collect_oss_diffs.mjs [options]

  --targets=PATH        JSON file with list of repos (default: ${path.relative(ROOT, DEFAULT_TARGETS)})
  --per-repo=N          Fetch up to N most-recent merged PRs per repo (default: 3)
  --max-files=N         Skip PRs touching more files than N (default: 5)
  --max-lines=N         Skip PRs whose +/- line total exceeds N (default: 200)
  --min-additions=N     Skip trivially-small PRs (default: 5)
  --dry-run             Preview what would be fetched, do not write anything
  --help                This message
`);
    process.exit(0);
  }

  checkGhAuth();

  const targetsRaw = fs.readFileSync(values.targets, 'utf8');
  const config = JSON.parse(targetsRaw);
  if (!Array.isArray(config.repos)) {
    process.stderr.write(`✗ targets file ${values.targets} must have a "repos" array\n`);
    process.exit(2);
  }

  const opts = {
    perRepo:      parseInt(values['per-repo'], 10),
    maxFiles:     parseInt(values['max-files'], 10),
    maxLines:     parseInt(values['max-lines'], 10),
    minAdditions: parseInt(values['min-additions'], 10),
  };

  process.stderr.write(`📋 collecting from ${config.repos.length} repo(s) — up to ${opts.perRepo} PR(s) per repo\n`);
  process.stderr.write(`   filters: ≤${opts.maxFiles} files, ≤${opts.maxLines} changed lines, ≥${opts.minAdditions} additions\n\n`);

  let total = 0;
  for (const repo of config.repos) {
    const accepted = await processRepo(repo, opts);
    total += accepted.length;
    if (values['dry-run']) continue;

    fs.mkdirSync(path.join(OUT_DIR, 'diffs'), { recursive: true });
    fs.mkdirSync(path.join(OUT_DIR, 'expected'), { recursive: true });

    for (const { pr, diff, stats } of accepted) {
      const slug = safeSlug(`${repo.replace('/', '__')}__pr${pr.number}`);
      const diffPath = path.join(OUT_DIR, 'diffs', `${slug}.diff`);
      const expectedPath = path.join(OUT_DIR, 'expected', `${slug}.json`);
      fs.writeFileSync(diffPath, diff);
      if (!fs.existsSync(expectedPath)) {
        fs.writeFileSync(expectedPath, JSON.stringify({
          name: `[UNLABELED] ${repo} PR #${pr.number}: ${pr.title}`,
          diff: path.relative(path.dirname(expectedPath), diffPath),
          source: { repo, pr: pr.number, mergedAt: pr.mergedAt, title: pr.title, stats },
          expected: [],
          expect_zero_findings: null,
          unlabeled: true,
          notes: 'Awaiting human ground-truth labelling. See docs/OSS_AUDIT_PLAYBOOK.md.',
        }, null, 2) + '\n');
      } else {
        process.stderr.write(`  (kept existing labels at ${path.relative(ROOT, expectedPath)})\n`);
      }
    }
  }

  process.stderr.write(`\n✓ ${total} PR diff(s) ${values['dry-run'] ? 'previewed' : 'staged'}\n`);
  if (!values['dry-run'] && total > 0) {
    process.stderr.write(`  next: hand-label each ${path.relative(process.cwd(), path.join(OUT_DIR, 'expected'))}/*.json (see docs/OSS_AUDIT_PLAYBOOK.md)\n`);
  }
}

main().catch(err => {
  process.stderr.write(`collect_oss_diffs: ${err.stack || err.message}\n`);
  process.exit(1);
});
