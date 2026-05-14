#!/usr/bin/env node
/**
 * collect_oss_diffs_api.mjs — `gh`-free alternative that reads public PR
 * diffs via the GitHub REST API. Unauthenticated calls are rate-limited
 * to 60/hour, which is enough for ≤ 10 repos × 5 PRs per scrape.
 *
 * The expected JSON stub is created identically to collect_oss_diffs.mjs;
 * the operator hand-labels it the same way (see docs/OSS_AUDIT_PLAYBOOK.md).
 *
 * Usage:
 *   node scripts/collect_oss_diffs_api.mjs --per-repo=5 --max-files=5
 *   node scripts/collect_oss_diffs_api.mjs --dry-run
 *   GITHUB_TOKEN=ghp_... node scripts/collect_oss_diffs_api.mjs   # 5000/hr quota
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const DEFAULT_TARGETS = path.join(ROOT, 'benchmark/oss_pilot/targets.json');
const OUT_DIR = path.join(ROOT, 'benchmark/oss_pilot');

async function gh(pathPart, accept = 'application/vnd.github+json') {
  const headers = {
    'User-Agent': 'security-audit-oss-collector',
    Accept: accept,
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  const res = await fetch(`https://api.github.com${pathPart}`, { headers });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`GET ${pathPart} → ${res.status} ${res.statusText}: ${body.slice(0, 200)}`);
  }
  return res;
}

function safeSlug(s) {
  return s.replace(/[^A-Za-z0-9_.-]+/g, '_');
}

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

async function processRepo(repo, opts) {
  process.stderr.write(`▶ ${repo}\n`);
  let prs;
  try {
    const res = await gh(`/repos/${repo}/pulls?state=closed&per_page=${opts.perRepo * 3}&sort=updated&direction=desc`);
    prs = await res.json();
  } catch (e) {
    process.stderr.write(`  ✗ list failed: ${e.message.slice(0, 120)}\n`);
    return [];
  }
  // Keep only merged (not just closed)
  prs = prs.filter(p => p.merged_at).slice(0, opts.perRepo);
  if (prs.length === 0) {
    process.stderr.write('  (no merged PRs in this slice)\n');
    return [];
  }

  const accepted = [];
  for (const pr of prs) {
    // `additions` and `changed_files` are not returned on the list endpoint;
    // they live on the individual PR. Skip pre-filtering and rely on diff
    // stats computed below.
    let diff;
    try {
      const res = await gh(`/repos/${repo}/pulls/${pr.number}`, 'application/vnd.github.v3.diff');
      diff = await res.text();
    } catch (e) {
      process.stderr.write(`  ✗ PR #${pr.number}: diff fetch failed (${e.message.slice(0, 100)})\n`);
      continue;
    }
    const stats = diffStats(diff);
    if (stats.files > opts.maxFiles) {
      process.stderr.write(`  ✗ PR #${pr.number}: diff has ${stats.files} files > ${opts.maxFiles} limit\n`);
      continue;
    }
    if (stats.addedLines + stats.removedLines > opts.maxLines) {
      process.stderr.write(`  ✗ PR #${pr.number}: ${stats.addedLines + stats.removedLines} lines > ${opts.maxLines}\n`);
      continue;
    }
    if (stats.addedLines + stats.removedLines < opts.minAdditions) {
      process.stderr.write(`  ✗ PR #${pr.number}: ${stats.addedLines + stats.removedLines} lines < ${opts.minAdditions} (too trivial)\n`);
      continue;
    }
    accepted.push({ repo, pr, diff, stats });
    process.stderr.write(`  ✓ PR #${pr.number}: ${stats.files} file(s), +${stats.addedLines}/-${stats.removedLines}\n`);
  }
  return accepted;
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
    process.stdout.write(`Usage: node scripts/collect_oss_diffs_api.mjs [options]

REST-API variant of collect_oss_diffs.mjs — does NOT require gh CLI.
Unauthenticated rate limit: 60 requests/hour. Set GITHUB_TOKEN env for 5000/hr.

  --targets=PATH       JSON file with list of repos
  --per-repo=N         Fetch up to N most-recent merged PRs per repo (default: 3)
  --max-files=N        Skip PRs with more changed files than N (default: 5)
  --max-lines=N        Skip PRs whose +/- line total exceeds N (default: 200)
  --min-additions=N    Skip trivially-small PRs (default: 5)
  --dry-run            Preview only, no writes
`);
    process.exit(0);
  }

  const cfg = JSON.parse(fs.readFileSync(values.targets, 'utf8'));
  const opts = {
    perRepo:      parseInt(values['per-repo'], 10),
    maxFiles:     parseInt(values['max-files'], 10),
    maxLines:     parseInt(values['max-lines'], 10),
    minAdditions: parseInt(values['min-additions'], 10),
  };

  process.stderr.write(`📋 collecting from ${cfg.repos.length} repo(s) — up to ${opts.perRepo} merged PR(s) per repo\n`);
  if (!process.env.GITHUB_TOKEN) {
    process.stderr.write('⚠  no GITHUB_TOKEN — rate-limited to 60 req/hour\n');
  }
  process.stderr.write('\n');

  let total = 0;
  for (const repo of cfg.repos) {
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
          source: {
            repo,
            pr: pr.number,
            html_url: pr.html_url,
            merged_at: pr.merged_at,
            title: pr.title,
            stats,
          },
          expected: [],
          expect_zero_findings: null,
          unlabeled: true,
          notes: 'Awaiting human ground-truth labelling. See docs/OSS_AUDIT_PLAYBOOK.md.',
        }, null, 2) + '\n');
      }
    }
  }

  process.stderr.write(`\n✓ ${total} PR diff(s) ${values['dry-run'] ? 'previewed' : 'staged'}\n`);
}

main().catch(err => {
  process.stderr.write(`collect_oss_diffs_api: ${err.stack || err.message}\n`);
  process.exit(1);
});
