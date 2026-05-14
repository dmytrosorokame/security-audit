#!/usr/bin/env node
/**
 * run_benchmark.mjs — orchestrates scan_diff.mjs over the example diffs in
 * `examples/` and compares output against ground truth in `benchmark/expected/`.
 *
 * For each case we classify the result as:
 *   - FULL_TP        — expected rule_id detected (strict match)
 *   - PARTIAL_TP     — owasp_id + cwe_id match but rule_id different
 *                      (e.g. R-01 vs R-02 for the same XSS sink family)
 *   - TRUE_NEGATIVE  — case was `expect_zero_findings` and tool returned none
 *   - FALSE_NEGATIVE — expected finding missing
 *   - FALSE_POSITIVE — finding emitted on a case marked `expect_zero_findings`
 *
 * Precision / recall / F1 are computed in two modes:
 *   - strict: only FULL_TP counts as TP. Partial matches count as FN.
 *   - loose:  FULL_TP and PARTIAL_TP both count as TP.
 *
 * We report both because strict matters for remediation routing (the rule_id
 * picks the cheat-sheet link and severity), while loose tracks "did we catch
 * the right vulnerability category at all."
 *
 * Usage:
 *   node benchmark/run_benchmark.mjs
 *   node benchmark/run_benchmark.mjs --seeds=3      # run each case 3x to measure variance
 *   node benchmark/run_benchmark.mjs --provider=anthropic --model=sonnet
 *   node benchmark/run_benchmark.mjs --no-write     # don't update results.md
 *   node benchmark/run_benchmark.mjs --dry-run      # smoke check, no API calls
 *   node benchmark/run_benchmark.mjs --case=01_dom_xss_introduction
 *
 * Exits 0 if F1 >= --min-f1 (default 0.6 strict / 0.8 loose), 1 otherwise.
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, '..');
const DEFAULT_CORPUS_DIR = path.join(__dirname, 'expected');
const RESULTS_FILE = path.join(__dirname, 'results.md');
const SCAN_DIFF = path.join(ROOT, 'scripts/scan_diff.mjs');

/**
 * Load all expected-JSON cases from a corpus directory.
 *
 * A "corpus" is any directory laid out as either:
 *   <dir>/<case>.json                 (legacy: smoke set in benchmark/expected/)
 *   <dir>/expected/<case>.json        (new: independent corpora with sibling diffs/)
 *
 * Both layouts are supported so the smoke set keeps working without migration
 * while independent corpora can keep their diffs co-located.
 *
 * @param {string} corpusDir — absolute or relative path to corpus root
 * @returns {Array<{id, corpus, name, diffPath, expected, expectZero, notes}>}
 */
function loadCases(corpusDir) {
  const abs = path.isAbsolute(corpusDir) ? corpusDir : path.resolve(corpusDir);
  if (!fs.existsSync(abs)) throw new Error(`corpus not found: ${corpusDir}`);
  // Prefer <dir>/expected/*.json if present (independent-corpus layout),
  // fall back to <dir>/*.json (legacy smoke-set layout).
  const expectedSubdir = path.join(abs, 'expected');
  const sourceDir = fs.existsSync(expectedSubdir) ? expectedSubdir : abs;
  const corpusLabel = path.relative(ROOT, abs) || path.basename(abs);
  const files = fs.readdirSync(sourceDir).filter(f => f.endsWith('.json')).sort();
  return files.map(f => {
    const raw = JSON.parse(fs.readFileSync(path.join(sourceDir, f), 'utf8'));
    const diffAbs = path.resolve(sourceDir, raw.diff);
    return {
      id: f.replace(/\.json$/, ''),
      corpus: corpusLabel,
      name: raw.name,
      diffPath: diffAbs,
      expected: raw.expected || [],
      expectZero: !!raw.expect_zero_findings,
      notes: raw.notes,
      cveReference: raw.cve_reference,
    };
  });
}

function runScan({ diffPath, provider, model, dryRun, timeoutSec, cacheDir }) {
  const args = [
    SCAN_DIFF,
    `--diff=${diffPath}`,
    `--format=json`,
    `--fail-on=none`,
  ];
  if (provider && provider !== 'auto') args.push(`--provider=${provider}`);
  if (model) args.push(`--model=${model}`);
  if (dryRun) args.push('--dry-run');
  if (timeoutSec) args.push(`--timeout=${timeoutSec}`);
  if (cacheDir) args.push(`--cache-dir=${cacheDir}`);

  const started = Date.now();
  let stdout;
  try {
    stdout = execFileSync(process.execPath, args, {
      encoding: 'utf8',
      maxBuffer: 200 * 1024 * 1024,
      env: { ...process.env, SECURITY_AUDIT_DEBUG: '' },
    });
  } catch (e) {
    // scan_diff exits 2 when findings >= --fail-on; we pass --fail-on=none so
    // exit 2 should never happen here. Anything non-zero is a real error.
    const msg = e.stdout?.toString() || e.stderr?.toString() || e.message;
    throw new Error(`scan_diff failed for ${path.basename(diffPath)}: ${msg.slice(0, 400)}`);
  }
  const wallMs = Date.now() - started;

  let report;
  try {
    report = JSON.parse(stdout);
  } catch {
    throw new Error(`scan_diff returned non-JSON for ${path.basename(diffPath)}: ${stdout.slice(0, 300)}`);
  }
  return { report, wallMs };
}

/**
 * Classify each expected finding against the actual findings list.
 * Returns: { results: [{expected, classification, matched}], extras: [...] }
 *
 * Classification per expected entry:
 *   - 'FULL_TP'     — same rule_id (or in accept_alternatives) found
 *   - 'PARTIAL_TP'  — owasp_id + cwe_id match but rule_id differs
 *   - 'FALSE_NEGATIVE' — no actual finding matches
 *
 * `extras` are actual findings not matched to any expected entry. On
 * `expect_zero_findings` cases, each extra counts as a False Positive.
 */
function classify(expectedList, actualFindings) {
  const used = new Set();
  const results = [];

  for (const exp of expectedList) {
    const acceptable = new Set([exp.rule_id, ...(exp.accept_alternatives || [])]);
    let matched = null;
    let classification = 'FALSE_NEGATIVE';

    // Pass 1: strict rule_id match
    for (let i = 0; i < actualFindings.length; i++) {
      if (used.has(i)) continue;
      const a = actualFindings[i];
      if (acceptable.has(a.rule_id)) {
        matched = a;
        classification = 'FULL_TP';
        used.add(i);
        break;
      }
    }
    // Pass 2: same OWASP+CWE category
    if (classification === 'FALSE_NEGATIVE') {
      for (let i = 0; i < actualFindings.length; i++) {
        if (used.has(i)) continue;
        const a = actualFindings[i];
        if (a.owasp_id === exp.owasp_id && a.cwe_id === exp.cwe_id) {
          matched = a;
          classification = 'PARTIAL_TP';
          used.add(i);
          break;
        }
      }
    }
    results.push({ expected: exp, classification, matched });
  }

  const extras = actualFindings.filter((_, i) => !used.has(i));
  return { results, extras };
}

function computeMetrics(cases) {
  let strictTp = 0, looseTp = 0, fn = 0, fp = 0, tn = 0;
  for (const c of cases) {
    if (c.expectZero) {
      if (c.extras.length === 0 && c.results.length === 0) tn++;
      fp += c.extras.length;
      continue;
    }
    for (const r of c.results) {
      if (r.classification === 'FULL_TP') { strictTp++; looseTp++; }
      else if (r.classification === 'PARTIAL_TP') { looseTp++; fn++; /* strict counts as miss */ }
      else fn++;
    }
    fp += c.extras.length;
  }

  const f1 = (tp) => {
    const denomP = tp + fp;
    const denomR = tp + fn;
    const p = denomP > 0 ? tp / denomP : 0;
    const r = denomR > 0 ? tp / denomR : 0;
    return {
      precision: round3(p),
      recall: round3(r),
      f1: round3(p + r > 0 ? (2 * p * r) / (p + r) : 0),
    };
  };

  return {
    strict: { tp: strictTp, fp, fn: fn + (looseTp - strictTp), tn, ...f1(strictTp) },
    loose:  { tp: looseTp,  fp, fn,                              tn, ...f1(looseTp) },
  };
}

function round3(x) {
  return Math.round(x * 1000) / 1000;
}

function formatResults(corpora, opts) {
  const lines = [];
  lines.push('# Benchmark results');
  lines.push('');
  lines.push(`_Generated: ${new Date().toISOString()}_`);
  lines.push('');
  lines.push(`- Corpora: ${corpora.length}`);
  lines.push(`- Total cases: ${corpora.reduce((n, c) => n + c.runs.length, 0)}`);
  lines.push(`- Seeds per case: ${opts.seeds}`);
  lines.push(`- Provider: ${opts.provider || 'auto'}`);
  lines.push(`- Model: ${opts.model || '(default)'}`);
  lines.push('');
  lines.push('> ⚠️  The `benchmark/expected/` corpus is **curated by the same author who wrote the catalog** and serves only as a smoke / regression set.');
  lines.push('> The `benchmark/independent_corpus/` corpus reproduces patterns from publicly disclosed CVE families and was not used to design the catalog.');
  lines.push('> Report both numbers separately — the gap between them is the honest indicator of generalisability.');
  lines.push('');

  for (const c of corpora) {
    lines.push(`## Corpus: \`${c.label}\``);
    lines.push('');
    lines.push('| Case | Expected | Detected (best run) | Verdict | Latency (median) | Cost (median) |');
    lines.push('|------|----------|----------------------|---------|------------------|----------------|');
    for (const r of c.runs) {
      const detected = (r.bestRun.report.findings || []).map(f => f.rule_id).join(', ') || '—';
      const expectedStr = r.case.expectZero
        ? '— (TN expected)'
        : r.case.expected.map(e => e.rule_id).join(', ');
      const verdict = r.bestRun.label;
      const cost = r.medianCost != null ? `$${r.medianCost.toFixed(4)}` : '—';
      lines.push(`| ${r.case.id} | ${expectedStr} | ${detected} | ${verdict} | ${Math.round(r.medianLatency)}ms | ${cost} |`);
    }
    lines.push('');

    const m = c.metrics;
    lines.push('| Mode | TP | FP | FN | TN | Precision | Recall | F1 |');
    lines.push('|------|----|----|----|----|-----------|--------|----|');
    lines.push(`| Strict (rule_id exact) | ${m.strict.tp} | ${m.strict.fp} | ${m.strict.fn} | ${m.strict.tn} | ${m.strict.precision} | ${m.strict.recall} | **${m.strict.f1}** |`);
    lines.push(`| Loose (OWASP+CWE match) | ${m.loose.tp} | ${m.loose.fp} | ${m.loose.fn} | ${m.loose.tn} | ${m.loose.precision} | ${m.loose.recall} | **${m.loose.f1}** |`);
    lines.push('');
  }

  if (corpora.length > 1) {
    lines.push('## Generalisation gaps');
    lines.push('');
    lines.push('Each row is `(F1 of corpus A) − (F1 of corpus B)`. The expected (healthy) trend is monotonically degrading F1 from smoke → independent → complex → oss_pilot, reflecting cases drifting further from the catalog\'s design assumptions.');
    lines.push('');
    lines.push('A large positive gap (>0.20) on any step signals over-fit at that level; a flat or inverted gap suggests the next corpus is too easy.');
    lines.push('');
    const find = (re) => corpora.find(c => re.test(c.label));
    const pairs = [
      ['smoke → independent', find(/expected\/?$/), find(/independent/)],
      ['independent → complex', find(/independent/), find(/complex/)],
      ['complex → oss_pilot',   find(/complex/),    find(/oss_pilot/)],
    ];
    lines.push('| Transition | Strict F1 (a → b) | Strict gap | Loose F1 (a → b) | Loose gap |');
    lines.push('|------------|--------------------|-----------|-------------------|-----------|');
    for (const [label, a, b] of pairs) {
      if (!a || !b) continue;
      const ds = round3(a.metrics.strict.f1 - b.metrics.strict.f1);
      const dl = round3(a.metrics.loose.f1  - b.metrics.loose.f1);
      lines.push(`| ${label} | \`${a.metrics.strict.f1}\` → \`${b.metrics.strict.f1}\` | **${ds >= 0 ? '+' : ''}${ds}** | \`${a.metrics.loose.f1}\` → \`${b.metrics.loose.f1}\` | **${dl >= 0 ? '+' : ''}${dl}** |`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

function summarizeCase(c, runs) {
  const sorted = [...runs].sort((a, b) => a.report.findings?.length - b.report.findings?.length);
  const best = sorted[sorted.length - 1] || sorted[0]; // pick a run with findings if any
  const med = arr => {
    if (arr.length === 0) return 0;
    const s = [...arr].sort((a, b) => a - b);
    return s[Math.floor(s.length / 2)];
  };
  const latencies = runs.map(r => r.wallMs);
  const costs = runs.map(r => r.report.cost ?? r.report.cost_usd).filter(v => v != null);

  // Take the best run's findings for classification.
  const { results, extras } = classify(c.expected, best.report.findings || []);
  let label = 'OK';
  if (c.expectZero) {
    label = extras.length === 0 ? 'TN' : `FP×${extras.length}`;
  } else {
    const fulls = results.filter(r => r.classification === 'FULL_TP').length;
    const partials = results.filter(r => r.classification === 'PARTIAL_TP').length;
    const misses = results.filter(r => r.classification === 'FALSE_NEGATIVE').length;
    if (misses === 0 && partials === 0) label = `TP×${fulls}`;
    else if (misses === 0 && partials > 0) label = `Partial×${partials}` + (fulls ? ` + TP×${fulls}` : '');
    else label = `FN×${misses}`;
  }
  return {
    case: c,
    runs,
    bestRun: { ...best, label },
    results,
    extras,
    medianLatency: med(latencies),
    medianCost: costs.length ? costs[Math.floor(costs.length / 2)] : null,
    expectZero: c.expectZero,
  };
}

async function main() {
  const { values } = parseArgs({
    options: {
      seeds: { type: 'string', default: '1' },
      provider: { type: 'string' },
      model: { type: 'string' },
      'dry-run': { type: 'boolean', default: false },
      'no-write': { type: 'boolean', default: false },
      case: { type: 'string' },
      corpus: { type: 'string', multiple: true, default: [] },
      timeout: { type: 'string' },
      'cache-dir': { type: 'string' },
      'min-f1-strict': { type: 'string', default: '0.6' },
      'min-f1-loose': { type: 'string', default: '0.8' },
      help: { type: 'boolean', default: false },
    },
    strict: true,
  });

  if (values.help) {
    process.stdout.write(`Usage: node benchmark/run_benchmark.mjs [options]

  --seeds=N            Run each case N times (default 1)
  --provider=X         auto | anthropic | openai
  --model=X            provider-specific alias or id
  --case=ID            Run a single case (matches <corpus>/<ID>.json)
  --corpus=PATH        Corpus directory to run (repeatable). Default:
                       benchmark/expected (smoke) + benchmark/independent_corpus
                       if it exists. Pass --corpus repeatedly to combine
                       custom corpora with the defaults disabled.
  --timeout=N          Pass --timeout=N to scan_diff
  --cache-dir=PATH     Pass --cache-dir=PATH to scan_diff (default off here)
  --no-write           Don't update benchmark/results.md
  --dry-run            Skip API calls (smoke check the harness only)
  --min-f1-strict=X    Fail (exit 1) if any corpus's strict F1 below X (default 0.6)
  --min-f1-loose=X     Fail (exit 1) if any corpus's loose F1 below X (default 0.8)
`);
    process.exit(0);
  }

  // Resolve corpora list. Caller wins; otherwise auto-detect all available.
  const corpusDirs = (values.corpus || []).slice();
  if (corpusDirs.length === 0) {
    corpusDirs.push(DEFAULT_CORPUS_DIR);
    for (const sibling of ['independent_corpus', 'complex_corpus', 'oss_pilot']) {
      const dir = path.join(__dirname, sibling);
      // Auto-include only corpora that actually have at least one case file —
      // oss_pilot ships empty until the operator populates it.
      const expectedDir = path.join(dir, 'expected');
      if (fs.existsSync(expectedDir)) {
        const populated = fs.readdirSync(expectedDir).some(f => f.endsWith('.json'));
        if (populated) corpusDirs.push(dir);
      }
    }
  }

  const seeds = Math.max(1, parseInt(values.seeds, 10) || 1);
  const timeoutSec = values.timeout ? parseInt(values.timeout, 10) : 0;

  const corpora = [];
  for (const corpusDir of corpusDirs) {
    let cases = loadCases(corpusDir);
    if (values.case) {
      cases = cases.filter(c => c.id === values.case);
    }
    if (cases.length === 0) {
      process.stderr.write(`⚠  no cases matched in corpus ${corpusDir}\n`);
      continue;
    }
    process.stderr.write(`═ corpus: ${path.relative(ROOT, path.resolve(corpusDir)) || corpusDir} (${cases.length} case${cases.length === 1 ? '' : 's'})\n`);

    const runs = [];
    for (const c of cases) {
      process.stderr.write(`▶ ${c.id} (${seeds} run${seeds === 1 ? '' : 's'})\n`);
      const caseRuns = [];
      for (let s = 0; s < seeds; s++) {
        try {
          const out = runScan({
            diffPath: c.diffPath,
            provider: values.provider,
            model: values.model,
            dryRun: values['dry-run'],
            timeoutSec,
            cacheDir: values['cache-dir'],
          });
          caseRuns.push(out);
        } catch (e) {
          process.stderr.write(`  ✗ run ${s + 1}/${seeds} failed: ${e.message}\n`);
          caseRuns.push({ report: { findings: [] }, wallMs: 0 });
        }
      }
      runs.push(summarizeCase(c, caseRuns));
    }

    const metrics = computeMetrics(runs);
    corpora.push({
      label: cases[0]?.corpus || path.relative(ROOT, path.resolve(corpusDir)),
      runs,
      metrics,
    });
  }

  if (corpora.length === 0) {
    process.stderr.write('No corpora ran successfully.\n');
    process.exit(1);
  }

  const opts = { seeds, provider: values.provider, model: values.model };
  const md = formatResults(corpora, opts);

  // Always print to stdout for piping; optionally also commit to results.md.
  process.stdout.write(md + '\n');
  if (!values['no-write']) {
    fs.writeFileSync(RESULTS_FILE, md + '\n');
    process.stderr.write(`✓ wrote ${path.relative(process.cwd(), RESULTS_FILE)}\n`);
  }

  const minStrict = parseFloat(values['min-f1-strict']);
  const minLoose = parseFloat(values['min-f1-loose']);
  const failed = corpora.filter(c =>
    c.metrics.strict.f1 < minStrict || c.metrics.loose.f1 < minLoose,
  );
  if (failed.length > 0) {
    for (const c of failed) {
      process.stderr.write(`✗ corpus '${c.label}' below thresholds (strict ${c.metrics.strict.f1} < ${minStrict} or loose ${c.metrics.loose.f1} < ${minLoose})\n`);
    }
    process.exit(1);
  }
  for (const c of corpora) {
    process.stderr.write(`✓ corpus '${c.label}' passed (strict F1 ${c.metrics.strict.f1}, loose F1 ${c.metrics.loose.f1})\n`);
  }
  process.exit(0);
}

main().catch(err => {
  process.stderr.write(`run_benchmark: ${err.stack || err.message}\n`);
  process.exit(1);
});
