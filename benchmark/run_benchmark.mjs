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
 * Exits 0 if F1 >= --min-f1 (default 0.6 strict / 0.65 loose), 1 otherwise.
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
 * Sibling corpora auto-included by a default `npm run benchmark` (in display
 * order). A corpus is included only if its expected/ dir exists AND has ≥1
 * case file, so a corpus directory can be committed empty (skeleton) and
 * silently skipped until a later plan populates it. Order here is the honest
 * generalisation order: synthetic reproductions → external apps → breadth
 * supplement → real OSS PRs.
 */
export const KNOWN_CORPORA = [
  'independent_corpus',
  'complex_corpus',
  'nodegoat_corpus',
  'juiceshop_corpus',
  'snyk_corpus',
  'oss_pilot',
];

/**
 * Ordered corpus chain for the generalisation-gap table. Each consecutive
 * present pair becomes one row `(F1 of A) − (F1 of B)`. snyk_corpus is NOT in
 * the chain — it is a breadth supplement (spec §4.3), not a point on the
 * synthetic→external degradation axis. Names map a corpus directory basename
 * to its short display label.
 */
export const GAP_CHAIN = [
  'expected',
  'independent_corpus',
  'complex_corpus',
  'nodegoat_corpus',
  'juiceshop_corpus',
  'oss_pilot',
];

const GAP_LABELS = {
  expected: 'smoke',
  independent_corpus: 'independent',
  complex_corpus: 'complex',
  nodegoat_corpus: 'nodegoat',
  juiceshop_corpus: 'juiceshop',
  oss_pilot: 'oss_pilot',
};

/**
 * Build generalisation-gap pairs from GAP_CHAIN, keeping only corpora present
 * in this run. Matching is by label suffix because a corpus `label` is the
 * repo-relative dir (e.g. "benchmark/complex_corpus").
 *
 * @param {Array<{label: string, metrics: object}>} corpora
 * @returns {Array<{label: string, a: object, b: object}>}
 */
export function buildGapPairs(corpora) {
  const present = GAP_CHAIN
    .map(dir => ({ dir, corpus: corpora.find(c => c.label === dir || c.label.endsWith('/' + dir)) }))
    .filter(x => x.corpus);
  const pairs = [];
  for (let i = 0; i + 1 < present.length; i++) {
    pairs.push({
      label: `${GAP_LABELS[present[i].dir]} → ${GAP_LABELS[present[i + 1].dir]}`,
      a: present[i].corpus,
      b: present[i + 1].corpus,
    });
  }
  return pairs;
}

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

function runScan({ diffPath, provider, model, dryRun, timeoutSec, cacheDir, disableCache }) {
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
  if (disableCache) {
    args.push('--no-cache');
  } else if (cacheDir) {
    args.push(`--cache-dir=${cacheDir}`);
  }

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
export function classify(expectedList, actualFindings) {
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

export function computeMetrics(cases) {
  // Track strict/loose FN separately so PARTIAL_TP is counted once per mode:
  //   - strict mode: a partial match is a miss → strictFn += 1
  //   - loose mode:  a partial match is a hit  → strictFn does not move,
  //                  looseFn does not move
  // The previous implementation incremented a single `fn` counter inside the
  // PARTIAL_TP branch AND then added `(looseTp - strictTp)` back into the
  // strict bucket downstream, double-counting partials in strict.
  let strictTp = 0, looseTp = 0, strictFn = 0, looseFn = 0, fp = 0, tn = 0;
  for (const c of cases) {
    if (c.expectZero) {
      if (c.extras.length === 0 && c.results.length === 0) tn++;
      fp += c.extras.length;
      continue;
    }
    for (const r of c.results) {
      if (r.classification === 'FULL_TP') { strictTp++; looseTp++; }
      else if (r.classification === 'PARTIAL_TP') { looseTp++; strictFn++; /* strict miss only */ }
      else { strictFn++; looseFn++; }
    }
    fp += c.extras.length;
  }

  const f1 = (tp, fn) => {
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

  const baseMetrics = {
    strict: { tp: strictTp, fp, fn: strictFn, tn, ...f1(strictTp, strictFn) },
    loose:  { tp: looseTp,  fp, fn: looseFn,  tn, ...f1(looseTp,  looseFn) },
  };
  // Attach 95% confidence intervals — Wilson on precision/recall (each is
  // a proportion of independent trials, so Wilson is the standard interval
  // recommended by Brown/Cai/DasGupta 2001 over normal approximation) and
  // bootstrap on F1 (which is a non-linear combination — Wilson does not
  // apply directly). The bootstrap re-samples *cases* with replacement,
  // matching the unit of analysis. CI computation is cheap (10ms for n=11,
  // B=1000) so it runs unconditionally; gate behind a flag if it ever
  // becomes a bottleneck.
  baseMetrics.strict.ci = {
    precision: wilsonCI(strictTp, strictTp + fp),
    recall:    wilsonCI(strictTp, strictTp + strictFn),
    f1:        bootstrapF1CI(cases, 'strict'),
  };
  baseMetrics.loose.ci = {
    precision: wilsonCI(looseTp, looseTp + fp),
    recall:    wilsonCI(looseTp, looseTp + looseFn),
    f1:        bootstrapF1CI(cases, 'loose'),
  };
  return baseMetrics;
}

function round3(x) {
  return Math.round(x * 1000) / 1000;
}

/**
 * 95% Wilson score interval for a binomial proportion. More accurate than
 * normal approximation at the boundary (p near 0 or 1) and on small n,
 * which is exactly the regime our corpora live in (n=7..19). Returns
 * `[lo, hi]` rounded to 3 decimals, both clamped to [0, 1].
 *
 * Reference: Brown, Cai, DasGupta (2001), "Interval estimation for a
 * binomial proportion", Statistical Science 16(2). Wilson is one of the
 * three intervals they recommend over Wald (normal approximation).
 *
 * @param {number} k — successes (TP)
 * @param {number} n — trials   (TP + FP for precision, TP + FN for recall)
 * @returns {[number, number]}
 */
export function wilsonCI(k, n, z = 1.96) {
  if (!n || n <= 0) return [0, 0];
  const p = k / n;
  const z2 = z * z;
  const denom = 1 + z2 / n;
  const centre = (p + z2 / (2 * n)) / denom;
  const margin = z * Math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom;
  return [
    round3(Math.max(0, centre - margin)),
    round3(Math.min(1, centre + margin)),
  ];
}

/**
 * Deterministic PRNG seeded by an integer. Used by the bootstrap so the
 * CI is reproducible across runs of the same corpus — without this the
 * reported interval shifts ±0.02 between runs purely from Math.random
 * jitter, which is noise that obscures real F1 changes.
 *
 * Mulberry32 — public-domain 32-bit PRNG, period 2^32, passes the
 * BigCrush statistical battery for non-cryptographic use.
 */
export function mulberry32(seed) {
  let s = seed >>> 0;
  return function () {
    s = (s + 0x6D2B79F5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * Non-parametric bootstrap CI for F1, resampling `cases` with replacement
 * B times and recomputing F1 on each bootstrap sample. Seed defaults to 42
 * so the CI is reproducible; pass `seed` if you need an independent draw.
 *
 * Cases are the unit of analysis (not individual TP/FP events) — this
 * matches the typical "we observed N PR-like diffs" framing and keeps
 * within-case dependencies (multiple expected findings on one diff)
 * properly correlated.
 *
 * @param {Array} cases — same shape as input to computeMetrics
 * @param {'strict'|'loose'} mode
 * @param {object} [opts]
 * @param {number} [opts.B=1000] — bootstrap iterations
 * @param {number} [opts.seed=42]
 * @returns {[number, number]} [lo, hi] at 2.5% / 97.5% percentiles
 */
export function bootstrapF1CI(cases, mode, { B = 1000, seed = 42 } = {}) {
  if (!cases || cases.length === 0) return [0, 0];
  const rng = mulberry32(seed);
  const f1s = new Array(B);
  const n = cases.length;
  for (let b = 0; b < B; b++) {
    const sample = new Array(n);
    for (let i = 0; i < n; i++) sample[i] = cases[Math.floor(rng() * n)];
    // Inline a stripped-down F1 calc to avoid the recursive call into
    // computeMetrics (which would itself call bootstrap → infinite loop).
    let tp = 0, fn = 0, fp = 0;
    for (const c of sample) {
      if (c.expectZero) {
        fp += c.extras.length;
        continue;
      }
      for (const r of c.results) {
        if (r.classification === 'FULL_TP') tp++;
        else if (r.classification === 'PARTIAL_TP') { if (mode === 'loose') tp++; else fn++; }
        else fn++;
      }
      fp += c.extras.length;
    }
    const denomP = tp + fp, denomR = tp + fn;
    const p = denomP > 0 ? tp / denomP : 0;
    const r = denomR > 0 ? tp / denomR : 0;
    f1s[b] = p + r > 0 ? (2 * p * r) / (p + r) : 0;
  }
  f1s.sort((a, b) => a - b);
  return [
    round3(f1s[Math.floor(0.025 * B)]),
    round3(f1s[Math.floor(0.975 * B)]),
  ];
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
    // Format `value [lo, hi]` for each estimator. Wilson-on-proportion for
    // precision/recall and bootstrap-on-cases for F1 — see the helper
    // docs above for why these two methods rather than one.
    const ci = (val, [lo, hi]) => `${val} [${lo}, ${hi}]`;
    lines.push('| Mode | TP | FP | FN | TN | Precision (95% CI) | Recall (95% CI) | F1 (95% CI) |');
    lines.push('|------|----|----|----|----|---------------------|------------------|--------------|');
    lines.push(
      `| Strict (rule_id exact) | ${m.strict.tp} | ${m.strict.fp} | ${m.strict.fn} | ${m.strict.tn} `
      + `| ${ci(m.strict.precision, m.strict.ci.precision)} `
      + `| ${ci(m.strict.recall,    m.strict.ci.recall)} `
      + `| **${ci(m.strict.f1, m.strict.ci.f1)}** |`
    );
    lines.push(
      `| Loose (OWASP+CWE match) | ${m.loose.tp} | ${m.loose.fp} | ${m.loose.fn} | ${m.loose.tn} `
      + `| ${ci(m.loose.precision, m.loose.ci.precision)} `
      + `| ${ci(m.loose.recall,    m.loose.ci.recall)} `
      + `| **${ci(m.loose.f1, m.loose.ci.f1)}** |`
    );
    lines.push('');
    lines.push('<sub>Precision / recall CI: Wilson score interval (Brown–Cai–DasGupta 2001). F1 CI: non-parametric bootstrap over cases (B=1000, seed=42, percentile method). Both at 95% confidence.</sub>');
    lines.push('');
  }

  if (corpora.length > 1) {
    lines.push('## Generalisation gaps');
    lines.push('');
    lines.push('Each row is `(F1 of corpus A) − (F1 of corpus B)`. The expected (healthy) trend is monotonically degrading F1 from smoke → independent → complex → oss_pilot, reflecting cases drifting further from the catalog\'s design assumptions.');
    lines.push('');
    lines.push('A large positive gap (>0.20) on any step signals over-fit at that level; a flat or inverted gap suggests the next corpus is too easy.');
    lines.push('');
    const pairs = buildGapPairs(corpora);
    lines.push('| Transition | Strict F1 (a → b) | Strict gap | Loose F1 (a → b) | Loose gap |');
    lines.push('|------------|--------------------|-----------|-------------------|-----------|');
    for (const { label, a, b } of pairs) {
      const ds = round3(a.metrics.strict.f1 - b.metrics.strict.f1);
      const dl = round3(a.metrics.loose.f1 - b.metrics.loose.f1);
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
      'min-f1-loose': { type: 'string', default: '0.65' },
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
  --min-f1-loose=X     Fail (exit 1) if any corpus's loose F1 below X (default 0.65)
`);
    process.exit(0);
  }

  // Resolve corpora list. Caller wins; otherwise auto-detect all available.
  const corpusDirs = (values.corpus || []).slice();
  if (corpusDirs.length === 0) {
    corpusDirs.push(DEFAULT_CORPUS_DIR);
    for (const sibling of KNOWN_CORPORA) {
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

  // Cache key in llm_analyze.mjs is sha256(provider | model | grounding_hash
  // | userMessage) — it does NOT include the seed index. With seeds > 1 the
  // 2nd…Nth runs would all be served from cache and report variance = 0 by
  // construction, defeating the purpose of `--seeds`. Auto-disable the cache
  // whenever variance is being measured. Single-seed runs keep the cache for
  // cost / latency reasons.
  const disableCache = seeds > 1;
  if (disableCache && values['cache-dir']) {
    process.stderr.write(`ℹ  seeds=${seeds} > 1 — ignoring --cache-dir=${values['cache-dir']} so variance is measured against fresh API calls\n`);
  }

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
            disableCache,
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
  // A corpus with zero positive ground-truth cases (every case is
  // `expect_zero_findings: true`) has F1 ≡ 0 by definition (TP can never
  // be positive). Applying the F1 threshold to such a corpus is a
  // category error — the only meaningful gate is "no false positives".
  // The OSS pilot corpus is exactly this shape today.
  const failed = [];
  for (const c of corpora) {
    const hasPositiveCases = c.runs.some(r => !r.case.expectZero);
    if (hasPositiveCases) {
      if (c.metrics.strict.f1 < minStrict || c.metrics.loose.f1 < minLoose) {
        failed.push({ corpus: c, reason: `strict F1 ${c.metrics.strict.f1} < ${minStrict} or loose F1 ${c.metrics.loose.f1} < ${minLoose}` });
      }
    } else {
      // TN-only corpus: gate on FP count instead of F1.
      if (c.metrics.strict.fp > 0) {
        failed.push({ corpus: c, reason: `${c.metrics.strict.fp} false positive(s) on TN-only corpus (expected 0)` });
      }
    }
  }
  if (failed.length > 0) {
    for (const { corpus, reason } of failed) {
      process.stderr.write(`✗ corpus '${corpus.label}' failed: ${reason}\n`);
    }
    process.exit(1);
  }
  for (const c of corpora) {
    const hasPositive = c.runs.some(r => !r.case.expectZero);
    if (hasPositive) {
      process.stderr.write(`✓ corpus '${c.label}' passed (strict F1 ${c.metrics.strict.f1}, loose F1 ${c.metrics.loose.f1})\n`);
    } else {
      process.stderr.write(`✓ corpus '${c.label}' passed (TN-only, ${c.metrics.strict.tn} TN, 0 FP)\n`);
    }
  }
  process.exit(0);
}

// Run as CLI only when invoked directly. Without this guard, a unit test that
// imports `classify` / `computeMetrics` for regression-checking would also
// trigger main() and try to scan every corpus.
if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(err => {
    process.stderr.write(`run_benchmark: ${err.stack || err.message}\n`);
    process.exit(1);
  });
}
