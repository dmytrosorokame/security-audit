/**
 * validate_corpus.mjs — structural + label validator for benchmark corpora
 * built per the diploma spec (docs/superpowers/specs/2026-06-07-...).
 *
 * Checks every <corpus>/expected/*.json:
 *   - parses as JSON, has a non-empty `name`
 *   - `diff` points at an existing file (resolved against the expected/ dir)
 *   - `expect_zero_findings` is boolean
 *   - `provenance` = { kind: 'real'|'synthesized', source, note }  (spec §4)
 *   - when not a TN control: `expected` is a non-empty array and every entry
 *     has rule_id ∈ catalog, owasp_id /^A\d{2}$/, cwe_id /^CWE-\d+$/,
 *     severity ∈ {critical,high,medium,low,info}; accept_alternatives (if any)
 *     are valid rule ids too.
 *
 * Usage:
 *   node scripts/validate_corpus.mjs benchmark/nodegoat_corpus
 *   node scripts/validate_corpus.mjs benchmark/*_corpus   # shell-expanded
 * Exits 0 if clean, 1 if any errors.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractCatalogRuleIds } from './catalog_rules.mjs';

const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);
const OWASP_RE = /^A\d{2}$/;
const CWE_RE = /^CWE-\d+$/;

/**
 * @param {string} corpusDir
 * @param {{validRuleIds?: string[], catalogPath?: string}} [opts]
 * @returns {{errors: string[], warnings: string[], stats: object}}
 */
export function validateCorpus(corpusDir, opts = {}) {
  const errors = [];
  const warnings = [];
  const here = path.dirname(fileURLToPath(import.meta.url));
  const validRuleIds = new Set(
    opts.validRuleIds ?? extractCatalogRuleIds(
      opts.catalogPath ?? path.resolve(here, '../references/owasp-rules.md'),
    ),
  );
  const rulesReferenced = new Set();
  let cases = 0;
  let tnCases = 0;

  const expectedDir = path.join(corpusDir, 'expected');
  if (!fs.existsSync(expectedDir)) {
    errors.push(`${corpusDir}: no expected/ directory`);
    return { errors, warnings, stats: { cases, tnCases, rulesReferenced: [] } };
  }

  const files = fs.readdirSync(expectedDir).filter(f => f.endsWith('.json')).sort();
  if (files.length === 0) warnings.push(`${corpusDir}: expected/ has no .json cases`);

  for (const f of files) {
    const where = `${path.basename(corpusDir)}/${f}`;
    let json;
    try {
      json = JSON.parse(fs.readFileSync(path.join(expectedDir, f), 'utf8'));
    } catch (e) {
      errors.push(`${where}: invalid JSON — ${e.message}`);
      continue;
    }
    cases++;

    if (typeof json.name !== 'string' || !json.name.trim()) errors.push(`${where}: name must be a non-empty string`);

    if (typeof json.diff !== 'string' || !json.diff) {
      errors.push(`${where}: diff must be a relative path string`);
    } else {
      const diffAbs = path.resolve(expectedDir, json.diff);
      if (!fs.existsSync(diffAbs)) errors.push(`${where}: diff not found at ${json.diff}`);
    }

    if (typeof json.expect_zero_findings !== 'boolean') errors.push(`${where}: expect_zero_findings must be boolean`);

    const p = json.provenance;
    if (!p || typeof p !== 'object') {
      errors.push(`${where}: provenance block is required (spec §4)`);
    } else {
      if (p.kind !== 'real' && p.kind !== 'synthesized') errors.push(`${where}: provenance.kind must be "real" or "synthesized"`);
      if (typeof p.source !== 'string' || !p.source.trim()) errors.push(`${where}: provenance.source must be a non-empty string`);
      if (typeof p.note !== 'string' || !p.note.trim()) errors.push(`${where}: provenance.note must be a non-empty string`);
    }

    if (json.expect_zero_findings === true) {
      tnCases++;
      if (Array.isArray(json.expected) && json.expected.length > 0) {
        warnings.push(`${where}: TN case has non-empty expected[] — it will be ignored`);
      }
      continue;
    }

    if (!Array.isArray(json.expected) || json.expected.length === 0) {
      errors.push(`${where}: expected[] must be non-empty when expect_zero_findings is false`);
      continue;
    }
    for (const [i, e] of json.expected.entries()) {
      const at = `${where} expected[${i}]`;
      if (!validRuleIds.has(e.rule_id)) errors.push(`${at}: rule_id ${e.rule_id} not in catalog`);
      else rulesReferenced.add(e.rule_id);
      if (!OWASP_RE.test(e.owasp_id || '')) errors.push(`${at}: owasp_id must match A\\d\\d (got ${e.owasp_id})`);
      if (!CWE_RE.test(e.cwe_id || '')) errors.push(`${at}: cwe_id must match CWE-\\d+ (got ${e.cwe_id})`);
      if (!SEVERITIES.has(e.severity)) errors.push(`${at}: severity must be one of ${[...SEVERITIES].join('/')} (got ${e.severity})`);
      for (const alt of e.accept_alternatives || []) {
        if (!validRuleIds.has(alt)) errors.push(`${at}: accept_alternatives ${alt} not in catalog`);
        else rulesReferenced.add(alt);
      }
    }
  }

  return { errors, warnings, stats: { cases, tnCases, rulesReferenced: [...rulesReferenced] } };
}

function main(argv) {
  const dirs = argv.slice(2);
  if (dirs.length === 0) {
    process.stderr.write('usage: node scripts/validate_corpus.mjs <corpus-dir> [more...]\n');
    process.exit(1);
  }
  let totalErrors = 0;
  for (const dir of dirs) {
    const { errors, warnings, stats } = validateCorpus(dir);
    for (const w of warnings) process.stderr.write(`⚠  ${w}\n`);
    for (const e of errors) process.stderr.write(`✗ ${e}\n`);
    totalErrors += errors.length;
    if (errors.length === 0) {
      process.stderr.write(`✓ ${dir}: ${stats.cases} case(s), ${stats.tnCases} TN, rules: ${stats.rulesReferenced.join(', ') || '—'}\n`);
    }
  }
  process.exit(totalErrors > 0 ? 1 : 0);
}

if (import.meta.url === `file://${process.argv[1]}`) main(process.argv);
