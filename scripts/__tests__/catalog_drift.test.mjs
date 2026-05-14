/**
 * Catalog drift detector.
 *
 * Three sources reference rule IDs:
 *   1. references/owasp-rules.md       — the source of truth (## R-XX headings)
 *   2. references/owasp-mapping.md     — OWASP→rule cross-reference
 *   3. benchmark/expected/*.json       — ground truth used by run_benchmark.mjs
 *
 * Drift between these is exactly the kind of bug that ate the original
 * f1_table (Expected: R-15 — a rule that never existed). This test fails fast
 * if a rule id is referenced anywhere but missing from the catalog.
 */
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const SCRIPTS_DIR = path.dirname(__filename);
const ROOT = path.resolve(SCRIPTS_DIR, '..', '..');

const RULES_MD = path.join(ROOT, 'references/owasp-rules.md');
const MAPPING_MD = path.join(ROOT, 'references/owasp-mapping.md');
const EXPECTED_DIR = path.join(ROOT, 'benchmark/expected');
const INDEPENDENT_EXPECTED_DIR = path.join(ROOT, 'benchmark/independent_corpus/expected');
const COMPLEX_EXPECTED_DIR = path.join(ROOT, 'benchmark/complex_corpus/expected');

const RULE_RE = /\b([RBD]-\d{2})\b/g;
const HEADING_RE = /^##\s+([RBD]-\d{2})\s/gm;

function loadCatalog() {
  const text = fs.readFileSync(RULES_MD, 'utf8');
  const ids = new Set();
  let m;
  HEADING_RE.lastIndex = 0;
  while ((m = HEADING_RE.exec(text))) ids.add(m[1]);
  return ids;
}

function extractIds(text) {
  const ids = new Set();
  let m;
  RULE_RE.lastIndex = 0;
  while ((m = RULE_RE.exec(text))) ids.add(m[1]);
  return ids;
}

describe('catalog drift', () => {
  const catalog = loadCatalog();

  it('catalog has at least the documented 34 rules', () => {
    // README advertises 34 patterns; below this we have regressed coverage.
    expect(catalog.size).toBeGreaterThanOrEqual(34);
  });

  it('catalog rule families balance: 11 R-, 15 B-, 8 D-', () => {
    const r = [...catalog].filter(id => id.startsWith('R-'));
    const b = [...catalog].filter(id => id.startsWith('B-'));
    const d = [...catalog].filter(id => id.startsWith('D-'));
    // These numbers are documented in README.md and SKILL.md; if they change,
    // the docs must change too. Failing here is the trigger to update both.
    expect(r.length).toBe(11);
    expect(b.length).toBe(15);
    expect(d.length).toBe(8);
  });

  it('every rule referenced in owasp-mapping.md exists in the catalog', () => {
    const mapping = fs.readFileSync(MAPPING_MD, 'utf8');
    const referenced = extractIds(mapping);
    const orphans = [...referenced].filter(id => !catalog.has(id));
    expect(orphans, `Mapping references undefined rules: ${orphans.join(', ')}`).toEqual([]);
  });

  it('every rule referenced in benchmark/expected/*.json exists in the catalog', () => {
    const files = fs.readdirSync(EXPECTED_DIR).filter(f => f.endsWith('.json'));
    const referenced = new Set();
    const sources = [];
    for (const file of files) {
      const raw = fs.readFileSync(path.join(EXPECTED_DIR, file), 'utf8');
      const data = JSON.parse(raw);
      for (const exp of data.expected || []) {
        if (exp.rule_id) {
          referenced.add(exp.rule_id);
          sources.push(`${file}:expected.rule_id=${exp.rule_id}`);
        }
        for (const alt of exp.accept_alternatives || []) {
          referenced.add(alt);
          sources.push(`${file}:accept_alternatives=${alt}`);
        }
      }
    }
    const orphans = [...referenced].filter(id => !catalog.has(id));
    expect(
      orphans,
      `Benchmark ground-truth references undefined rules: ${orphans.join(', ')}\nSources:\n  ${sources.filter(s => orphans.some(o => s.includes(o))).join('\n  ')}`,
    ).toEqual([]);
  });

  it('no expected.json references the historically-broken R-15 / R-12', () => {
    const files = fs.readdirSync(EXPECTED_DIR).filter(f => f.endsWith('.json'));
    const allText = files.map(f => fs.readFileSync(path.join(EXPECTED_DIR, f), 'utf8')).join('\n');
    expect(allText).not.toMatch(/\bR-15\b/);
    expect(allText).not.toMatch(/\bR-12\b/);
  });

  it('every rule_id in benchmark/independent_corpus/expected/*.json exists in the catalog', () => {
    if (!fs.existsSync(INDEPENDENT_EXPECTED_DIR)) return; // optional corpus
    const files = fs.readdirSync(INDEPENDENT_EXPECTED_DIR).filter(f => f.endsWith('.json'));
    const referenced = new Set();
    const sources = [];
    for (const file of files) {
      const data = JSON.parse(fs.readFileSync(path.join(INDEPENDENT_EXPECTED_DIR, file), 'utf8'));
      for (const exp of data.expected || []) {
        if (exp.rule_id) {
          referenced.add(exp.rule_id);
          sources.push(`${file}:expected.rule_id=${exp.rule_id}`);
        }
        for (const alt of exp.accept_alternatives || []) {
          referenced.add(alt);
        }
      }
    }
    const orphans = [...referenced].filter(id => !catalog.has(id) && id !== 'NEW_PATTERN');
    expect(orphans, `Independent corpus references undefined rules: ${orphans.join(', ')}`).toEqual([]);
  });

  it('every independent corpus case cites a real CVE/CWE reference', () => {
    if (!fs.existsSync(INDEPENDENT_EXPECTED_DIR)) return;
    const files = fs.readdirSync(INDEPENDENT_EXPECTED_DIR).filter(f => f.endsWith('.json'));
    const noRef = [];
    for (const file of files) {
      const data = JSON.parse(fs.readFileSync(path.join(INDEPENDENT_EXPECTED_DIR, file), 'utf8'));
      // True-negative cases legitimately have no CVE reference.
      if (data.expect_zero_findings) continue;
      if (!data.cve_reference || data.cve_reference.length < 4) {
        noRef.push(file);
      }
    }
    expect(noRef, `Independent corpus cases missing cve_reference: ${noRef.join(', ')}`).toEqual([]);
  });

  it('every rule_id in benchmark/complex_corpus/expected/*.json exists in the catalog', () => {
    if (!fs.existsSync(COMPLEX_EXPECTED_DIR)) return; // optional corpus
    const files = fs.readdirSync(COMPLEX_EXPECTED_DIR).filter(f => f.endsWith('.json'));
    const referenced = new Set();
    for (const file of files) {
      const data = JSON.parse(fs.readFileSync(path.join(COMPLEX_EXPECTED_DIR, file), 'utf8'));
      for (const exp of data.expected || []) {
        if (exp.rule_id) referenced.add(exp.rule_id);
        for (const alt of exp.accept_alternatives || []) referenced.add(alt);
      }
    }
    const orphans = [...referenced].filter(id => !catalog.has(id) && id !== 'NEW_PATTERN');
    expect(orphans, `Complex corpus references undefined rules: ${orphans.join(', ')}`).toEqual([]);
  });

  it('every complex corpus case declares its complexity dimension', () => {
    if (!fs.existsSync(COMPLEX_EXPECTED_DIR)) return;
    const files = fs.readdirSync(COMPLEX_EXPECTED_DIR).filter(f => f.endsWith('.json'));
    const VALID = new Set(['multi-file', 'compositional', 'semantic', 'noise-heavy', 'taint-chain']);
    const noClass = [];
    for (const file of files) {
      const data = JSON.parse(fs.readFileSync(path.join(COMPLEX_EXPECTED_DIR, file), 'utf8'));
      if (!data.complexity || !VALID.has(data.complexity)) noClass.push(`${file}:${data.complexity}`);
    }
    expect(noClass, `Complex corpus cases missing or invalid complexity tag: ${noClass.join(', ')}`).toEqual([]);
  });
});
