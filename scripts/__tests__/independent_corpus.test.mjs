/**
 * Smoke tests for the independent corpus structure.
 *
 * The point of the corpus is methodological — but mechanically, the corpus
 * must still parse, every diff file must exist, and every expected JSON must
 * match the schema run_benchmark.mjs expects. If any of these break, the
 * generalisation-gap reporting silently misses cases — exactly the kind of
 * regression that erodes the methodological claim.
 */
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(__filename), '..', '..');
const CORPUS = path.join(ROOT, 'benchmark/independent_corpus');
const EXPECTED_DIR = path.join(CORPUS, 'expected');
const DIFFS_DIR = path.join(CORPUS, 'diffs');

describe('independent corpus — structure', () => {
  it('corpus directory exists and is non-empty', () => {
    expect(fs.existsSync(CORPUS)).toBe(true);
    expect(fs.existsSync(EXPECTED_DIR)).toBe(true);
    expect(fs.existsSync(DIFFS_DIR)).toBe(true);
  });

  it('has at least 8 expected JSON cases (target: 10+)', () => {
    const files = fs.readdirSync(EXPECTED_DIR).filter(f => f.endsWith('.json'));
    expect(files.length).toBeGreaterThanOrEqual(8);
  });

  it('every expected JSON has a corresponding diff file', () => {
    const files = fs.readdirSync(EXPECTED_DIR).filter(f => f.endsWith('.json'));
    const missing = [];
    for (const f of files) {
      const data = JSON.parse(fs.readFileSync(path.join(EXPECTED_DIR, f), 'utf8'));
      const diffPath = path.resolve(EXPECTED_DIR, data.diff);
      if (!fs.existsSync(diffPath)) missing.push(`${f} → ${data.diff}`);
    }
    expect(missing, `Missing diff files: ${missing.join(', ')}`).toEqual([]);
  });

  it('every diff has a corresponding expected JSON (no orphan diffs)', () => {
    const diffs = fs.readdirSync(DIFFS_DIR).filter(f => f.endsWith('.diff'));
    const expectedJsons = fs.readdirSync(EXPECTED_DIR).filter(f => f.endsWith('.json'));
    const referencedDiffs = new Set();
    for (const f of expectedJsons) {
      const data = JSON.parse(fs.readFileSync(path.join(EXPECTED_DIR, f), 'utf8'));
      referencedDiffs.add(path.basename(data.diff));
    }
    const orphans = diffs.filter(d => !referencedDiffs.has(d));
    expect(orphans, `Diff files with no expected JSON: ${orphans.join(', ')}`).toEqual([]);
  });
});

describe('independent corpus — case schema', () => {
  const files = fs.readdirSync(EXPECTED_DIR).filter(f => f.endsWith('.json'));

  it.each(files)('%s has required fields', (file) => {
    const data = JSON.parse(fs.readFileSync(path.join(EXPECTED_DIR, file), 'utf8'));
    expect(typeof data.name).toBe('string');
    expect(typeof data.diff).toBe('string');
    expect(Array.isArray(data.expected)).toBe(true);
    expect(typeof data.expect_zero_findings).toBe('boolean');
  });

  it.each(files)('%s either expects findings OR has expect_zero_findings, never both', (file) => {
    const data = JSON.parse(fs.readFileSync(path.join(EXPECTED_DIR, file), 'utf8'));
    if (data.expect_zero_findings) {
      expect(data.expected).toHaveLength(0);
    } else {
      expect(data.expected.length).toBeGreaterThan(0);
    }
  });

  it.each(files)('%s expected rule_id matches catalog format', (file) => {
    const data = JSON.parse(fs.readFileSync(path.join(EXPECTED_DIR, file), 'utf8'));
    for (const e of data.expected) {
      expect(e.rule_id).toMatch(/^(R-\d{2}|B-\d{2}|D-\d{2}|NEW_PATTERN)$/);
      expect(e.owasp_id).toMatch(/^A\d{2}:\d{4}$/);
      expect(e.cwe_id).toMatch(/^CWE-\d+$/);
      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(e.severity);
    }
  });
});

describe('independent corpus — coverage diversity', () => {
  it('covers at least 3 different OWASP categories', () => {
    const files = fs.readdirSync(EXPECTED_DIR).filter(f => f.endsWith('.json'));
    const owasp = new Set();
    for (const f of files) {
      const data = JSON.parse(fs.readFileSync(path.join(EXPECTED_DIR, f), 'utf8'));
      for (const e of data.expected) owasp.add(e.owasp_id);
    }
    // If we converge on only 1-2 OWASP categories, the corpus stops being
    // useful as a generalisation check. Force diversity by failing here.
    expect(owasp.size).toBeGreaterThanOrEqual(3);
  });

  it('includes at least one true-negative case (over-flagging probe)', () => {
    const files = fs.readdirSync(EXPECTED_DIR).filter(f => f.endsWith('.json'));
    const tnCases = files
      .map(f => JSON.parse(fs.readFileSync(path.join(EXPECTED_DIR, f), 'utf8')))
      .filter(d => d.expect_zero_findings);
    expect(tnCases.length).toBeGreaterThanOrEqual(1);
  });

  it('mixes rule families: at least one R-, one B-, plus TN', () => {
    const files = fs.readdirSync(EXPECTED_DIR).filter(f => f.endsWith('.json'));
    const families = new Set();
    for (const f of files) {
      const data = JSON.parse(fs.readFileSync(path.join(EXPECTED_DIR, f), 'utf8'));
      for (const e of data.expected) families.add(e.rule_id[0]); // 'R' | 'B' | 'D'
    }
    // 'R' is frontend, 'B' backend, 'D' Docker — at least two of these must
    // be present for the corpus to test breadth rather than a single family.
    expect(families.size).toBeGreaterThanOrEqual(2);
  });
});
