/**
 * Structural and quality checks for the complex corpus.
 *
 * The complex corpus is the only place we deliberately test multi-file
 * diffs — if these slip into trivial single-file cases, the corpus stops
 * doing its job. Tests below pin that property.
 */
import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const ROOT = path.resolve(path.dirname(__filename), '..', '..');
const CORPUS = path.join(ROOT, 'benchmark/complex_corpus');
const EXPECTED_DIR = path.join(CORPUS, 'expected');
const DIFFS_DIR = path.join(CORPUS, 'diffs');

function countDiffFiles(text) {
  return (text.match(/^diff --git /gm) || []).length;
}

describe('complex corpus — structure', () => {
  it('exists and is populated', () => {
    expect(fs.existsSync(CORPUS)).toBe(true);
    expect(fs.existsSync(EXPECTED_DIR)).toBe(true);
    expect(fs.existsSync(DIFFS_DIR)).toBe(true);
  });

  it('has at least 5 cases', () => {
    const files = fs.readdirSync(EXPECTED_DIR).filter(f => f.endsWith('.json'));
    expect(files.length).toBeGreaterThanOrEqual(5);
  });

  it('every case json has a diff file that exists', () => {
    const files = fs.readdirSync(EXPECTED_DIR).filter(f => f.endsWith('.json'));
    const missing = [];
    for (const f of files) {
      const data = JSON.parse(fs.readFileSync(path.join(EXPECTED_DIR, f), 'utf8'));
      const diffPath = path.resolve(EXPECTED_DIR, data.diff);
      if (!fs.existsSync(diffPath)) missing.push(`${f} → ${data.diff}`);
    }
    expect(missing, `Missing diffs: ${missing.join(', ')}`).toEqual([]);
  });
});

describe('complex corpus — diff complexity', () => {
  const files = fs.readdirSync(EXPECTED_DIR).filter(f => f.endsWith('.json'));

  it('every case touches ≥ 2 files (single-file → belongs in independent_corpus)', () => {
    const singleFile = [];
    for (const f of files) {
      const data = JSON.parse(fs.readFileSync(path.join(EXPECTED_DIR, f), 'utf8'));
      const diffPath = path.resolve(EXPECTED_DIR, data.diff);
      const text = fs.readFileSync(diffPath, 'utf8');
      const count = countDiffFiles(text);
      if (count < 2) singleFile.push(`${f}: only ${count} file(s)`);
    }
    expect(singleFile, `Single-file cases in complex corpus: ${singleFile.join('; ')}`).toEqual([]);
  });

  it('files_changed field matches actual diff file count', () => {
    const mismatches = [];
    for (const f of files) {
      const data = JSON.parse(fs.readFileSync(path.join(EXPECTED_DIR, f), 'utf8'));
      const diffPath = path.resolve(EXPECTED_DIR, data.diff);
      const text = fs.readFileSync(diffPath, 'utf8');
      const actual = countDiffFiles(text);
      if (data.files_changed !== actual) {
        mismatches.push(`${f}: declared ${data.files_changed}, actual ${actual}`);
      }
    }
    expect(mismatches, `files_changed lies: ${mismatches.join('; ')}`).toEqual([]);
  });

  it('challenge field is non-empty for every case (explains why it is hard)', () => {
    const noChallenge = [];
    for (const f of files) {
      const data = JSON.parse(fs.readFileSync(path.join(EXPECTED_DIR, f), 'utf8'));
      if (!data.challenge || data.challenge.length < 30) noChallenge.push(f);
    }
    expect(noChallenge, `Cases without a substantive 'challenge' field: ${noChallenge.join(', ')}`).toEqual([]);
  });

  it('covers at least 3 distinct complexity dimensions', () => {
    const dims = new Set();
    for (const f of files) {
      const data = JSON.parse(fs.readFileSync(path.join(EXPECTED_DIR, f), 'utf8'));
      dims.add(data.complexity);
    }
    expect(dims.size).toBeGreaterThanOrEqual(3);
  });

  it('includes at least one true negative (multi-file refactor with no regression)', () => {
    const tnCases = files
      .map(f => JSON.parse(fs.readFileSync(path.join(EXPECTED_DIR, f), 'utf8')))
      .filter(d => d.expect_zero_findings);
    expect(tnCases.length).toBeGreaterThanOrEqual(1);
  });
});

describe('complex corpus — schema integrity', () => {
  const files = fs.readdirSync(EXPECTED_DIR).filter(f => f.endsWith('.json'));

  it.each(files)('%s has required fields', (file) => {
    const data = JSON.parse(fs.readFileSync(path.join(EXPECTED_DIR, file), 'utf8'));
    expect(typeof data.name).toBe('string');
    expect(typeof data.diff).toBe('string');
    expect(Array.isArray(data.expected)).toBe(true);
    expect(typeof data.expect_zero_findings).toBe('boolean');
    expect(typeof data.complexity).toBe('string');
    expect(typeof data.files_changed).toBe('number');
  });
});
