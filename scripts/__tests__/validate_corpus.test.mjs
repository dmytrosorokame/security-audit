import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { validateCorpus } from '../validate_corpus.mjs';

const VALID_RULES = ['B-03', 'B-01', 'R-01'];

let dir;
beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'corpus-'));
  fs.mkdirSync(path.join(dir, 'expected'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'diffs'), { recursive: true });
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

function writeCase(name, json, { withDiff = true } = {}) {
  fs.writeFileSync(path.join(dir, 'expected', `${name}.json`), JSON.stringify(json));
  if (withDiff && typeof json.diff === 'string') {
    const diffAbs = path.resolve(dir, 'expected', json.diff);
    fs.mkdirSync(path.dirname(diffAbs), { recursive: true });
    fs.writeFileSync(diffAbs, '--- a\n+++ b\n');
  }
}

const goodCase = {
  name: 'NoSQL injection',
  diff: '../diffs/ng01.diff',
  expect_zero_findings: false,
  expected: [{ rule_id: 'B-03', owasp_id: 'A05', cwe_id: 'CWE-943', severity: 'high' }],
  provenance: { kind: 'real', source: 'https://x/commit/abc', note: 'inverted fix' },
};

describe('validateCorpus', () => {
  it('passes a well-formed case', () => {
    writeCase('ng01', goodCase);
    const r = validateCorpus(dir, { validRuleIds: VALID_RULES });
    expect(r.errors).toEqual([]);
    expect(r.stats.cases).toBe(1);
    expect(r.stats.rulesReferenced).toContain('B-03');
  });

  it('flags a missing diff file', () => {
    writeCase('ng02', goodCase, { withDiff: false });
    const r = validateCorpus(dir, { validRuleIds: VALID_RULES });
    expect(r.errors.some(e => /diff not found/.test(e))).toBe(true);
  });

  it('flags a rule_id absent from the catalog', () => {
    writeCase('ng03', { ...goodCase, expected: [{ rule_id: 'B-99', owasp_id: 'A05', cwe_id: 'CWE-943', severity: 'high' }] });
    const r = validateCorpus(dir, { validRuleIds: VALID_RULES });
    expect(r.errors.some(e => /B-99.*not in catalog/.test(e))).toBe(true);
  });

  it('flags missing provenance', () => {
    const { provenance: _provenance, ...noProv } = goodCase;
    writeCase('ng04', noProv);
    const r = validateCorpus(dir, { validRuleIds: VALID_RULES });
    expect(r.errors.some(e => /provenance/.test(e))).toBe(true);
  });

  it('flags malformed owasp_id / cwe_id / severity', () => {
    writeCase('ng05', { ...goodCase, expected: [{ rule_id: 'B-03', owasp_id: '5', cwe_id: '943', severity: 'urgent' }] });
    const r = validateCorpus(dir, { validRuleIds: VALID_RULES });
    expect(r.errors.some(e => /owasp_id/.test(e))).toBe(true);
    expect(r.errors.some(e => /cwe_id/.test(e))).toBe(true);
    expect(r.errors.some(e => /severity/.test(e))).toBe(true);
  });

  it('requires non-empty expected when expect_zero_findings is false', () => {
    writeCase('ng06', { ...goodCase, expected: [] });
    const r = validateCorpus(dir, { validRuleIds: VALID_RULES });
    expect(r.errors.some(e => /expected.*non-empty/.test(e))).toBe(true);
  });

  it('accepts a TN control case (expect_zero_findings true, no expected)', () => {
    writeCase('ng07', {
      name: 'safe refactor',
      diff: '../diffs/ng07.diff',
      expect_zero_findings: true,
      provenance: { kind: 'synthesized', source: 'hand-written', note: 'guard kept' },
    });
    const r = validateCorpus(dir, { validRuleIds: VALID_RULES });
    expect(r.errors).toEqual([]);
    expect(r.stats.tnCases).toBe(1);
  });

  it('errors when the corpus has no expected/ dir', () => {
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'empty-'));
    const r = validateCorpus(empty, { validRuleIds: VALID_RULES });
    expect(r.errors.some(e => /no expected\//.test(e))).toBe(true);
    fs.rmSync(empty, { recursive: true, force: true });
  });
});
