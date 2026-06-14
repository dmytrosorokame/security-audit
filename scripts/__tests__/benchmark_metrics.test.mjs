import { describe, it, expect } from 'vitest';
import { classify, computeMetrics } from '../../benchmark/run_benchmark.mjs';

// Regression coverage for the FN double-counting bug in computeMetrics().
//
// Prior version:
//   - in the loop, PARTIAL_TP did `looseTp++; fn++;`
//   - in the return, `strict.fn = fn + (looseTp - strictTp)` added partials AGAIN
//   so a single partial match counted as 2 strict-FN, inflating recall denominator.
//
// New version tracks strict/loose FN separately so each classification
// contributes exactly once per mode.

function summarize(c) {
  const { results, extras } = classify(c.expected, c.actual);
  return { expected: c.expected, expectZero: c.expectZero, results, extras };
}

describe('benchmark computeMetrics — PARTIAL_TP accounting', () => {
  it('counts PARTIAL_TP as exactly one strict-FN, not two', () => {
    // One case: expected R-01, actual R-02 with same owasp/cwe → PARTIAL_TP.
    const m = computeMetrics([summarize({
      expected: [{ rule_id: 'R-01', owasp_id: 'A05', cwe_id: 'CWE-79' }],
      actual:   [{ rule_id: 'R-02', owasp_id: 'A05', cwe_id: 'CWE-79' }],
      expectZero: false,
    })]);
    expect(m.strict.tp).toBe(0);
    expect(m.strict.fn).toBe(1);    // not 2 (regression check)
    expect(m.loose.tp).toBe(1);
    expect(m.loose.fn).toBe(0);
    expect(m.strict.recall).toBeCloseTo(0, 3);
    expect(m.loose.recall).toBeCloseTo(1, 3);
  });

  it('FULL_TP contributes one TP to both modes, no FN', () => {
    const m = computeMetrics([summarize({
      expected: [{ rule_id: 'R-01', owasp_id: 'A05', cwe_id: 'CWE-79' }],
      actual:   [{ rule_id: 'R-01', owasp_id: 'A05', cwe_id: 'CWE-79' }],
      expectZero: false,
    })]);
    expect(m.strict.tp).toBe(1);
    expect(m.strict.fn).toBe(0);
    expect(m.loose.tp).toBe(1);
    expect(m.loose.fn).toBe(0);
  });

  it('FALSE_NEGATIVE (no match at all) contributes one FN to both modes', () => {
    const m = computeMetrics([summarize({
      expected: [{ rule_id: 'R-01', owasp_id: 'A05', cwe_id: 'CWE-79' }],
      actual:   [],
      expectZero: false,
    })]);
    expect(m.strict.tp).toBe(0);
    expect(m.strict.fn).toBe(1);
    expect(m.loose.fn).toBe(1);
  });

  it('expect-zero case with no extras counts as TN, never inflates FN', () => {
    const m = computeMetrics([summarize({
      expected: [],
      actual: [],
      expectZero: true,
    })]);
    expect(m.strict.tn).toBe(1);
    expect(m.strict.fp).toBe(0);
    expect(m.strict.fn).toBe(0);
  });

  it('expect-zero case with extras counts each extra as FP', () => {
    const m = computeMetrics([summarize({
      expected: [],
      actual: [
        { rule_id: 'R-01', owasp_id: 'A05', cwe_id: 'CWE-79' },
        { rule_id: 'B-04', owasp_id: 'A01', cwe_id: 'CWE-918' },
      ],
      expectZero: true,
    })]);
    expect(m.strict.tn).toBe(0);
    expect(m.strict.fp).toBe(2);
  });

  it('mixed corpus: 1 FULL + 1 PARTIAL + 1 FN strictly degrades to recall=1/3', () => {
    const cases = [
      summarize({
        expected: [{ rule_id: 'R-01', owasp_id: 'A05', cwe_id: 'CWE-79' }],
        actual:   [{ rule_id: 'R-01', owasp_id: 'A05', cwe_id: 'CWE-79' }],
        expectZero: false,
      }),
      summarize({
        expected: [{ rule_id: 'B-04', owasp_id: 'A01', cwe_id: 'CWE-918' }],
        actual:   [{ rule_id: 'B-05', owasp_id: 'A01', cwe_id: 'CWE-918' }], // PARTIAL
        expectZero: false,
      }),
      summarize({
        expected: [{ rule_id: 'B-01', owasp_id: 'A05', cwe_id: 'CWE-89' }],
        actual:   [],
        expectZero: false,
      }),
    ];
    const m = computeMetrics(cases);
    // Strict: 1 TP, 0 FP, 2 FN (1 partial + 1 missed) → recall = 1/3
    expect(m.strict.tp).toBe(1);
    expect(m.strict.fn).toBe(2);
    expect(m.strict.recall).toBeCloseTo(0.333, 3);
    // Loose: 2 TP, 0 FP, 1 FN → recall = 2/3
    expect(m.loose.tp).toBe(2);
    expect(m.loose.fn).toBe(1);
    expect(m.loose.recall).toBeCloseTo(0.667, 3);
  });
});

describe('benchmark classify — greedy matching', () => {
  it('matches by exact rule_id first', () => {
    const { results } = classify(
      [{ rule_id: 'R-01', owasp_id: 'A05', cwe_id: 'CWE-79' }],
      [{ rule_id: 'R-01', owasp_id: 'A05', cwe_id: 'CWE-79' }],
    );
    expect(results[0].classification).toBe('FULL_TP');
  });

  it('honors accept_alternatives as full matches', () => {
    const { results } = classify(
      [{ rule_id: 'R-01', accept_alternatives: ['R-02'], owasp_id: 'A05', cwe_id: 'CWE-79' }],
      [{ rule_id: 'R-02', owasp_id: 'A05', cwe_id: 'CWE-79' }],
    );
    expect(results[0].classification).toBe('FULL_TP');
  });

  it('falls back to OWASP+CWE category match as PARTIAL_TP', () => {
    const { results } = classify(
      [{ rule_id: 'R-01', owasp_id: 'A05', cwe_id: 'CWE-79' }],
      [{ rule_id: 'R-99', owasp_id: 'A05', cwe_id: 'CWE-79' }],
    );
    expect(results[0].classification).toBe('PARTIAL_TP');
  });

  it('returns FALSE_NEGATIVE when nothing matches', () => {
    const { results } = classify(
      [{ rule_id: 'R-01', owasp_id: 'A05', cwe_id: 'CWE-79' }],
      [{ rule_id: 'B-04', owasp_id: 'A01', cwe_id: 'CWE-918' }],
    );
    expect(results[0].classification).toBe('FALSE_NEGATIVE');
  });

  it('treats unmatched actual findings as extras (potential FP)', () => {
    const { results, extras } = classify(
      [{ rule_id: 'R-01', owasp_id: 'A05', cwe_id: 'CWE-79' }],
      [
        { rule_id: 'R-01', owasp_id: 'A05', cwe_id: 'CWE-79' },
        { rule_id: 'B-04', owasp_id: 'A01', cwe_id: 'CWE-918' },
      ],
    );
    expect(results[0].classification).toBe('FULL_TP');
    expect(extras.length).toBe(1);
    expect(extras[0].rule_id).toBe('B-04');
  });
});
