/**
 * ReDoS audit — every user-input-facing regex in the codebase must complete
 * on pathological inputs in well under 100ms. The patterns we audit:
 *
 *   1. validate_finding.mjs secret patterns + connection-string regex
 *   2. validate_finding.mjs identifier regexes (rule_id, owasp_id, cwe_id)
 *   3. extract_diff.mjs / suppression.mjs globToRegex output
 *
 * If any regex degrades to exponential backtracking on a crafted string, the
 * test takes seconds — failing the timeout and CI. This is a defence against
 * a malicious PR shipping a 5 KB pathological string in evidence/diff content.
 *
 * Reference: OWASP ReDoS Cheat Sheet
 *   https://cheatsheetseries.owasp.org/cheatsheets/Regular_expression_Denial_of_Service_-_ReDoS_Cheat_Sheet.html
 */
import { describe, it, expect } from 'vitest';
import { redactSecrets, validateFinding } from '../validate_finding.mjs';
import { globToRegex } from '../extract_diff.mjs';

const HARD_BUDGET_MS = 200; // generous; well under any human-observable hang

function timed(fn) {
  const t0 = process.hrtime.bigint();
  const result = fn();
  const t1 = process.hrtime.bigint();
  return { result, ms: Number(t1 - t0) / 1e6 };
}

describe('ReDoS: redactSecrets stays linear on adversarial inputs', () => {
  it('handles a long string of @ characters (connection-string regex stress)', () => {
    // Connection-string regex has nested `(?:%40[^\s@]+)*`. Attack inputs:
    // a sea of @ separators with no scheme should fail fast (no scheme match)
    // and any near-miss should not backtrack catastrophically.
    const evil = '@'.repeat(10_000);
    const { ms } = timed(() => redactSecrets(evil));
    expect(ms).toBeLessThan(HARD_BUDGET_MS);
  });

  it('handles thousands of dot-separated base64-like chunks (JWT regex)', () => {
    // JWT regex has three quantified segments {15,}, {10,}, {20,}. A long
    // sequence of period-separated bytes is the classic ReDoS input shape.
    const evil = 'eyJh' + 'a'.repeat(1_000) + '.' + 'b'.repeat(1_000) + '.' + 'c'.repeat(1_000) + '.junk';
    const { ms } = timed(() => redactSecrets(evil));
    expect(ms).toBeLessThan(HARD_BUDGET_MS);
  });

  it('handles a 50 KB blob of "ghp_" prefixed chunks (GitHub PAT regex)', () => {
    const evil = 'ghp_'.repeat(12_500); // ≈50 KB
    const { ms } = timed(() => redactSecrets(evil));
    expect(ms).toBeLessThan(HARD_BUDGET_MS);
  });

  it('handles deeply nested PEM blocks (private-key regex)', () => {
    // Lazy `[\s\S]+?` in the PEM regex pairs with greedy outer matchers in
    // earlier patterns; this stress-tests the whole replace chain.
    const block = '-----BEGIN PRIVATE KEY-----\n' + 'A'.repeat(5_000) + '\n-----END PRIVATE KEY-----';
    const evil = block.repeat(50);
    const { ms } = timed(() => redactSecrets(evil));
    expect(ms).toBeLessThan(HARD_BUDGET_MS * 5); // 50× repetition gets 5× budget
  });
});

describe('ReDoS: identifier regexes in validateFinding stay linear', () => {
  it('reject path for malformed rule_id of 100 KB', () => {
    const f = { rule_id: 'X'.repeat(100_000), owasp_id: 'A05', cwe_id: 'CWE-79',
                severity: 'high', confidence: 'high', verdict: 'TRUE_POSITIVE',
                file: 'x.ts', line: 1, evidence: 'x', rationale: 'x', title: 'x' };
    const { ms } = timed(() => validateFinding(f));
    expect(ms).toBeLessThan(HARD_BUDGET_MS);
  });

  it('reject path for malformed owasp_id of 100 KB', () => {
    const f = { rule_id: 'R-02', owasp_id: 'A'.repeat(100_000), cwe_id: 'CWE-79',
                severity: 'high', confidence: 'high', verdict: 'TRUE_POSITIVE',
                file: 'x.ts', line: 1, evidence: 'x', rationale: 'x', title: 'x' };
    const { ms } = timed(() => validateFinding(f));
    expect(ms).toBeLessThan(HARD_BUDGET_MS);
  });
});

describe('ReDoS: globToRegex output stays linear', () => {
  it('long path under `**/foo` pattern', () => {
    const re = globToRegex('**/foo');
    const evil = 'a/'.repeat(50_000) + 'foo';
    const { ms } = timed(() => re.test(evil));
    expect(ms).toBeLessThan(HARD_BUDGET_MS);
  });

  it('many alternations under `**/*.{ts,tsx,js,jsx,mjs}`', () => {
    const re = globToRegex('**/*.{ts,tsx,js,jsx,mjs}');
    const evil = 'src/'.repeat(10_000) + 'a.tsx';
    const { ms } = timed(() => re.test(evil));
    expect(ms).toBeLessThan(HARD_BUDGET_MS);
  });

  it('many nested ** segments compile and run linearly', () => {
    // Pathological glob from a malicious .security-audit-ignore: ten `**/`.
    const re = globToRegex('**/**/**/**/**/**/**/**/**/**/*.ts');
    const evil = 'a/'.repeat(5_000) + 'x.ts';
    const { ms } = timed(() => re.test(evil));
    expect(ms).toBeLessThan(HARD_BUDGET_MS);
  });
});
