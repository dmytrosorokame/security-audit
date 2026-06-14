import { describe, it, expect } from 'vitest';
import { formatReport } from '../format_cli.mjs';

const finding = (over = {}) => ({
  rule_id: 'R-02',
  owasp_id: 'A05',
  cwe_id: 'CWE-79',
  severity: 'high',
  confidence: 'high',
  verdict: 'TRUE_POSITIVE',
  file: 'src/app.ts',
  line: 5,
  evidence: 'el.innerHTML = body',
  rationale: 'unsanitised user input',
  remediation: 'wrap with DOMPurify',
  title: 'DOM XSS via innerHTML',
  risk_score: 7.5,
  ...over,
});

// eslint-disable-next-line no-control-regex -- we intentionally strip ANSI escape sequences in test assertions
const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');

describe('formatReport — empty diff', () => {
  it('prints a green pass when no findings', () => {
    const out = formatReport({ findings: [] });
    expect(stripAnsi(out)).toMatch(/No security issues found/);
  });

  it('includes non-security observations on a clean report', () => {
    const out = formatReport({
      findings: [],
      non_security_observations: ['Consider rate limiting'],
    });
    expect(stripAnsi(out)).toMatch(/Consider rate limiting/);
  });

  it('does not crash with completely empty input', () => {
    expect(() => formatReport({})).not.toThrow();
  });
});

describe('formatReport — single finding', () => {
  const out = stripAnsi(formatReport({ findings: [finding()] }));

  it('renders the title', () => {
    expect(out).toContain('DOM XSS via innerHTML');
  });

  it('renders severity in uppercase brackets', () => {
    expect(out).toContain('[HIGH]');
  });

  it('renders rule/OWASP/CWE identifiers together', () => {
    expect(out).toContain('R-02');
    expect(out).toContain('A05');
    expect(out).toContain('CWE-79');
  });

  it('renders file:line', () => {
    expect(out).toContain('src/app.ts:5');
  });

  it('renders verdict and confidence', () => {
    expect(out).toMatch(/verdict:\s+TRUE_POSITIVE/);
    expect(out).toMatch(/confidence:\s+high/);
  });

  it('indents the evidence block', () => {
    expect(out).toMatch(/evidence:/);
    expect(out).toContain('el.innerHTML = body');
  });

  it('renders rationale and remediation', () => {
    expect(out).toMatch(/rationale:\s+unsanitised user input/);
    expect(out).toMatch(/fix:\s+wrap with DOMPurify/);
  });

  it('emits risk score', () => {
    expect(out).toContain('risk=7.5');
  });
});

describe('formatReport — verdict icons', () => {
  it.each([
    ['TRUE_POSITIVE',   '🔴'],
    ['LIKELY_TP',       '🟠'],
    ['NEEDS_HUMAN',     '🟡'],
    ['FALSE_POSITIVE',  '⚪'],
  ])('uses %s → %s icon', (verdict, icon) => {
    const out = stripAnsi(formatReport({ findings: [finding({ verdict })] }));
    expect(out).toContain(icon);
  });

  it('falls back to a bullet for unknown verdict', () => {
    const out = stripAnsi(formatReport({ findings: [finding({ verdict: 'BOGUS' })] }));
    expect(out).toContain('• [');
  });
});

describe('formatReport — sorting and summary', () => {
  it('sorts findings by risk_score descending', () => {
    const out = stripAnsi(formatReport({
      findings: [
        finding({ title: 'low-risk', risk_score: 3.0 }),
        finding({ title: 'high-risk', risk_score: 9.5 }),
        finding({ title: 'mid-risk', risk_score: 6.0 }),
      ],
    }));
    const positions = ['high-risk', 'mid-risk', 'low-risk'].map(t => out.indexOf(t));
    expect(positions[0]).toBeGreaterThan(0);
    expect(positions[0]).toBeLessThan(positions[1]);
    expect(positions[1]).toBeLessThan(positions[2]);
  });

  it('renders severity breakdown in the summary line', () => {
    const out = stripAnsi(formatReport({
      findings: [finding({ severity: 'critical' }), finding({ severity: 'high' }), finding({ severity: 'high' })],
      summary: { by_severity: { critical: 1, high: 2 } },
    }));
    expect(out).toContain('3 findings');
    expect(out).toContain('1 critical');
    expect(out).toContain('2 high');
  });

  it('renders OWASP breakdown', () => {
    const out = stripAnsi(formatReport({
      findings: [finding()],
      summary: { by_owasp: { 'A05': 1, 'A01': 2 } },
    }));
    expect(out).toContain('OWASP:');
    expect(out).toContain('A05: 1');
    expect(out).toContain('A01: 2');
  });

  it('renders cost and latency footer when present', () => {
    const out = stripAnsi(formatReport({
      findings: [finding()],
      cost: 0.0031,
      latency_ms: 25500,
    }));
    expect(out).toContain('cost ≈ $0.0031');
    expect(out).toContain('latency 25.5s');
  });

  it('omits cost/latency footer when absent', () => {
    const out = stripAnsi(formatReport({ findings: [finding()] }));
    expect(out).not.toContain('cost ≈');
    expect(out).not.toContain('latency');
  });
});

describe('formatReport — colour control', () => {
  it('emits ANSI escape codes when color=true', () => {
    const out = formatReport({ findings: [finding()] }, { color: true });
    // eslint-disable-next-line no-control-regex
    expect(out).toMatch(/\x1b\[/);
  });

  it('emits plain text when color=false', () => {
    const out = formatReport({ findings: [finding()] }, { color: false });
    // eslint-disable-next-line no-control-regex
    expect(out).not.toMatch(/\x1b\[/);
  });

  it('color defaults to true', () => {
    const out = formatReport({ findings: [finding()] });
    // eslint-disable-next-line no-control-regex
    expect(out).toMatch(/\x1b\[/);
  });
});

describe('formatReport — non-security observations after findings', () => {
  it('renders observations block after findings', () => {
    const out = stripAnsi(formatReport({
      findings: [finding()],
      non_security_observations: ['TODO add CSRF later', 'rate limit hint missing'],
    }));
    expect(out).toContain('Non-security observations:');
    expect(out).toContain('TODO add CSRF later');
    expect(out).toContain('rate limit hint missing');
  });
});
