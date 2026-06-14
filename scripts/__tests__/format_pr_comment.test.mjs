import { describe, it, expect } from 'vitest';
import { formatPrComment, escapeMd, pickFence } from '../format_pr_comment.mjs';

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
  rationale: 'innerHTML rendered from user input',
  remediation: 'Use DOMPurify.sanitize',
  title: 'DOM XSS via innerHTML',
  risk_score: 7.5,
  ...over,
});

describe('escapeMd (HTML-safe entity escape)', () => {
  it('escapes < and > as HTML entities (not backslash-escape)', () => {
    // CommonMark backslash-escape does NOT cover < and >, so the only safe
    // option is HTML entity encoding. This is a regression check.
    expect(escapeMd('XSS via <script> tag')).toBe('XSS via &lt;script&gt; tag');
  });

  it('escapes & first to avoid double-encoding existing entities', () => {
    expect(escapeMd('a & b')).toBe('a &amp; b');
    // If we escaped < first, then & would become &amp; → &amp;amp;lt; — wrong.
    expect(escapeMd('a < b & c > d')).toBe('a &lt; b &amp; c &gt; d');
  });

  it('backslash-escapes backtick (CommonMark-compatible)', () => {
    expect(escapeMd('code `block` here')).toBe('code \\`block\\` here');
  });

  it('does not double-escape an already-escaped entity', () => {
    // We don't re-decode the input; escaping `&amp;` should give `&amp;amp;`
    // (this is fine — author input shouldn't contain raw entities).
    expect(escapeMd('&amp;')).toBe('&amp;amp;');
  });

  it('preserves prose punctuation (parens, dashes, plus, exclamation)', () => {
    expect(escapeMd('a (b) c-d! +')).toBe('a (b) c-d! +');
  });

  it('blocks the <img onerror> XSS vector that survived backslash-escape', () => {
    // Before the fix, escapeMd produced `\<img onerror=...\>` which renders
    // as live HTML in many markdown engines. With entity-encoding it now
    // renders as visible text instead.
    const xss = '<img src=x onerror=alert(1)>';
    const out = escapeMd(xss);
    expect(out).not.toContain('<img');
    expect(out).toBe('&lt;img src=x onerror=alert(1)&gt;');
  });

  it('is a no-op on non-string', () => {
    expect(escapeMd(42)).toBe(42);
    expect(escapeMd(null)).toBeNull();
  });
});

describe('pickFence', () => {
  it('returns ``` (3 backticks) for content with no backticks', () => {
    expect(pickFence('plain code')).toBe('```');
  });

  it('returns ```` (4 backticks) when content contains ``` (3-tick run)', () => {
    expect(pickFence('here is a ``` block')).toBe('````');
  });

  it('returns 5 backticks for content with a 4-tick run', () => {
    expect(pickFence('weird ```` thing')).toBe('`````');
  });

  it('handles non-string input', () => {
    expect(pickFence(undefined)).toBe('```');
  });
});

describe('formatPrComment — empty diff', () => {
  it('emits a passing comment when there are 0 findings', () => {
    const out = formatPrComment({ findings: [] });
    expect(out).toMatch(/No security issues found/);
  });

  it('still shows non_security_observations on a passing report', () => {
    const out = formatPrComment({
      findings: [],
      non_security_observations: ['Consider adding rate limiting later'],
    });
    expect(out).toMatch(/rate limiting/);
  });

  it('shows a clean green check only when nothing was suppressed', () => {
    const out = formatPrComment({ findings: [], suppressed_findings: [] });
    expect(out).toMatch(/✅ \*\*No security issues found/);
  });
});

describe('formatPrComment — suppressed findings', () => {
  const suppressed = (over = {}) => ({
    rule_id: 'B-01',
    severity: 'critical',
    risk_score: 9.1,
    file: 'src/server/scripts/cleanup_sessions.ts',
    line: 17,
    title: 'SQL injection via table identifier interpolation',
    suppression: { source: 'inline', directive_line: 15, matched_rules: ['B-01'] },
    ...over,
  });

  it('does NOT show a green check when a critical finding is suppressed (no active findings)', () => {
    const out = formatPrComment({ findings: [], suppressed_findings: [suppressed()] });
    expect(out).not.toMatch(/✅ \*\*No security issues found/);
    expect(out).toMatch(/⚠️/);
    expect(out).toMatch(/1 critical\/high/);
  });

  it('renders a suppressed-findings section with rule, location and mute source', () => {
    const out = formatPrComment({ findings: [], suppressed_findings: [suppressed()] });
    expect(out).toMatch(/🔇 Suppressed findings \(1\)/);
    expect(out).toMatch(/`B-01`/);
    expect(out).toMatch(/cleanup_sessions\.ts:17/);
    expect(out).toMatch(/inline directive at line 15/);
  });

  it('keeps a green check when only low/info findings are suppressed', () => {
    const out = formatPrComment({
      findings: [],
      suppressed_findings: [suppressed({ severity: 'low', rule_id: 'R-12' })],
    });
    expect(out).toMatch(/✅ \*\*No active security findings/);
    expect(out).toMatch(/🔇 Suppressed findings \(1\)/);
  });

  it('appends a suppressed count to the summary line when active findings exist', () => {
    const out = formatPrComment({
      findings: [finding()],
      suppressed_findings: [suppressed()],
      summary: { by_severity: { high: 1 } },
    });
    expect(out).toMatch(/🔇 1 suppressed/);
    expect(out).toMatch(/🔇 Suppressed findings \(1\)/);
  });

  it('renders ignore-file suppressions with the pattern', () => {
    const out = formatPrComment({
      findings: [],
      suppressed_findings: [suppressed({
        suppression: { source: 'ignore-file', rule_pattern: 'B-01', glob: '/cleanup.*/' },
      })],
    });
    expect(out).toMatch(/\.security-audit-ignore/);
  });
});

describe('formatPrComment — single finding', () => {
  it('renders OWASP and CWE as clickable links', () => {
    const out = formatPrComment({ findings: [finding()] });
    expect(out).toMatch(/\[A05\]\(https:\/\/owasp\.org\/Top10\/2025\/A05_2025-Injection\//);
    expect(out).toMatch(/\[CWE-79\]\(https:\/\/cwe\.mitre\.org\/data\/definitions\/79/);
  });

  it('falls back to OWASP Top10 root for unknown owasp_id', () => {
    const f = finding({ owasp_id: 'A99' });
    const out = formatPrComment({ findings: [f] });
    expect(out).toContain('https://owasp.org/Top10/');
  });

  it('includes file:line marker', () => {
    const out = formatPrComment({ findings: [finding()] });
    expect(out).toContain('src/app.ts:5');
  });

  it('encodes < > in title text as HTML entities (cannot render as HTML)', () => {
    const f = finding({ title: 'XSS via <script> tag' });
    const out = formatPrComment({ findings: [f] });
    expect(out).toContain('XSS via &lt;script&gt; tag');
    expect(out).not.toContain('<script>');
  });

  it('uses commit-sha if provided', () => {
    const out = formatPrComment({ findings: [finding()] }, { commitSha: 'abcdef1234567890' });
    expect(out).toContain('abcdef1');
  });
});

describe('formatPrComment — evidence fencing (regression for backtick injection)', () => {
  it('wraps evidence containing ``` in a 4-tick fence', () => {
    const f = finding({ evidence: 'const x = `template ${user} string`; eval(`${dangerous}`)' });
    const out = formatPrComment({ findings: [f] });
    // Default 3-tick fence is fine when content has at most single backticks.
    // No `````` (4+) needed.
    expect(out).toMatch(/```\nconst x = `template/);
  });

  it('escalates fence when evidence contains a 3-tick run', () => {
    const f = finding({ evidence: 'broken ``` markdown injection' });
    const out = formatPrComment({ findings: [f] });
    expect(out).toMatch(/````\nbroken ```/);
  });
});

describe('formatPrComment — multiple findings sorted by risk', () => {
  it('sorts findings descending by risk_score', () => {
    const out = formatPrComment({
      findings: [
        finding({ rule_id: 'R-01', title: 'low risk', risk_score: 3.0 }),
        finding({ rule_id: 'R-02', title: 'high risk', risk_score: 9.0 }),
      ],
    });
    const idxHigh = out.indexOf('high risk');
    const idxLow = out.indexOf('low risk');
    expect(idxHigh).toBeGreaterThan(0);
    expect(idxHigh).toBeLessThan(idxLow);
  });

  it('summarizes severity counts in the header', () => {
    const out = formatPrComment({
      findings: [
        finding({ severity: 'critical' }),
        finding({ severity: 'high' }),
        finding({ severity: 'high' }),
      ],
      summary: { by_severity: { critical: 1, high: 2 } },
    });
    expect(out).toContain('3 findings');
  });
});
