import { describe, it, expect } from 'vitest';
import {
  buildDirectiveIndex,
  applyInlineDirectives,
  parseIgnoreFile,
  applyIgnoreFile,
  applySuppression,
  parseRuleIdsFromBody,
} from '../suppression.mjs';

const goodFinding = (over = {}) => ({
  rule_id: 'R-02',
  owasp_id: 'A05',
  cwe_id: 'CWE-79',
  severity: 'high',
  confidence: 'high',
  verdict: 'TRUE_POSITIVE',
  file: 'src/app.ts',
  line: 5,
  evidence: 'el.innerHTML = body',
  rationale: 'r',
  remediation: 'fix',
  title: 't',
  ...over,
});

describe('parseRuleIdsFromBody', () => {
  it('extracts a single rule id', () => {
    expect(parseRuleIdsFromBody('R-02')).toEqual(['R-02']);
  });

  it('extracts comma-separated rule ids', () => {
    expect(parseRuleIdsFromBody('R-01, R-02, R-03')).toEqual(['R-01', 'R-02', 'R-03']);
  });

  it('strips reason after em-dash', () => {
    expect(parseRuleIdsFromBody('R-02 — safe because input trusted')).toEqual(['R-02']);
  });

  it('strips reason after en-dash', () => {
    expect(parseRuleIdsFromBody('R-02 – allowlisted')).toEqual(['R-02']);
  });

  it('strips reason after double-hyphen', () => {
    expect(parseRuleIdsFromBody('R-02 -- allowlisted')).toEqual(['R-02']);
  });

  it('strips trailing JS block-comment terminator', () => {
    expect(parseRuleIdsFromBody('R-02 */')).toEqual(['R-02']);
  });

  it('strips trailing JSX block-comment terminator', () => {
    expect(parseRuleIdsFromBody('R-02 */}')).toEqual(['R-02']);
  });

  it('strips trailing HTML comment terminator', () => {
    expect(parseRuleIdsFromBody('R-10 -->')).toEqual(['R-10']);
  });

  it('accepts wildcard *', () => {
    expect(parseRuleIdsFromBody('*')).toEqual(['*']);
  });

  it('rejects malformed tokens', () => {
    expect(parseRuleIdsFromBody('R-XX, INVALID')).toEqual([]);
  });
});

describe('buildDirectiveIndex (5 comment styles)', () => {
  const makeDiff = (content) => ({
    files: [
      {
        path: 'src/app.ts',
        hunks: [{ old_start: 1, old_lines: 0, new_start: 1, new_lines: 5, content }],
      },
    ],
  });

  it('catches // line-comment directive', () => {
    const diff = makeDiff('@@ -1,0 +1,2 @@\n+// security-audit-ignore: R-02 — safe\n+const x = 1;\n');
    const idx = buildDirectiveIndex(diff);
    expect(idx.get('src/app.ts').get(1)).toEqual(['R-02']);
  });

  it('catches /* block-comment directive', () => {
    const diff = makeDiff('@@ -1,0 +1,2 @@\n+/* security-audit-ignore: R-02 */\n+const x = 1;\n');
    const idx = buildDirectiveIndex(diff);
    expect(idx.get('src/app.ts').get(1)).toEqual(['R-02']);
  });

  it('catches {/* JSX-comment directive', () => {
    const diff = makeDiff('@@ -1,0 +1,2 @@\n+{/* security-audit-ignore: R-02 */}\n+const x = 1;\n');
    const idx = buildDirectiveIndex(diff);
    expect(idx.get('src/app.ts').get(1)).toEqual(['R-02']);
  });

  it('catches # shell/Dockerfile/YAML directive', () => {
    const diff = makeDiff('@@ -1,0 +1,2 @@\n+# security-audit-ignore: D-01\n+USER root\n');
    const idx = buildDirectiveIndex(diff);
    expect(idx.get('src/app.ts').get(1)).toEqual(['D-01']);
  });

  it('catches <!-- HTML-comment directive', () => {
    const diff = makeDiff('@@ -1,0 +1,2 @@\n+<!-- security-audit-ignore: R-10 -->\n+<div></div>\n');
    const idx = buildDirectiveIndex(diff);
    expect(idx.get('src/app.ts').get(1)).toEqual(['R-10']);
  });
});

describe('applyInlineDirectives', () => {
  const diff = {
    files: [
      {
        path: 'src/app.ts',
        hunks: [
          {
            old_start: 1,
            old_lines: 0,
            new_start: 1,
            new_lines: 3,
            content: '@@ -1,0 +1,3 @@\n+// security-audit-ignore: R-02 — allowlisted\n+const x = userInput;\n+const y = 2;\n',
          },
        ],
      },
    ],
  };
  const index = buildDirectiveIndex(diff);

  it('suppresses finding on the line directly below directive (offset 1)', () => {
    const f = goodFinding({ line: 2 });
    const { kept, suppressed } = applyInlineDirectives([f], index);
    expect(kept).toHaveLength(0);
    expect(suppressed).toHaveLength(1);
    expect(suppressed[0].suppression.source).toBe('inline');
    expect(suppressed[0].suppression.directive_offset).toBe(1);
  });

  it('does NOT suppress findings 4+ lines below directive (out of lookback)', () => {
    const f = goodFinding({ line: 6 });
    const { kept, suppressed } = applyInlineDirectives([f], index);
    expect(kept).toHaveLength(1);
    expect(suppressed).toHaveLength(0);
  });

  it('does NOT suppress finding whose rule_id does not match', () => {
    const f = goodFinding({ line: 2, rule_id: 'B-04' });
    const { kept, suppressed } = applyInlineDirectives([f], index);
    expect(kept).toHaveLength(1);
    expect(suppressed).toHaveLength(0);
  });

  it('suppresses any rule when directive is `*`', () => {
    const wildcardDiff = {
      files: [{
        path: 'src/app.ts',
        hunks: [{
          old_start: 1, old_lines: 0, new_start: 1, new_lines: 2,
          content: '@@ -1,0 +1,2 @@\n+// security-audit-ignore: *\n+const x = 1;\n',
        }],
      }],
    };
    const idx = buildDirectiveIndex(wildcardDiff);
    const { kept } = applyInlineDirectives([goodFinding({ line: 2, rule_id: 'B-04' })], idx);
    expect(kept).toHaveLength(0);
  });
});

describe('parseIgnoreFile', () => {
  it('parses rule-only line', () => {
    const p = parseIgnoreFile('R-02\n');
    expect(p[0].glob).toBeNull();
    expect(p[0].ruleId).toBe('R-02');
  });

  it('parses glob-only line', () => {
    const p = parseIgnoreFile('tests/**\n');
    expect(p[0].glob).not.toBeNull();
    expect(p[0].ruleId).toBeNull();
  });

  it('parses glob:rule line', () => {
    const p = parseIgnoreFile('legacy/**:R-02\n');
    expect(p[0].glob).not.toBeNull();
    expect(p[0].ruleId).toBe('R-02');
  });

  it('skips comments and blank lines', () => {
    const p = parseIgnoreFile('# comment\n\n   \nR-02\n');
    expect(p).toHaveLength(1);
  });

  it('strips inline comments', () => {
    const p = parseIgnoreFile('R-02   # because\n');
    expect(p[0].ruleId).toBe('R-02');
  });
});

describe('applyIgnoreFile', () => {
  it('suppresses by glob-only rule', () => {
    const patterns = parseIgnoreFile('legacy/**\n');
    const f = goodFinding({ file: 'legacy/old.ts' });
    const { kept, suppressed } = applyIgnoreFile([f], patterns);
    expect(kept).toHaveLength(0);
    expect(suppressed[0].suppression.source).toBe('ignore-file');
  });

  it('suppresses by glob:rule combination', () => {
    const patterns = parseIgnoreFile('legacy/**:R-02\n');
    const f1 = goodFinding({ file: 'legacy/old.ts', rule_id: 'R-02' });
    const f2 = goodFinding({ file: 'legacy/old.ts', rule_id: 'B-04' });
    const { kept } = applyIgnoreFile([f1, f2], patterns);
    expect(kept).toHaveLength(1);
    expect(kept[0].rule_id).toBe('B-04');
  });

  it('returns inputs unchanged for empty patterns', () => {
    const f = goodFinding();
    const { kept, suppressed } = applyIgnoreFile([f], []);
    expect(kept).toEqual([f]);
    expect(suppressed).toEqual([]);
  });
});

describe('applySuppression — end-to-end + summary recompute', () => {
  it('recomputes summary based on kept findings only', () => {
    const report = {
      findings: [
        goodFinding({ severity: 'critical' }),
        goodFinding({ severity: 'high', rule_id: 'B-04' }),
      ],
      summary: { total: 2, by_severity: { critical: 1, high: 1 } },
    };
    // No suppressions applied → summary should match findings count
    const result = applySuppression(report, { diff: { files: [] }, repoRoot: '/nonexistent-path-noignorefile' });
    expect(result.summary.total).toBe(2);
    expect(result.findings).toHaveLength(2);
    expect(result.suppressed_findings).toHaveLength(0);
  });
});
