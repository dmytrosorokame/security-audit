import { describe, it, expect } from 'vitest';
import { formatSarif, fingerprintFinding } from '../format_sarif.mjs';

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
  rationale: 'r',
  remediation: 'fix',
  title: 'XSS via innerHTML',
  risk_score: 7.5,
  ...over,
});

describe('formatSarif — top-level structure', () => {
  it('produces a SARIF 2.1.0 document', () => {
    const sarif = formatSarif({ findings: [finding()] });
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toMatch(/sarif-schema-2\.1\.0/);
    expect(sarif.runs).toHaveLength(1);
  });

  it('emits a single run with tool.driver populated', () => {
    const sarif = formatSarif({ findings: [finding()] });
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe('security-audit');
    expect(run.tool.driver.informationUri).toMatch(/github\.com/);
  });

  it('emits automationDetails.id for GitHub Code Scanning deduplication', () => {
    const sarif = formatSarif({ findings: [finding()] });
    expect(sarif.runs[0].automationDetails).toBeDefined();
    expect(typeof sarif.runs[0].automationDetails.id).toBe('string');
    expect(sarif.runs[0].automationDetails.id.length).toBeGreaterThan(0);
  });

  it('honors a caller-supplied run_id over an auto-generated one', () => {
    const sarif = formatSarif({ findings: [finding()], run_id: 'custom-run-42' });
    expect(sarif.runs[0].automationDetails.id).toBe('custom-run-42');
  });
});

describe('formatSarif — rules array', () => {
  it('emits one rule per unique rule_id', () => {
    const findings = [
      finding({ rule_id: 'R-01' }),
      finding({ rule_id: 'R-02' }),
      finding({ rule_id: 'R-02' }),
    ];
    const sarif = formatSarif({ findings });
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(2);
  });

  it('falls back to OWASP root when CWE is unknown', () => {
    const sarif = formatSarif({ findings: [finding({ cwe_id: 'CWE-UNKNOWN' })] });
    expect(sarif.runs[0].tool.driver.rules[0].helpUri).toMatch(/owasp\.org/);
  });

  it('uses CWE definition URL when CWE is known', () => {
    const sarif = formatSarif({ findings: [finding({ cwe_id: 'CWE-79' })] });
    expect(sarif.runs[0].tool.driver.rules[0].helpUri).toContain('cwe.mitre.org/data/definitions/79');
  });

  it('tags rules with security + OWASP + CWE labels', () => {
    const sarif = formatSarif({ findings: [finding()] });
    expect(sarif.runs[0].tool.driver.rules[0].properties.tags).toContain('security');
    expect(sarif.runs[0].tool.driver.rules[0].properties.tags).toContain('A05');
    expect(sarif.runs[0].tool.driver.rules[0].properties.tags).toContain('CWE-79');
  });

  it('maps severity to SARIF level (critical/high → error, medium → warning, low → note)', () => {
    const findings = [
      finding({ rule_id: 'R-01', severity: 'critical' }),
      finding({ rule_id: 'R-02', severity: 'medium' }),
      finding({ rule_id: 'R-03', severity: 'low' }),
    ];
    const sarif = formatSarif({ findings });
    const levels = sarif.runs[0].results.map(r => r.level);
    expect(levels).toEqual(['error', 'warning', 'note']);
  });

  it('exposes CVSS-like score via properties.security-severity', () => {
    const sarif = formatSarif({ findings: [finding({ severity: 'critical' })] });
    expect(sarif.runs[0].tool.driver.rules[0].properties['security-severity']).toBe('9.5');
  });
});

describe('formatSarif — fingerprints', () => {
  it('attaches a partialFingerprint to every result', () => {
    const sarif = formatSarif({ findings: [finding()] });
    expect(sarif.runs[0].results[0].partialFingerprints['security-audit/v1']).toMatch(/^[a-f0-9]{32}$/);
  });

  it('same rule + file + evidence → identical fingerprint (deduplication signal)', () => {
    const a = fingerprintFinding(finding({ line: 10 }));
    const b = fingerprintFinding(finding({ line: 99 })); // line should NOT affect fingerprint
    expect(a).toBe(b);
  });

  it('different rule_id → different fingerprint', () => {
    const a = fingerprintFinding(finding({ rule_id: 'R-01' }));
    const b = fingerprintFinding(finding({ rule_id: 'R-02' }));
    expect(a).not.toBe(b);
  });
});

describe('formatSarif — suppressions', () => {
  it('marks suppressed findings via results[].suppressions[]', () => {
    const report = {
      findings: [],
      suppressed_findings: [
        {
          ...finding(),
          suppression: { source: 'inline', reason: 'allowlisted internal URL' },
        },
      ],
    };
    const sarif = formatSarif(report);
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0].suppressions[0].kind).toBe('inSource');
    expect(sarif.runs[0].results[0].suppressions[0].justification).toMatch(/allowlisted/);
  });

  it('maps repo-ignore suppressions to SARIF "external" kind', () => {
    const sarif = formatSarif({
      findings: [],
      suppressed_findings: [{ ...finding(), suppression: { source: 'repo-ignore', reason: 'legacy' } }],
    });
    expect(sarif.runs[0].results[0].suppressions[0].kind).toBe('external');
  });

  it('active findings have no suppressions field', () => {
    const sarif = formatSarif({ findings: [finding()] });
    expect(sarif.runs[0].results[0].suppressions).toBeUndefined();
  });
});

describe('formatSarif — physical location', () => {
  it('emits artifactLocation with %SRCROOT% uriBaseId', () => {
    const sarif = formatSarif({ findings: [finding()] });
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    expect(loc.artifactLocation.uri).toBe('src/app.ts');
    expect(loc.artifactLocation.uriBaseId).toBe('%SRCROOT%');
  });

  it('includes startLine and snippet text', () => {
    const sarif = formatSarif({ findings: [finding()] });
    const region = sarif.runs[0].results[0].locations[0].physicalLocation.region;
    expect(region.startLine).toBe(5);
    expect(region.snippet.text).toBe('el.innerHTML = body');
  });
});
