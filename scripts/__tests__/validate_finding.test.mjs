import { describe, it, expect } from 'vitest';
import {
  validateFinding,
  validateReport,
  redactSecrets,
  normalizeFinding,
  correctFindingLine,
  calibrateConfidence,
} from '../validate_finding.mjs';

const goodFinding = () => ({
  rule_id: 'R-02',
  owasp_id: 'A05',
  cwe_id: 'CWE-79',
  severity: 'high',
  confidence: 'high',
  verdict: 'TRUE_POSITIVE',
  file: 'src/Comment.tsx',
  line: 13,
  evidence: 'el.innerHTML = comment.body',
  rationale: 'innerHTML from user input',
  remediation: 'Use DOMPurify',
  title: 'DOM XSS via innerHTML',
});

describe('validateFinding — schema', () => {
  it('accepts a well-formed finding', () => {
    expect(validateFinding(goodFinding()).valid).toBe(true);
  });

  it('rejects missing required field', () => {
    const f = goodFinding();
    delete f.rule_id;
    const r = validateFinding(f);
    expect(r.valid).toBe(false);
    expect(r.errors.join(' ')).toMatch(/rule_id/);
  });

  it('rejects invalid rule_id format', () => {
    const f = { ...goodFinding(), rule_id: 'XYZ-99' };
    expect(validateFinding(f).valid).toBe(false);
  });

  it('accepts NEW_PATTERN as rule_id', () => {
    const f = { ...goodFinding(), rule_id: 'NEW_PATTERN' };
    expect(validateFinding(f).valid).toBe(true);
  });

  it('rejects malformed owasp_id (wrong number of digits)', () => {
    // `A1` lacks the second digit; format is A followed by exactly two digits.
    const f = { ...goodFinding(), owasp_id: 'A1' };
    expect(validateFinding(f).valid).toBe(false);
  });

  it('rejects legacy owasp_id with year suffix (Axx:YYYY no longer accepted)', () => {
    const f = { ...goodFinding(), owasp_id: 'A03:2021' };
    expect(validateFinding(f).valid).toBe(false);
  });

  it('rejects invalid severity', () => {
    const f = { ...goodFinding(), severity: 'catastrophic' };
    expect(validateFinding(f).valid).toBe(false);
  });

  it('rejects non-integer line', () => {
    const f = { ...goodFinding(), line: 13.7 };
    expect(validateFinding(f).valid).toBe(false);
  });

  it('accepts CWE-UNKNOWN', () => {
    const f = { ...goodFinding(), cwe_id: 'CWE-UNKNOWN' };
    expect(validateFinding(f).valid).toBe(true);
  });
});

describe('redactSecrets', () => {
  it('redacts AWS access keys', () => {
    expect(redactSecrets('key=AKIAIOSFODNN7EXAMPLE here')).toBe('key=<REDACTED:AWS_ACCESS_KEY> here');
  });

  it('redacts GitHub personal access tokens', () => {
    const s = 'token=ghp_abcdefghijklmnopqrstuvwxyz0123456789';
    expect(redactSecrets(s)).toBe('token=<REDACTED:GITHUB_PAT>');
  });

  it('redacts Stripe live secret keys', () => {
    const s = 'STRIPE=sk_live_abcdef0123456789abcd';
    expect(redactSecrets(s)).toBe('STRIPE=<REDACTED:STRIPE_SECRET>');
  });

  it('redacts a realistic JWT', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    expect(redactSecrets(`Authorization: Bearer ${jwt}`)).toBe('Authorization: Bearer <REDACTED:JWT>');
  });

  it('does NOT redact base64 JSON that happens to start with eyJ (regression for #JWT-false-positive)', () => {
    // base64 of {"a":1} → eyJhIjoxfQ== — old regex would match if dots appeared nearby
    const base64Json = 'eyJhIjoxfQ==';
    expect(redactSecrets(`payload=${base64Json}`)).toBe(`payload=${base64Json}`);
  });

  it('does NOT redact short base64 fragments with dots', () => {
    // eyJabc.def.ghi — too short to be a JWT
    const fake = 'eyJabc.def.ghi';
    expect(redactSecrets(fake)).toBe(fake);
  });

  it('redacts connection string password but keeps user/host visible', () => {
    const conn = 'postgresql://app:hunter2@db.example.com:5432/app';
    expect(redactSecrets(conn)).toContain('app:<REDACTED:CONNECTION_STRING_PASSWORD>@db.example.com');
  });

  it('redacts private keys', () => {
    const pk = '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN...\n-----END PRIVATE KEY-----';
    expect(redactSecrets(pk)).toContain('<REDACTED:PRIVATE_KEY>');
  });

  it('is a no-op on non-string input', () => {
    expect(redactSecrets(null)).toBeNull();
    expect(redactSecrets(123)).toBe(123);
  });
});

describe('normalizeFinding', () => {
  it('redacts evidence and computes risk_score if missing', () => {
    // Supply a 3-element exploit_trace so calibration keeps confidence=high
    // and the risk_score lands on the canonical 7.5 (high × high × TP).
    // Without the trace, calibration would downgrade and lower the score —
    // that path is tested separately under "calibrateConfidence".
    const f = normalizeFinding({
      severity: 'high',
      confidence: 'high',
      verdict: 'TRUE_POSITIVE',
      exploit_trace: ['source: req.body.apiKey', 'sink: bundled into client', 'missing guard: secret committed to source'],
      evidence: 'apiKey=AKIAIOSFODNN7EXAMPLE',
      rationale: 'r',
    });
    expect(f.evidence).toContain('<REDACTED:AWS_ACCESS_KEY>');
    expect(f.risk_score).toBe(7.5);
  });

  it('truncates evidence longer than 300 chars', () => {
    const f = normalizeFinding({
      severity: 'medium',
      confidence: 'medium',
      verdict: 'LIKELY_TP',
      evidence: 'x'.repeat(500),
    });
    expect(f.evidence.length).toBe(300);
    expect(f.evidence.endsWith('...')).toBe(true);
  });
});

describe('correctFindingLine', () => {
  // A 3-line hunk where new_start=10: one context line at 10, one added at 11, one context at 12
  const fileEntry = {
    path: 'foo.ts',
    hunks: [
      {
        old_start: 10,
        old_lines: 2,
        new_start: 10,
        new_lines: 3,
        content: '@@ -10,2 +10,3 @@\n const a = 1;\n+const b = 2;\n const c = 3;\n',
      },
    ],
  };

  it('snaps a context-line target to the nearest added line', () => {
    // LLM picked line 10 (context); should correct to 11 (the +const b line)
    expect(correctFindingLine({ line: 10 }, fileEntry)).toBe(11);
  });

  it('returns the added line if already pointed at it', () => {
    expect(correctFindingLine({ line: 11 }, fileEntry)).toBe(11);
  });

  it('returns null when finding line is outside any hunk', () => {
    expect(correctFindingLine({ line: 999 }, fileEntry)).toBeNull();
  });
});

describe('exploit_trace schema validation', () => {
  it('accepts a 3-element trace array of non-empty strings', () => {
    const f = { ...goodFinding(), exploit_trace: ['source: x', 'sink: y', 'missing: z'] };
    expect(validateFinding(f).valid).toBe(true);
  });

  it('rejects exploit_trace that is not an array', () => {
    const f = { ...goodFinding(), exploit_trace: 'source → sink' };
    const r = validateFinding(f);
    expect(r.valid).toBe(false);
    expect(r.errors.join(' ')).toMatch(/exploit_trace must be an array/);
  });

  it('rejects exploit_trace with empty-string entries', () => {
    const f = { ...goodFinding(), exploit_trace: ['source', '', 'guard'] };
    const r = validateFinding(f);
    expect(r.valid).toBe(false);
    expect(r.errors.join(' ')).toMatch(/non-empty strings/);
  });

  it('rejects exploit_trace with non-string entries', () => {
    const f = { ...goodFinding(), exploit_trace: ['source', 42, 'guard'] };
    expect(validateFinding(f).valid).toBe(false);
  });

  it('treats absent exploit_trace as schema-valid (calibration handles downgrade)', () => {
    const f = { ...goodFinding() };
    delete f.exploit_trace;
    expect(validateFinding(f).valid).toBe(true);
  });
});

describe('calibrateConfidence', () => {
  it('keeps high confidence when exploit_trace has 3+ elements', () => {
    const f = { confidence: 'high', exploit_trace: ['src', 'sink', 'guard'] };
    const out = calibrateConfidence(f);
    expect(out.confidence).toBe('high');
    expect(out.confidence_downgraded_from).toBeUndefined();
  });

  it('downgrades high → medium when only 2 trace elements', () => {
    const f = { confidence: 'high', exploit_trace: ['src', 'sink'] };
    const out = calibrateConfidence(f);
    expect(out.confidence).toBe('medium');
    expect(out.confidence_downgraded_from).toBe('high');
    expect(out.confidence_downgrade_reason).toMatch(/2 element/);
  });

  it('downgrades high → low when only 1 trace element', () => {
    // Two-step downgrade: high → medium (needs 3, has 1) then medium → low
    // (needs 2, still has 1). The reported reason cites the original target.
    const f = { confidence: 'high', exploit_trace: ['only sink visible'] };
    const out = calibrateConfidence(f);
    expect(out.confidence).toBe('low');
    expect(out.confidence_downgraded_from).toBe('high');
  });

  it('downgrades medium → low when only 1 trace element', () => {
    const f = { confidence: 'medium', exploit_trace: ['only sink'] };
    const out = calibrateConfidence(f);
    expect(out.confidence).toBe('low');
    expect(out.confidence_downgraded_from).toBe('medium');
  });

  it('keeps low confidence unchanged regardless of trace', () => {
    const f = { confidence: 'low', exploit_trace: [] };
    const out = calibrateConfidence(f);
    expect(out.confidence).toBe('low');
    expect(out.confidence_downgraded_from).toBeUndefined();
  });

  it('treats missing exploit_trace as zero elements (downgrade applies)', () => {
    const f = { confidence: 'high' };
    expect(calibrateConfidence(f).confidence).toBe('low');
  });

  it('filters falsy/empty entries before counting (defensive)', () => {
    const f = { confidence: 'high', exploit_trace: ['src', null, '', 'sink'] };
    // Two truthy entries → medium, not high.
    expect(calibrateConfidence(f).confidence).toBe('medium');
  });

  it('is a no-op on non-object input', () => {
    expect(calibrateConfidence(null)).toBeNull();
    expect(calibrateConfidence(undefined)).toBeUndefined();
  });
});

describe('normalizeFinding — calibration affects risk_score', () => {
  it('high → medium downgrade lowers the computed risk_score', () => {
    const reported = normalizeFinding({
      severity: 'high',
      confidence: 'high',
      verdict: 'TRUE_POSITIVE',
      exploit_trace: ['src', 'sink', 'guard'],
      evidence: 'x',
    });
    const downgraded = normalizeFinding({
      severity: 'high',
      confidence: 'high', // self-reported high
      verdict: 'TRUE_POSITIVE',
      exploit_trace: ['src', 'sink'], // but trace is incomplete
      evidence: 'x',
    });
    expect(reported.risk_score).toBeGreaterThan(downgraded.risk_score);
    expect(downgraded.confidence).toBe('medium');
    expect(downgraded.confidence_downgraded_from).toBe('high');
  });

  it('annotates downgraded findings so the CLI/SARIF can surface them', () => {
    const out = normalizeFinding({
      severity: 'critical',
      confidence: 'high',
      verdict: 'TRUE_POSITIVE',
      exploit_trace: ['only sink visible'],
      evidence: 'x',
    });
    expect(out.confidence_downgraded_from).toBe('high');
    expect(out.confidence).toBe('low');
    expect(out.confidence_downgrade_reason).toMatch(/exploit_trace has 1 element/);
  });
});

describe('validateReport', () => {
  it('flags wrong schema_version', () => {
    const r = validateReport({ schema_version: '0.9', findings: [] });
    expect(r.valid).toBe(false);
    expect(r.errors.join(' ')).toMatch(/schema_version/);
  });

  it('passes with a single good finding', () => {
    const report = { schema_version: '1.0', findings: [goodFinding()] };
    expect(validateReport(report).valid).toBe(true);
  });

  it('aggregates per-finding errors with index prefix', () => {
    const bad = goodFinding();
    delete bad.cwe_id;
    const report = { schema_version: '1.0', findings: [goodFinding(), bad] };
    const r = validateReport(report);
    expect(r.valid).toBe(false);
    expect(r.errors.join('\n')).toMatch(/findings\[1\]/);
  });
});

describe('validateFinding — diff cross-check', () => {
  const diff = {
    files: [
      {
        path: 'src/foo.ts',
        hunks: [
          {
            old_start: 1,
            old_lines: 0,
            new_start: 1,
            new_lines: 1,
            content: '@@ -1,0 +1,1 @@\n+const danger = eval(userInput);\n',
          },
        ],
      },
    ],
  };

  it('rejects findings on files not in the diff', () => {
    const f = { ...goodFinding(), file: 'other.ts', line: 1, evidence: 'eval' };
    const r = validateFinding(f, { diff });
    expect(r.valid).toBe(false);
    expect(r.errors.join(' ')).toMatch(/not present in the diff/);
  });

  it('accepts findings on added lines with matching evidence', () => {
    const f = {
      ...goodFinding(),
      file: 'src/foo.ts',
      line: 1,
      evidence: 'eval(userInput)',
    };
    const r = validateFinding(f, { diff });
    expect(r.valid).toBe(true);
  });

  it('rejects findings whose evidence is not in the diff text', () => {
    const f = {
      ...goodFinding(),
      file: 'src/foo.ts',
      line: 1,
      evidence: 'completely fabricated quote that does not exist',
    };
    const r = validateFinding(f, { diff });
    expect(r.valid).toBe(false);
    expect(r.errors.join(' ')).toMatch(/evidence not found/);
  });
});
