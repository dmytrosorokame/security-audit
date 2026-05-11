/**
 * validate_finding.mjs — lightweight schema validator for LLM-produced findings.
 *
 * No heavy deps (no Zod). Plain runtime checks. Returns:
 *   { valid: true } | { valid: false, errors: [string] }
 *
 * Also exports a `normalizeFinding` helper that fills in defaults (e.g. risk_score
 * if missing, deduplicates evidence whitespace) so downstream code can rely on
 * a consistent shape.
 */

import { calculateRiskScore } from './risk_score.mjs';

const VALID_SEVERITY = new Set(['critical', 'high', 'medium', 'low', 'info']);
const VALID_CONFIDENCE = new Set(['high', 'medium', 'low']);
const VALID_VERDICT = new Set(['TRUE_POSITIVE', 'LIKELY_TP', 'NEEDS_HUMAN', 'FALSE_POSITIVE']);

const RULE_ID_RX = /^(R-\d{2}|B-\d{2}|D-\d{2}|NEW_PATTERN)$/;
const OWASP_RX = /^A\d{2}:\d{4}$/;
const CWE_RX = /^CWE-\d+$|^CWE-UNKNOWN$/;

export function validateFinding(f, opts = {}) {
  const errors = [];
  if (!f || typeof f !== 'object') return { valid: false, errors: ['finding is not an object'] };

  // Required fields
  for (const k of ['rule_id', 'owasp_id', 'cwe_id', 'severity', 'confidence', 'verdict', 'file', 'line', 'evidence', 'rationale', 'title']) {
    if (f[k] === undefined || f[k] === null || f[k] === '') errors.push(`missing required field: ${k}`);
  }

  // Type/format checks
  if (f.rule_id && !RULE_ID_RX.test(f.rule_id)) errors.push(`invalid rule_id: ${f.rule_id} (expected R-XX/B-XX/D-XX/NEW_PATTERN)`);
  if (f.owasp_id && !OWASP_RX.test(f.owasp_id)) errors.push(`invalid owasp_id: ${f.owasp_id} (expected AXX:YYYY)`);
  if (f.cwe_id && !CWE_RX.test(f.cwe_id)) errors.push(`invalid cwe_id: ${f.cwe_id} (expected CWE-N or CWE-UNKNOWN)`);
  if (f.severity && !VALID_SEVERITY.has(f.severity)) errors.push(`invalid severity: ${f.severity}`);
  if (f.confidence && !VALID_CONFIDENCE.has(f.confidence)) errors.push(`invalid confidence: ${f.confidence}`);
  if (f.verdict && !VALID_VERDICT.has(f.verdict)) errors.push(`invalid verdict: ${f.verdict}`);
  if (f.line !== undefined && (typeof f.line !== 'number' || f.line < 0 || !Number.isInteger(f.line))) {
    errors.push(`invalid line: ${f.line} (expected non-negative integer)`);
  }
  if (f.file && typeof f.file !== 'string') errors.push('file must be a string');
  if (f.evidence && typeof f.evidence === 'string' && f.evidence.length > 500) {
    errors.push(`evidence too long: ${f.evidence.length} chars (max 500)`);
  }

  // Optional file presence cross-check
  if (opts.diff && f.file && f.line && opts.diff.files) {
    const fileEntry = opts.diff.files.find(x => x.path === f.file);
    if (!fileEntry) {
      errors.push(`file '${f.file}' not present in the diff`);
    } else {
      // Verify line falls within at least one hunk of the new side
      const inHunk = fileEntry.hunks.some(h => {
        return f.line >= h.new_start && f.line < h.new_start + h.new_lines;
      });
      if (!inHunk) {
        errors.push(`line ${f.line} not in any hunk of ${f.file}`);
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

export function normalizeFinding(f) {
  const out = { ...f };
  // Trim evidence whitespace and collapse to single-line if too noisy
  if (typeof out.evidence === 'string') {
    out.evidence = out.evidence.trim();
    if (out.evidence.length > 300) out.evidence = out.evidence.slice(0, 297) + '...';
  }
  // Compute risk_score if absent
  if (out.risk_score === undefined || out.risk_score === null) {
    out.risk_score = calculateRiskScore(out);
  }
  return out;
}

export function validateReport(report, opts = {}) {
  const errors = [];
  if (!report || typeof report !== 'object') return { valid: false, errors: ['report is not an object'] };
  if (report.schema_version !== '1.0') errors.push(`expected schema_version '1.0', got '${report.schema_version}'`);
  if (!Array.isArray(report.findings)) errors.push('findings must be an array');

  const findingResults = (report.findings || []).map((f, i) => {
    const r = validateFinding(f, opts);
    if (!r.valid) {
      for (const e of r.errors) errors.push(`findings[${i}]: ${e}`);
    }
    return r;
  });

  return { valid: errors.length === 0, errors, findingResults };
}

// CLI smoke test
if (import.meta.url === `file://${process.argv[1]}`) {
  const sample = {
    schema_version: '1.0',
    findings: [
      {
        rule_id: 'R-02',
        owasp_id: 'A03:2021',
        cwe_id: 'CWE-79',
        severity: 'high',
        confidence: 'high',
        verdict: 'TRUE_POSITIVE',
        file: 'apps/web/src/Comment.tsx',
        line: 13,
        evidence: 'el.innerHTML = comment.body',
        rationale: 'innerHTML assigned from user-supplied comment body',
        remediation: 'Sanitize with DOMPurify',
        title: 'DOM XSS via innerHTML',
      },
    ],
    summary: { total: 1 },
  };
  const r = validateReport(sample);
  console.log(JSON.stringify(r, null, 2));
}
