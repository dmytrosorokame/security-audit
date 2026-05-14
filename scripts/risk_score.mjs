// CVSS-like risk score for findings.
// Inputs: severity + confidence + verdict + rule-specific impact.
// Output: 0.0–10.0.
//
// Formula:
//   base = severityWeight (0.0–10.0)
//   confidence_factor = {high: 1.0, medium: 0.85, low: 0.6}
//   verdict_factor = {TRUE_POSITIVE: 1.0, LIKELY_TP: 0.9, NEEDS_HUMAN: 0.7, FALSE_POSITIVE: 0.0}
//   risk = base * confidence_factor * verdict_factor
//   clamp [0.0, 10.0], 1 decimal.

const SEVERITY_BASE = {
  critical: 9.5,
  high: 7.5,
  medium: 5.0,
  low: 3.0,
  info: 1.0,
};

const CONFIDENCE_FACTOR = {
  high: 1.0,
  medium: 0.85,
  low: 0.6,
};

const VERDICT_FACTOR = {
  TRUE_POSITIVE: 1.0,
  LIKELY_TP: 0.9,
  NEEDS_HUMAN: 0.7,
  FALSE_POSITIVE: 0.0,
};

/**
 * Compute a CVSS-like 0–10 risk score for a finding.
 *
 * Score = severityBase × confidenceFactor × verdictFactor, clamped to [0, 10]
 * and rounded to one decimal. Verdict `FALSE_POSITIVE` zeros the score so
 * suppressed-by-LLM findings never trip severity gates.
 *
 * @param {{severity?: string, confidence?: string, verdict?: string}} finding
 * @returns {number} risk score in [0.0, 10.0]
 */
export function calculateRiskScore(finding) {
  const base = SEVERITY_BASE[finding.severity] ?? 0;
  const cf = CONFIDENCE_FACTOR[finding.confidence] ?? 0.85;
  const vf = VERDICT_FACTOR[finding.verdict] ?? 0.85;
  const score = base * cf * vf;
  return Math.round(Math.max(0, Math.min(10, score)) * 10) / 10;
}
