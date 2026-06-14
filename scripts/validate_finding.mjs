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
// owasp_id is the bare category code (A01..A10) — no year suffix, so the
// catalog can track the OWASP standard without re-versioning every finding
// when OWASP republishes (which it does every 3-4 years).
const OWASP_RX = /^A\d{2}$/;
const CWE_RX = /^CWE-\d+$|^CWE-UNKNOWN$/;

// Secret patterns we redact from `evidence` before the finding leaves the
// pipeline. When R-07 fires on a hardcoded API key, the LLM legitimately
// includes the key string as evidence — but PR comments, SARIF reports, and
// logs would then leak the secret. We replace the matched substring with the
// label of the secret family (e.g. AWS_ACCESS_KEY) so downstream consumers
// still know *what kind* of secret was detected without seeing the value.
const SECRET_PATTERNS = [
  { rx: /AKIA[0-9A-Z]{16}/g,                                          label: 'AWS_ACCESS_KEY' },
  { rx: /AIza[0-9A-Za-z_-]{35}/g,                                     label: 'GOOGLE_API_KEY' },
  { rx: /sk_live_[0-9a-zA-Z]{20,}/g,                                  label: 'STRIPE_SECRET' },
  { rx: /pk_live_[0-9a-zA-Z]{20,}/g,                                  label: 'STRIPE_PUBLISHABLE' },
  { rx: /sk-(?:proj-)?[A-Za-z0-9_-]{40,}/g,                           label: 'OPENAI_KEY' },
  { rx: /xox[abposr]-[0-9a-zA-Z-]{10,}/g,                             label: 'SLACK_TOKEN' },
  { rx: /ghp_[0-9a-zA-Z]{36}/g,                                       label: 'GITHUB_PAT' },
  // JWT: require the header to start with `eyJ` followed by `h`, `0`, or `r`
  // (base64 prefixes of `{"a` (alg), `{"t` (typ), or `{"k` (kid) — the realistic
  // first fields in a JOSE header), plus a minimum length on each segment.
  // Without these constraints the old pattern `eyJ…\.…\.…` triggers on any
  // short base64 strings separated by dots, e.g. `eyJhIg==.x.y`.
  { rx: /\beyJ[h0r][A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\b/g, label: 'JWT' },
  { rx: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, label: 'PRIVATE_KEY' },
];

// Connection strings are handled separately: the password can contain `@` if
// URL-encoded (`%40`), so a single regex over the whole URL is brittle. We
// pull out the password group ourselves and replace just that segment.
const CONN_STRING_RX = /\b(postgres|postgresql|mongodb|mongodb\+srv|mysql|mariadb|redis|amqp|amqps):\/\/([^:@/\s]+):([^\s@]+(?:%40[^\s@]+)*)@([^\s/?#]+)/g;

/**
 * Redact any well-known secret patterns in a string. Replaces match with
 * `<REDACTED:LABEL>`. Used on `evidence` so we don't leak the very thing we
 * flagged through PR comments / SARIF / stdout.
 */
export function redactSecrets(text) {
  if (typeof text !== 'string') return text;
  let out = text;
  for (const { rx, label } of SECRET_PATTERNS) {
    out = out.replace(rx, `<REDACTED:${label}>`);
  }
  // Connection strings: keep scheme, user, host visible so the finding still
  // makes sense; redact only the password segment.
  out = out.replace(CONN_STRING_RX, (_, scheme, user, _pwd, host) =>
    `${scheme}://${user}:<REDACTED:CONNECTION_STRING_PASSWORD>@${host}`);
  return out;
}

export function validateFinding(f, opts = {}) {
  const errors = [];
  if (!f || typeof f !== 'object') return { valid: false, errors: ['finding is not an object'] };

  // Required fields
  for (const k of ['rule_id', 'owasp_id', 'cwe_id', 'severity', 'confidence', 'verdict', 'file', 'line', 'evidence', 'rationale', 'title']) {
    if (f[k] === undefined || f[k] === null || f[k] === '') errors.push(`missing required field: ${k}`);
  }

  // Type/format checks
  if (f.rule_id && !RULE_ID_RX.test(f.rule_id)) errors.push(`invalid rule_id: ${f.rule_id} (expected R-XX/B-XX/D-XX/NEW_PATTERN)`);
  if (f.owasp_id && !OWASP_RX.test(f.owasp_id)) errors.push(`invalid owasp_id: ${f.owasp_id} (expected AXX, no year suffix — e.g. 'A05' not 'A05:2021')`);
  if (f.cwe_id && !CWE_RX.test(f.cwe_id)) errors.push(`invalid cwe_id: ${f.cwe_id} (expected CWE-N or CWE-UNKNOWN)`);
  if (f.severity && !VALID_SEVERITY.has(f.severity)) errors.push(`invalid severity: ${f.severity}`);
  if (f.confidence && !VALID_CONFIDENCE.has(f.confidence)) errors.push(`invalid confidence: ${f.confidence}`);
  if (f.verdict && !VALID_VERDICT.has(f.verdict)) errors.push(`invalid verdict: ${f.verdict}`);
  if (f.line !== undefined && (typeof f.line !== 'number' || f.line < 0 || !Number.isInteger(f.line))) {
    errors.push(`invalid line: ${f.line} (expected non-negative integer)`);
  }
  if (f.file && typeof f.file !== 'string') errors.push('file must be a string');

  // Calibration check on exploit_trace. The system prompt requires every
  // finding to ship a trace (source → sink → missing-guard) and ties the
  // legitimacy of `confidence: "high"` to a 3-element trace. Enforcing this
  // here is the post-processor side of that contract: if the LLM emits high
  // confidence without a full chain, we downgrade rather than trust it. This
  // is the calibration discipline — the LLM's self-reported confidence is
  // only honoured when backed by visible evidence.
  if (f.exploit_trace !== undefined) {
    if (!Array.isArray(f.exploit_trace)) {
      errors.push('exploit_trace must be an array of short strings');
    } else if (f.exploit_trace.some(s => typeof s !== 'string' || s.length === 0)) {
      errors.push('exploit_trace entries must be non-empty strings');
    }
  }
  // Evidence length: normalizeFinding truncates to 300 chars, so we only WARN
  // above that — not an error. Truncation is non-destructive (audit info is
  // preserved in the original LLM output if needed for debugging).

  // Cross-check against the diff: file present, line is a real changed line
  // (added or in the immediate context of a hunk).
  if (opts.diff && f.file && f.line && opts.diff.files) {
    const fileEntry = opts.diff.files.find(x => x.path === f.file);
    if (!fileEntry) {
      errors.push(`file '${f.file}' not present in the diff`);
    } else {
      const changeMap = buildChangeMap(fileEntry);
      const status = changeMap.get(f.line);
      if (!status) {
        errors.push(`line ${f.line} not in any hunk of ${f.file}`);
      } else if (status === 'context' && !opts.allowContextLines) {
        // Findings should point at an added (`+`) line, not surrounding
        // context. The diff is what *changed*; flagging an unchanged context
        // line means the LLM mis-attributed the location.
        errors.push(`line ${f.line} is context-only (not an added line) in ${f.file}`);
      }
    }
  }

  // Evidence should be a substring of the diff content for the file —
  // anti-hallucination check for the evidence quote itself.
  if (opts.diff && f.file && typeof f.evidence === 'string' && f.evidence.length >= 8) {
    const fileEntry = opts.diff.files.find(x => x.path === f.file);
    if (fileEntry) {
      const allContent = fileEntry.hunks.map(h => h.content).join('\n');
      // Normalize whitespace on both sides — LLM tends to collapse whitespace.
      const haystack = normalizeForEvidenceMatch(allContent);
      const needle = normalizeForEvidenceMatch(f.evidence);
      // Truncate needle to first 80 chars to tolerate the LLM adding ellipsis
      // or trailing commentary; require a substantial overlap so we don't
      // accept trivially-matching short tokens.
      const probe = needle.slice(0, Math.min(needle.length, 80));
      if (probe.length >= 8 && !haystack.includes(probe)) {
        errors.push(`evidence not found in diff content for ${f.file} (LLM may have paraphrased or hallucinated)`);
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Walk one file's hunks and produce a Map<line, 'added' | 'context'>.
 * Lines that exist only on the old side (removed) are not included — they
 * have no new-side line number to flag.
 *
 * Empty rows inside the hunk body are treated as context for empty source
 * lines (some tools strip the leading-space prefix on blank context rows).
 * We use `new_lines` from the hunk header to distinguish in-body empties
 * (real context) from trailing newline artifacts after the last content row.
 */
function buildChangeMap(fileEntry) {
  const map = new Map();
  for (const h of fileEntry.hunks) {
    let line = h.new_start - 1;
    let consumed = 0;
    const rows = h.content.split('\n');
    for (const row of rows) {
      if (row.startsWith('@@')) continue;
      if (row.startsWith('\\')) continue;  // "\ No newline at end of file"
      if (row.startsWith('-')) continue;
      if (row === '') {
        // Real empty context line (counts) vs trailing artifact (doesn't).
        if (consumed < h.new_lines) {
          line++; consumed++;
          map.set(line, 'context');
        }
        continue;
      }
      if (row.startsWith('+')) {
        line++; consumed++;
        map.set(line, 'added');
      } else if (row.startsWith(' ')) {
        line++; consumed++;
        map.set(line, 'context');
      }
    }
  }
  return map;
}

/** Normalize whitespace for evidence substring matching. */
function normalizeForEvidenceMatch(s) {
  return s.replace(/\s+/g, ' ').trim();
}

/**
 * If `f.line` is inside a hunk but points at a context line (not an added
 * line), try to correct it to the nearest added line within the same hunk.
 * Returns the corrected line, or null if no in-hunk added line is found.
 *
 * Used by scan_diff to recover findings where the LLM nailed the file, hunk,
 * and evidence but mis-numbered the precise line. Live testing showed this is
 * a common LLM failure mode — they sometimes pick the start of the hunk or
 * the function signature line.
 */
export function correctFindingLine(f, fileEntry) {
  if (!f || !fileEntry) return null;
  // Find the hunk containing f.line
  const hunk = fileEntry.hunks.find(h => f.line >= h.new_start && f.line < h.new_start + h.new_lines);
  if (!hunk) return null;
  // Walk the hunk to find all added lines. Mirror the empty-context handling
  // from buildChangeMap so we stay aligned with the validator.
  let line = hunk.new_start - 1;
  let consumed = 0;
  const addedLines = [];
  for (const row of hunk.content.split('\n')) {
    if (row.startsWith('@@')) continue;
    if (row.startsWith('\\')) continue;
    if (row.startsWith('-')) continue;
    if (row === '') {
      if (consumed < hunk.new_lines) { line++; consumed++; }
      continue;
    }
    if (row.startsWith('+')) { line++; consumed++; addedLines.push(line); }
    else if (row.startsWith(' ')) { line++; consumed++; }
  }
  if (addedLines.length === 0) return null;
  // Pick the nearest added line to f.line (ties broken toward earlier line)
  let best = addedLines[0];
  let bestDist = Math.abs(best - f.line);
  for (const al of addedLines) {
    const d = Math.abs(al - f.line);
    if (d < bestDist) { best = al; bestDist = d; }
  }
  return best;
}

/**
 * Calibrate the self-reported confidence against the visible exploit chain.
 *
 * Contract (mirrors prompts/system.md "Confidence (calibrated, not subjective)"):
 *   - `high`     needs exploit_trace ≥ 3 entries (source + sink + missing-guard)
 *   - `medium`   needs exploit_trace ≥ 2 entries
 *   - `low`      no minimum
 *
 * When the LLM over-reports, we downgrade rather than reject. The annotation
 * lives in `confidence_downgraded_from` so the CLI / SARIF output can surface
 * the calibration to readers — over-confidence is the single biggest failure
 * mode of LLM-based SAST, and silently fixing it would hide the signal.
 *
 * @param {object} f
 * @returns {object} a (possibly) downgraded copy
 */
export function calibrateConfidence(f) {
  if (!f || typeof f !== 'object') return f;
  const trace = Array.isArray(f.exploit_trace) ? f.exploit_trace.filter(Boolean) : [];
  const reported = f.confidence;
  let calibrated = reported;
  if (reported === 'high' && trace.length < 3) calibrated = 'medium';
  if (calibrated === 'medium' && trace.length < 2) calibrated = 'low';
  if (calibrated === reported) return f;
  return {
    ...f,
    confidence: calibrated,
    confidence_downgraded_from: reported,
    confidence_downgrade_reason: `exploit_trace has ${trace.length} element(s); '${reported}' requires ${reported === 'high' ? 3 : 2}`,
  };
}

export function normalizeFinding(f) {
  let out = { ...f };
  if (typeof out.evidence === 'string') {
    // Order: trim → redact → truncate. Redaction first means a 280-char string
    // with an API key in the middle still gets the secret replaced even after
    // truncation pushes the boundary; truncating first could cut the key in
    // half and leak fragments.
    out.evidence = redactSecrets(out.evidence.trim());
    if (out.evidence.length > 300) out.evidence = out.evidence.slice(0, 297) + '...';
  }
  if (typeof out.rationale === 'string') {
    out.rationale = redactSecrets(out.rationale);
  }
  if (typeof out.remediation === 'string') {
    out.remediation = redactSecrets(out.remediation);
  }
  // Calibration must run BEFORE risk_score: the score multiplies by a
  // confidence factor, so we want the downgraded value to flow through.
  out = calibrateConfidence(out);
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
        owasp_id: 'A05',
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
