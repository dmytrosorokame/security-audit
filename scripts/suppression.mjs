/**
 * suppression.mjs — applies two layers of suppression to a findings list:
 *
 *   1. **Inline directive**:  `// security-audit-ignore: <rule_id>[ — reason]`
 *      A comment on a line within `LOOKBACK` lines before a flagged construct
 *      suppresses any finding whose `rule_id` matches the directive's argument.
 *      Multiple rule_ids comma-separated are allowed. `*` matches any rule.
 *
 *   2. **Repo-level `.security-audit-ignore` file** (gitignore-style):
 *      Located at the repo root. One rule per line:
 *
 *        rule_id                    # suppress this rule everywhere
 *        path/glob:rule_id          # suppress rule on matching files
 *        path/glob                  # suppress all rules on matching files
 *        # comment
 *
 *      Glob syntax matches extract_diff.mjs (supports *, **, ?, {a,b}).
 *
 * Both layers add a `suppressed_findings` array to the report so users can
 * audit what got muted. Findings are removed from `findings` and `summary`
 * is recomputed.
 */

import fs from 'node:fs';
import path from 'node:path';

// Directive may appear up to this many lines above the flagged line. Most
// suppressions go directly above the code (offset 1), but tolerating 1–3 lines
// covers blank lines and ESLint-style header comments.
const LOOKBACK = 3;

// Comment styles we recognize:
//   //   JS/TS line comment              // security-audit-ignore: R-02
//   /*   JS block comment                /* security-audit-ignore: R-02 */
//   {/*  JSX expression comment          {/* security-audit-ignore: R-02 */}
//   #    Dockerfile / shell / YAML       # security-audit-ignore: D-01
//   <!-- HTML comment                    <!-- security-audit-ignore: R-10 -->
// The whole rest of the line is captured; reason text and trailing terminator
// are stripped by `parseRuleIdsFromBody` afterwards.
const DIRECTIVE_RX = /(?:\/\/|\/\*|\{\/\*|#|<!--)\s*security-audit-ignore\s*:\s*(.+)/;
const VALID_RULE_ID_RX = /^(R-\d{2}|B-\d{2}|D-\d{2}|NEW_PATTERN|\*)$/;

/**
 * From a directive body like "R-02, R-03 — markdown comes from trusted CMS",
 * extract just the rule IDs.
 *
 * Strips trailing comment terminators (asterisk-slash for JS block comments,
 * --> for HTML), then splits off any reason text (after em-dash, en-dash, or
 * double-hyphen), then filters comma-separated tokens by valid rule_id format.
 */
function parseRuleIdsFromBody(body) {
  // Strip trailing comment terminators: */, */}, -->
  body = body.replace(/\s*-->\s*$/, '')
             .replace(/\s*\*\/\s*\}?\s*$/, '');
  // Split off reason text after em-dash, en-dash, or double-hyphen
  body = body.split(/\s+(?:—|–|--)\s+/)[0];
  return body.split(',')
    .map(s => s.trim())
    .filter(s => VALID_RULE_ID_RX.test(s));
}

/**
 * Parse a single hunk's content for directive lines. Returns a Map from
 * absolute new-side line number → array of rule_ids the directive suppresses.
 */
function parseDirectivesFromHunk(hunk) {
  const directives = new Map();
  const lines = hunk.content.split('\n');
  // Skip the @@-header line; track new-side line numbers as we go.
  let newLine = hunk.new_start - 1;  // -1 because we increment before use
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (raw.startsWith('@@')) continue;
    if (raw.startsWith('-')) continue;            // old-side only, no new-line increment
    // '+' (added) and ' ' (context) lines both advance new-side counter.
    newLine++;
    if (!raw.startsWith('+') && !raw.startsWith(' ')) continue;
    const text = raw.slice(1);  // strip leading '+' or ' '
    const m = text.match(DIRECTIVE_RX);
    if (!m) continue;
    const ruleIds = parseRuleIdsFromBody(m[1]);
    if (ruleIds.length === 0) continue;
    directives.set(newLine, ruleIds);
  }
  return directives;
}

/**
 * Build a map: file path → Map<line, rule_ids[]>.
 * Used for fast O(1) lookups during suppression matching.
 */
export function buildDirectiveIndex(diffJson) {
  const index = new Map();
  for (const file of diffJson.files || []) {
    const fileDirectives = new Map();
    for (const hunk of file.hunks || []) {
      const dirs = parseDirectivesFromHunk(hunk);
      for (const [line, rules] of dirs) {
        fileDirectives.set(line, rules);
      }
    }
    if (fileDirectives.size > 0) {
      index.set(file.path, fileDirectives);
    }
  }
  return index;
}

function ruleMatches(directiveRules, findingRuleId) {
  return directiveRules.some(r => r === '*' || r === findingRuleId);
}

/**
 * Apply inline directives to a findings list. Returns
 * `{ kept: [findings still active], suppressed: [findings with reason] }`.
 */
export function applyInlineDirectives(findings, directiveIndex) {
  const kept = [];
  const suppressed = [];
  for (const f of findings) {
    const fileDirs = directiveIndex.get(f.file);
    let matched = null;
    if (fileDirs) {
      for (let offset = 1; offset <= LOOKBACK; offset++) {
        const candidate = fileDirs.get(f.line - offset);
        if (candidate && ruleMatches(candidate, f.rule_id)) {
          matched = { line: f.line - offset, rules: candidate, offset };
          break;
        }
      }
    }
    if (matched) {
      suppressed.push({
        ...f,
        suppression: {
          source: 'inline',
          directive_line: matched.line,
          directive_offset: matched.offset,
          matched_rules: matched.rules,
        },
      });
    } else {
      kept.push(f);
    }
  }
  return { kept, suppressed };
}

// =============================================================================
// Repo-level .security-audit-ignore
// =============================================================================

function globToRegex(glob) {
  let re = '^';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') { re += '.*'; i++; }
      else re += '[^/]*';
    } else if (c === '?') {
      re += '[^/]';
    } else if (c === '{') {
      const end = glob.indexOf('}', i);
      if (end === -1) re += '\\{';
      else {
        const alts = glob.slice(i + 1, end).split(',').map(a => a.replace(/[.+^$()|[\]\\]/g, '\\$&'));
        re += '(' + alts.join('|') + ')';
        i = end;
      }
    } else if ('.+^$()|[]\\'.includes(c)) {
      re += '\\' + c;
    } else {
      re += c;
    }
  }
  re += '$';
  return new RegExp(re);
}

/**
 * Parse the .security-audit-ignore file into a list of patterns.
 * Each pattern is { glob: RegExp|null, ruleId: string|null }.
 * - "R-02"           → glob: null, ruleId: "R-02"  (rule-only, all files)
 * - "tests/**"       → glob: re,  ruleId: null      (file-only, all rules)
 * - "tests/**:R-02"  → glob: re,  ruleId: "R-02"   (both)
 */
export function parseIgnoreFile(text) {
  const patterns = [];
  for (const raw of text.split('\n')) {
    const line = raw.split('#')[0].trim();
    if (!line) continue;
    const idx = line.lastIndexOf(':');
    let globPart = '';
    let rulePart = '';
    if (idx === -1) {
      // No colon — could be a rule or a glob. If it matches rule_id pattern, treat as rule.
      if (/^(R-\d{2}|B-\d{2}|D-\d{2}|NEW_PATTERN|\*)$/.test(line)) {
        rulePart = line;
      } else {
        globPart = line;
      }
    } else {
      globPart = line.slice(0, idx).trim();
      rulePart = line.slice(idx + 1).trim();
    }
    patterns.push({
      glob: globPart ? globToRegex(globPart) : null,
      ruleId: rulePart || null,
    });
  }
  return patterns;
}

/** Load .security-audit-ignore from repo root. Returns [] if missing. */
export function loadIgnoreFile(repoRoot) {
  const file = path.join(repoRoot || process.cwd(), '.security-audit-ignore');
  if (!fs.existsSync(file)) return [];
  return parseIgnoreFile(fs.readFileSync(file, 'utf8'));
}

/**
 * Match a finding against the parsed ignore patterns.
 * Returns the first matching pattern, or null.
 */
function matchIgnorePatterns(patterns, finding) {
  for (const p of patterns) {
    const globOk = p.glob ? p.glob.test(finding.file) : true;
    const ruleOk = p.ruleId ? (p.ruleId === '*' || p.ruleId === finding.rule_id) : true;
    // Require at least one of glob/rule to actually match (avoid no-op rules).
    if ((p.glob || p.ruleId) && globOk && ruleOk) return p;
  }
  return null;
}

export function applyIgnoreFile(findings, patterns) {
  if (!patterns || patterns.length === 0) return { kept: findings, suppressed: [] };
  const kept = [];
  const suppressed = [];
  for (const f of findings) {
    const match = matchIgnorePatterns(patterns, f);
    if (match) {
      suppressed.push({
        ...f,
        suppression: {
          source: 'ignore-file',
          glob: match.glob ? String(match.glob) : null,
          rule_pattern: match.ruleId || null,
        },
      });
    } else {
      kept.push(f);
    }
  }
  return { kept, suppressed };
}

// =============================================================================
// Combined entry — apply both layers + recompute summary
// =============================================================================

export function applySuppression(report, { diff, repoRoot } = {}) {
  const originalFindings = report.findings || [];
  const directiveIndex = diff ? buildDirectiveIndex(diff) : new Map();
  const ignorePatterns = loadIgnoreFile(repoRoot);

  let kept = originalFindings;
  const allSuppressed = [];

  const inlineResult = applyInlineDirectives(kept, directiveIndex);
  kept = inlineResult.kept;
  allSuppressed.push(...inlineResult.suppressed);

  const fileResult = applyIgnoreFile(kept, ignorePatterns);
  kept = fileResult.kept;
  allSuppressed.push(...fileResult.suppressed);

  return {
    ...report,
    findings: kept,
    suppressed_findings: allSuppressed,
    summary: recomputeSummary(kept),
  };
}

function recomputeSummary(findings) {
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const owasp = {};
  for (const f of findings) {
    if (sev[f.severity] !== undefined) sev[f.severity]++;
    if (f.owasp_id) owasp[f.owasp_id] = (owasp[f.owasp_id] || 0) + 1;
  }
  // Strip zero counts for cleaner output
  for (const k of Object.keys(sev)) if (sev[k] === 0) delete sev[k];
  return { total: findings.length, by_severity: sev, by_owasp: owasp };
}
