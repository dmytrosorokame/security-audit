/**
 * format_pr_comment.mjs — produces a single GitHub Pull-Request comment
 * (Markdown) from a security-audit report JSON.
 *
 * Usage:
 *   cat report.json | node format_pr_comment.mjs
 *   node format_pr_comment.mjs --input=report.json
 *   node format_pr_comment.mjs --input=report.json --commit-sha=abc123
 */

import fs from 'node:fs';
import { parseArgs } from 'node:util';

const SEVERITY_EMOJI = {
  critical: '🛑',
  high: '🔴',
  medium: '🟠',
  low: '🟡',
  info: 'ℹ️',
};

const VERDICT_LABEL = {
  TRUE_POSITIVE: '**Confirmed**',
  LIKELY_TP: 'Likely',
  NEEDS_HUMAN: 'Needs human review',
  FALSE_POSITIVE: 'False positive (LLM)',
};

// Canonical URL pattern on owasp.org is `A##_2025-Title/`, not `A##_Title/`.
// The `_2025-` infix is part of the slug — without it owasp.org returns 404.
// Verified empirically against https://owasp.org/Top10/2025/ on 2026-05-24.
// Note: A09's slug includes the "Security_" prefix on owasp.org, even though
// our internal mapping (references/owasp-mapping.md) drops it for brevity —
// the canonical title is "Security Logging and Alerting Failures".
const OWASP_URLS = {
  A01: 'https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/',
  A02: 'https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/',
  A03: 'https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/',
  A04: 'https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/',
  A05: 'https://owasp.org/Top10/2025/A05_2025-Injection/',
  A06: 'https://owasp.org/Top10/2025/A06_2025-Insecure_Design/',
  A07: 'https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/',
  A08: 'https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/',
  A09: 'https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/',
  A10: 'https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/',
};

function formatPrComment(report, { commitSha } = {}) {
  const findings = report.findings || [];
  const suppressed = report.suppressed_findings || [];
  const lines = [];

  // Header
  lines.push('## 🔐 security-audit — PR review');
  lines.push('');
  if (commitSha) {
    lines.push(`_Commit_: \`${commitSha.slice(0, 7)}\``);
    lines.push('');
  }

  if (findings.length === 0) {
    // No ACTIVE findings — but a suppressed finding is not the same as a clean
    // diff. If anything critical/high was muted, the headline must not be a
    // reassuring green check, or a real vulnerability hides behind a ✅.
    const mutedHigh = suppressed.filter(f => f.severity === 'critical' || f.severity === 'high');
    if (suppressed.length === 0) {
      lines.push('✅ **No security issues found in this diff.**');
    } else if (mutedHigh.length > 0) {
      lines.push(`⚠️ **No active findings, but ${suppressed.length} ${plural(suppressed.length, 'finding was', 'findings were')} suppressed** — including ${mutedHigh.length} critical/high. Confirm each suppression is justified before merging.`);
    } else {
      lines.push(`✅ **No active security findings** — ${suppressed.length} ${plural(suppressed.length, 'finding', 'findings')} suppressed (low/info).`);
    }
    lines.push('');
    if (report.non_security_observations?.length) {
      lines.push('### Notes');
      for (const note of report.non_security_observations) {
        lines.push(`- ${note}`);
      }
      lines.push('');
    }
    renderSuppressed(suppressed, lines);
    lines.push(footer(report));
    return lines.join('\n');
  }

  // Summary
  const sevs = report.summary?.by_severity || {};
  const sevSummary = ['critical', 'high', 'medium', 'low', 'info']
    .filter(s => sevs[s] > 0)
    .map(s => `${SEVERITY_EMOJI[s]} ${sevs[s]} ${s}`)
    .join(' · ');
  const suppressedNote = suppressed.length ? ` · 🔇 ${suppressed.length} suppressed` : '';
  lines.push(`**${findings.length} finding${findings.length === 1 ? '' : 's'}** — ${sevSummary || 'no severity breakdown'}${suppressedNote}`);
  lines.push('');

  // Sort by risk descending
  const sorted = [...findings].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));

  // Per-finding sections
  for (const [idx, f] of sorted.entries()) {
    const sevEmoji = SEVERITY_EMOJI[f.severity] || '•';
    const risk = f.risk_score !== undefined ? ` · risk \`${f.risk_score}\`/10` : '';
    lines.push(`### ${sevEmoji} ${idx + 1}. ${escapeMd(f.title)}`);
    lines.push('');
    const owaspUrl = OWASP_URLS[f.owasp_id] || 'https://owasp.org/Top10/';
    const cweNum = (f.cwe_id || '').replace(/[^0-9]/g, '');
    const cweUrl = cweNum ? `https://cwe.mitre.org/data/definitions/${cweNum}.html` : 'https://cwe.mitre.org/';
    lines.push(`**${f.severity.toUpperCase()}** · ${f.rule_id} · [${f.owasp_id}](${owaspUrl}) · [${f.cwe_id}](${cweUrl})${risk}`);
    lines.push('');
    lines.push(`📍 \`${f.file}:${f.line}\``);
    lines.push('');
    if (f.evidence) {
      const fence = pickFence(f.evidence);
      lines.push(fence);
      lines.push(f.evidence);
      lines.push(fence);
      lines.push('');
    }
    if (f.rationale) {
      lines.push(`**Why this matters**: ${escapeMd(f.rationale)}`);
      lines.push('');
    }
    if (f.remediation) {
      lines.push(`**Suggested fix**: ${escapeMd(f.remediation)}`);
      lines.push('');
    }
    lines.push(`<sub>Verdict: ${VERDICT_LABEL[f.verdict] || f.verdict} · Confidence: ${f.confidence}</sub>`);
    lines.push('');
    lines.push('---');
    lines.push('');
  }

  if (report.non_security_observations?.length) {
    lines.push('### 📝 Non-security observations');
    lines.push('');
    for (const note of report.non_security_observations) {
      lines.push(`- ${note}`);
    }
    lines.push('');
  }

  renderSuppressed(suppressed, lines);

  // Suppression hint
  lines.push('<details><summary>How to suppress a finding</summary>');
  lines.push('');
  lines.push('Add a comment on the line above the flagged code:');
  lines.push('```js');
  lines.push('// security-audit-ignore: <rule_id> — short reason');
  lines.push('```');
  lines.push('Or repo-wide via `.security-audit-ignore` (gitignore-style globs + rule IDs).');
  lines.push('');
  lines.push('</details>');
  lines.push('');

  lines.push(footer(report));
  return lines.join('\n');
}

function plural(n, one, many) {
  return n === 1 ? one : many;
}

/**
 * Render the suppressed-findings section. A suppressed finding is one the LLM
 * reported but `suppression.mjs` muted via an inline directive or the repo
 * `.security-audit-ignore` file. We surface them explicitly so a reviewer can
 * audit each mute — silently dropping them is what lets a suppressed critical
 * SQLi masquerade as a clean diff.
 */
function renderSuppressed(suppressed, lines) {
  if (!suppressed?.length) return;
  lines.push(`### 🔇 Suppressed findings (${suppressed.length})`);
  lines.push('');
  lines.push('Reported by the analyzer but muted by a suppression directive — **not** counted as active findings. Confirm each mute is justified.');
  lines.push('');
  const sorted = [...suppressed].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
  for (const f of sorted) {
    const sevEmoji = SEVERITY_EMOJI[f.severity] || '•';
    const sup = f.suppression || {};
    let how;
    if (sup.source === 'inline') {
      how = `inline directive at line ${sup.directive_line}`;
    } else if (sup.source === 'ignore-file') {
      const pat = [sup.rule_pattern, sup.glob].filter(Boolean).join(' ');
      how = `\`.security-audit-ignore\`${pat ? ` (${escapeMd(pat)})` : ''}`;
    } else {
      how = escapeMd(sup.source || 'suppressed');
    }
    const sev = (f.severity || 'info').toUpperCase();
    lines.push(`- ${sevEmoji} **${sev}** \`${f.rule_id}\` — ${escapeMd(f.title || '')} · 📍 \`${f.file}:${f.line}\` · muted by ${how}`);
  }
  lines.push('');
}

function footer(report) {
  const parts = [];
  if (report.tool?.name) parts.push(`${report.tool.name}@${report.tool.version ?? '?'}`);
  // `!= null` (loose) so we skip both undefined AND null. `roundCost()` in
  // providers/_common.mjs legitimately returns null when the model is not in
  // PRICING_PER_1M; calling .toFixed() on null throws.
  if (report.cost != null) parts.push(`cost ≈ $${report.cost.toFixed(4)}`);
  if (report.latency_ms != null) parts.push(`latency ${(report.latency_ms / 1000).toFixed(1)}s`);
  if (report.model) parts.push(`model ${report.model}`);
  const meta = parts.length ? `<sub>${parts.join(' · ')}</sub>` : '';
  return `<sub>🤖 Powered by [security-audit](https://github.com/dmytrosorokame/security-audit)</sub>${meta ? ' · ' + meta : ''}`;
}

// Markdown-safe escape for prose fields (title / rationale / remediation).
//
// We use HTML entities for `<` `>` `&` rather than backslash-escapes because
// CommonMark only honours backslash-escapes for the ASCII-punctuation list,
// which does NOT include `<` or `>`. A literal `\<script>` therefore renders
// as `<script>` and would be interpreted as HTML by the surrounding markdown
// engine (GitHub filters `<script>` specifically, but other tags like `<img
// onerror>` may still execute depending on the host). HTML entities are
// rendered as visible text by every Markdown processor — 100% safe.
//
// Backtick still uses backslash-escape because it's in the CommonMark
// escapable set and keeps inline-code rendering correct in URL labels.
function escapeMd(s) {
  if (typeof s !== 'string') return s;
  return s
    .replace(/&/g, '&amp;')   // MUST be first — converting < to &lt; first would double-escape
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/`/g, '\\`');
}

/**
 * Pick a fence (sequence of backticks) for a fenced code block that is
 * guaranteed to wrap `content` cleanly even if it contains backtick runs.
 * CommonMark: fence must contain more backticks than the longest run inside.
 *
 * @param {string} content
 * @returns {string} the opening/closing fence string
 */
function pickFence(content) {
  let longestRun = 0;
  if (typeof content === 'string') {
    const matches = content.match(/`+/g) || [];
    for (const m of matches) longestRun = Math.max(longestRun, m.length);
  }
  return '`'.repeat(Math.max(3, longestRun + 1));
}

async function readStdin() {
  let data = '';
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

async function main() {
  const { values } = parseArgs({
    options: {
      input: { type: 'string' },
      'commit-sha': { type: 'string' },
    },
    strict: true,
  });

  const raw = values.input ? fs.readFileSync(values.input, 'utf8') : await readStdin();
  if (!raw.trim()) { console.error('format_pr_comment: empty input'); process.exit(1); }
  const report = JSON.parse(raw);
  process.stdout.write(formatPrComment(report, { commitSha: values['commit-sha'] }) + '\n');
}

if (import.meta.url === `file://${process.argv[1]}`) main();

export { formatPrComment, escapeMd, pickFence };
