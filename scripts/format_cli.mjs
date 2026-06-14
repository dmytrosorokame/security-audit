/**
 * format_cli.mjs — human-readable terminal output.
 *
 * Reads a security-audit report JSON from stdin (or --input=file.json),
 * prints colorized summary + per-finding details to stdout.
 *
 * Usage:
 *   echo '{"findings":[...]}' | node format_cli.mjs
 *   node format_cli.mjs --input=report.json
 *   node format_cli.mjs --input=report.json --no-color
 */

import fs from 'node:fs';
import { parseArgs } from 'node:util';

const COLOR = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
};

const SEVERITY_COLOR = {
  critical: COLOR.red,
  high: COLOR.red,
  medium: COLOR.yellow,
  low: COLOR.blue,
  info: COLOR.gray,
};

const VERDICT_ICON = {
  TRUE_POSITIVE: '🔴',
  LIKELY_TP: '🟠',
  NEEDS_HUMAN: '🟡',
  FALSE_POSITIVE: '⚪',
};

function colorize(text, color, enabled) {
  if (!enabled) return text;
  return `${color}${text}${COLOR.reset}`;
}

function formatReport(report, { color = true } = {}) {
  const lines = [];
  const findings = report.findings || [];
  const summary = report.summary || {};

  // Header
  lines.push(colorize('━'.repeat(60), COLOR.gray, color));
  lines.push(colorize('  security-audit — diff review', COLOR.bold, color));
  lines.push(colorize('━'.repeat(60), COLOR.gray, color));
  lines.push('');

  if (findings.length === 0) {
    lines.push(colorize('  ✓ No security issues found in this diff', COLOR.cyan, color));
    lines.push('');
    if (report.non_security_observations?.length) {
      lines.push(colorize('  Notes:', COLOR.dim, color));
      for (const note of report.non_security_observations) {
        lines.push(`    • ${note}`);
      }
    }
    return lines.join('\n');
  }

  // Summary block
  const bs = summary.by_severity || {};
  const summaryParts = [];
  for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
    const n = bs[sev] || 0;
    if (n > 0) {
      summaryParts.push(colorize(`${n} ${sev}`, SEVERITY_COLOR[sev], color));
    }
  }
  lines.push(`  ${colorize(findings.length + ' finding' + (findings.length === 1 ? '' : 's'), COLOR.bold, color)}: ${summaryParts.join(', ') || '0'}`);

  if (summary.by_owasp && Object.keys(summary.by_owasp).length) {
    const byOwasp = Object.entries(summary.by_owasp).map(([k, v]) => `${k}: ${v}`).join(', ');
    lines.push(`  ${colorize('OWASP:', COLOR.dim, color)} ${byOwasp}`);
  }
  lines.push('');

  // Per-finding details
  findings.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));

  for (const f of findings) {
    const icon = VERDICT_ICON[f.verdict] || '•';
    const sevTag = colorize(`[${f.severity.toUpperCase()}]`, SEVERITY_COLOR[f.severity] || COLOR.reset, color);
    const risk = f.risk_score !== undefined ? colorize(`risk=${f.risk_score}`, COLOR.dim, color) : '';
    const ids = colorize(`${f.rule_id} ${f.owasp_id} ${f.cwe_id}`, COLOR.cyan, color);

    lines.push(`${icon} ${sevTag} ${colorize(f.title, COLOR.bold, color)} ${risk}`);
    lines.push(`   ${ids} — ${colorize(f.file + ':' + f.line, COLOR.magenta, color)}`);
    lines.push(`   ${colorize('verdict:', COLOR.dim, color)} ${f.verdict}  ${colorize('confidence:', COLOR.dim, color)} ${f.confidence}`);
    if (f.evidence) {
      const ev = f.evidence.split('\n').map(l => `       ${colorize(l, COLOR.gray, color)}`).join('\n');
      lines.push(`   ${colorize('evidence:', COLOR.dim, color)}`);
      lines.push(ev);
    }
    if (f.rationale) {
      lines.push(`   ${colorize('rationale:', COLOR.dim, color)} ${f.rationale}`);
    }
    if (f.remediation) {
      lines.push(`   ${colorize('fix:', COLOR.dim, color)} ${f.remediation}`);
    }
    lines.push('');
  }

  if (report.non_security_observations?.length) {
    lines.push(colorize('━'.repeat(60), COLOR.gray, color));
    lines.push(colorize('  Non-security observations:', COLOR.dim, color));
    for (const note of report.non_security_observations) {
      lines.push(`    • ${note}`);
    }
    lines.push('');
  }

  // `!= null` (loose) so we skip both undefined AND null. `roundCost()` in
  // providers/_common.mjs legitimately returns null when the model is not in
  // PRICING_PER_1M (e.g. custom --model=gpt-4-turbo-preview) — calling
  // .toFixed() on null throws "Cannot read properties of null".
  if (report.cost != null || report.latency_ms != null) {
    const parts = [];
    if (report.cost != null) parts.push(`cost ≈ $${report.cost.toFixed(4)}`);
    if (report.latency_ms != null) parts.push(`latency ${(report.latency_ms / 1000).toFixed(1)}s`);
    lines.push(colorize(`  ${parts.join(' · ')}`, COLOR.dim, color));
  }

  return lines.join('\n');
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
      'no-color': { type: 'boolean', default: false },
    },
    strict: true,
  });

  const raw = values.input ? fs.readFileSync(values.input, 'utf8') : await readStdin();
  if (!raw.trim()) {
    console.error('format_cli: empty input');
    process.exit(1);
  }
  const report = JSON.parse(raw);
  const color = !values['no-color'] && process.stdout.isTTY;
  console.log(formatReport(report, { color }));
}

if (import.meta.url === `file://${process.argv[1]}`) main();

export { formatReport };
