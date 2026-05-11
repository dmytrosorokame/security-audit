/**
 * format_sarif.mjs — converts a security-audit report into SARIF 2.1.0,
 * the standard format for GitHub Code Scanning, GitLab Security Dashboard,
 * Azure DevOps, and most SARIF-aware tooling.
 *
 * SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
 *
 * Usage:
 *   cat report.json | node format_sarif.mjs > report.sarif
 *   node format_sarif.mjs --input=report.json --output=report.sarif
 */

import fs from 'node:fs';
import { parseArgs } from 'node:util';

const SEVERITY_TO_SARIF = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'none',
};

function formatSarif(report) {
  const findings = report.findings || [];

  // Build unique rules array from findings
  const rulesMap = new Map();
  for (const f of findings) {
    const id = f.rule_id;
    if (!rulesMap.has(id)) {
      rulesMap.set(id, {
        id,
        name: titleCase(id),
        shortDescription: {
          text: f.title || titleCase(id),
        },
        fullDescription: {
          text: `${id} maps to ${f.owasp_id} / ${f.cwe_id}.`,
        },
        helpUri: f.cwe_id
          ? `https://cwe.mitre.org/data/definitions/${f.cwe_id.replace(/[^0-9]/g, '')}.html`
          : undefined,
        properties: {
          'security-severity': cvssScoreFromSeverity(f.severity),
          tags: ['security', f.owasp_id, f.cwe_id].filter(Boolean),
        },
        defaultConfiguration: {
          level: SEVERITY_TO_SARIF[f.severity] || 'warning',
        },
      });
    }
  }

  const results = findings.map(f => ({
    ruleId: f.rule_id,
    level: SEVERITY_TO_SARIF[f.severity] || 'warning',
    message: {
      text: f.rationale || f.title,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: f.file,
            uriBaseId: '%SRCROOT%',
          },
          region: {
            startLine: f.line,
            snippet: f.evidence ? { text: f.evidence } : undefined,
          },
        },
      },
    ],
    properties: {
      verdict: f.verdict,
      confidence: f.confidence,
      risk_score: f.risk_score,
      remediation: f.remediation,
    },
  }));

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: report.tool?.name || 'security-audit',
            version: report.tool?.version || '0.1.0',
            informationUri: 'https://github.com/dmytrosorokame/security-audit',
            rules: Array.from(rulesMap.values()),
          },
        },
        results,
        invocations: [
          {
            executionSuccessful: true,
            commandLine: 'security-audit scan-diff',
            startTimeUtc: report.scanned_at || new Date().toISOString(),
          },
        ],
      },
    ],
  };
}

function titleCase(s) {
  return (s || '').replace(/^./, c => c.toUpperCase()).replace(/[-_]/g, ' ');
}

function cvssScoreFromSeverity(sev) {
  // GitHub Code Scanning reads `security-severity` as CVSS score 0-10.
  return ({ critical: '9.5', high: '7.5', medium: '5.0', low: '3.0', info: '1.0' })[sev] || '5.0';
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
      output: { type: 'string' },
    },
    strict: true,
  });

  const raw = values.input ? fs.readFileSync(values.input, 'utf8') : await readStdin();
  if (!raw.trim()) { console.error('format_sarif: empty input'); process.exit(1); }
  const report = JSON.parse(raw);
  const sarif = formatSarif(report);
  const out = JSON.stringify(sarif, null, 2);
  if (values.output) {
    fs.writeFileSync(values.output, out + '\n');
  } else {
    process.stdout.write(out + '\n');
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main();

export { formatSarif };
