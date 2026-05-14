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

import crypto from 'node:crypto';
import fs from 'node:fs';
import { parseArgs } from 'node:util';

const SEVERITY_TO_SARIF = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'none',
};

const SUPPRESSION_KIND_TO_SARIF = {
  inline: 'inSource',
  'repo-ignore': 'external',
  external: 'external',
};

/**
 * Stable fingerprint used by GitHub Code Scanning to dedupe findings across
 * runs. Combination of rule_id + file + evidence — same finding in same file
 * with same code stays identified even if line numbers shift after a refactor.
 *
 * @param {{rule_id?: string, file?: string, evidence?: string}} f
 * @returns {string}
 */
function fingerprintFinding(f) {
  const key = [f.rule_id || '', f.file || '', (f.evidence || '').replace(/\s+/g, ' ').trim()].join('|');
  return crypto.createHash('sha256').update(key).digest('hex').slice(0, 32);
}

/**
 * Build a SARIF 2.1.0 log from a security-audit report.
 *
 * @param {object} report — output of scan_diff (findings, suppressed_findings, tool, scanned_at)
 * @returns {object} SARIF document
 */
function formatSarif(report) {
  const findings = report.findings || [];
  const suppressedFindings = report.suppressed_findings || [];

  // Build unique rules array from BOTH active and suppressed findings so the
  // Code Scanning UI can render suppressed entries (which still reference
  // their rule_id via results[].ruleId).
  const rulesMap = new Map();
  for (const f of [...findings, ...suppressedFindings]) {
    const id = f.rule_id;
    if (!id) continue;
    if (!rulesMap.has(id)) {
      rulesMap.set(id, {
        id,
        name: id,
        shortDescription: {
          text: f.title || id,
        },
        fullDescription: {
          text: `${id} maps to ${f.owasp_id || 'OWASP-UNKNOWN'} / ${f.cwe_id || 'CWE-UNKNOWN'}.`,
        },
        helpUri: f.cwe_id && f.cwe_id !== 'CWE-UNKNOWN'
          ? `https://cwe.mitre.org/data/definitions/${f.cwe_id.replace(/[^0-9]/g, '')}.html`
          : 'https://owasp.org/Top10/',
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

  const buildResult = (f, suppression) => {
    const fp = fingerprintFinding(f);
    const result = {
      ruleId: f.rule_id,
      level: SEVERITY_TO_SARIF[f.severity] || 'warning',
      message: {
        text: f.rationale || f.title || f.rule_id,
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
      partialFingerprints: {
        'security-audit/v1': fp,
      },
      properties: {
        verdict: f.verdict,
        confidence: f.confidence,
        risk_score: f.risk_score,
        remediation: f.remediation,
      },
    };
    if (suppression) {
      result.suppressions = [
        {
          kind: SUPPRESSION_KIND_TO_SARIF[suppression.source] || 'external',
          justification: suppression.reason || 'Suppressed by security-audit configuration',
        },
      ];
    }
    return result;
  };

  const results = [
    ...findings.map(f => buildResult(f, null)),
    ...suppressedFindings.map(f => buildResult(f, f.suppression || { source: 'external', reason: 'suppressed' })),
  ];

  const automationId = report.run_id
    || `security-audit/${(report.scanned_at || new Date().toISOString()).slice(0, 10)}/${crypto.randomBytes(4).toString('hex')}`;

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
        automationDetails: {
          id: automationId,
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

export { formatSarif, fingerprintFinding };
