/**
 * Catalog rule-id utilities. The OWASP grounding catalog
 * (references/owasp-rules.md) defines each rule as a level-2 header
 * `## <ID> — <title>` where <ID> matches /^[RBD]-\d+$/. These helpers
 * extract the authoritative set of rule ids so the corpus validator can
 * reject labels that reference a non-existent rule, and so the coverage
 * map (later plan) can list catalog-vs-exercised rules.
 */
import fs from 'node:fs';

const RULE_HEADER = /^##\s+([RBD]-\d+)\b/;

/**
 * @param {string} markdown — catalog file contents
 * @returns {string[]} rule ids in first-seen order, deduped
 */
export function parseRuleIds(markdown) {
  const seen = new Set();
  const out = [];
  for (const line of markdown.split('\n')) {
    const m = RULE_HEADER.exec(line);
    if (m && !seen.has(m[1])) {
      seen.add(m[1]);
      out.push(m[1]);
    }
  }
  return out;
}

/**
 * @param {string} catalogPath — path to owasp-rules.md
 * @returns {string[]}
 */
export function extractCatalogRuleIds(catalogPath) {
  return parseRuleIds(fs.readFileSync(catalogPath, 'utf8'));
}
