import { describe, it, expect } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseRuleIds, extractCatalogRuleIds } from '../catalog_rules.mjs';

describe('parseRuleIds', () => {
  it('extracts R-/B-/D- ids from level-2 headers', () => {
    const md = [
      '# Catalog',
      '## R-01 — Unsanitized innerHTML',
      'prose',
      '## B-04 — SSRF',
      '## D-01 — Dockerfile root user',
    ].join('\n');
    expect(parseRuleIds(md)).toEqual(['R-01', 'B-04', 'D-01']);
  });

  it('ignores headers that are not rule ids', () => {
    const md = '## How the LLM uses this\n## Coverage\n## R-02 — DOM injection';
    expect(parseRuleIds(md)).toEqual(['R-02']);
  });

  it('dedupes and preserves first-seen order', () => {
    const md = '## R-01 — a\n## R-01 — dup\n## B-01 — b';
    expect(parseRuleIds(md)).toEqual(['R-01', 'B-01']);
  });
});

describe('extractCatalogRuleIds', () => {
  it('reads ids from a catalog file on disk', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cat-'));
    const file = path.join(dir, 'owasp-rules.md');
    fs.writeFileSync(file, '## R-01 — x\n## B-02 — y\n');
    expect(extractCatalogRuleIds(file)).toEqual(['R-01', 'B-02']);
  });

  it('reads the real project catalog and finds R-01 and B-04', () => {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const real = path.resolve(here, '../../references/owasp-rules.md');
    const ids = extractCatalogRuleIds(real);
    expect(ids).toContain('R-01');
    expect(ids).toContain('B-04');
    expect(ids.length).toBeGreaterThanOrEqual(30); // ~34 rules per ADR-004
  });
});
