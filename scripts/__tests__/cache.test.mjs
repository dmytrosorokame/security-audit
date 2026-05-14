import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { computeCacheKey, readCache, writeCache, redactReportSecrets } from '../llm_analyze.mjs';

const grounding = [
  { label: 'system', text: 'system prompt' },
  { label: 'rules', text: 'rule catalog' },
];
const userMsg = 'diff here';

describe('computeCacheKey', () => {
  it('produces a 64-char hex sha256', () => {
    const key = computeCacheKey('openai', 'gpt-4o-mini', grounding, userMsg);
    expect(key).toMatch(/^[a-f0-9]{64}$/);
  });

  it('is deterministic across calls', () => {
    const a = computeCacheKey('openai', 'gpt-4o-mini', grounding, userMsg);
    const b = computeCacheKey('openai', 'gpt-4o-mini', grounding, userMsg);
    expect(a).toBe(b);
  });

  it('differs when provider changes', () => {
    const a = computeCacheKey('openai', 'gpt-4o-mini', grounding, userMsg);
    const b = computeCacheKey('anthropic', 'gpt-4o-mini', grounding, userMsg);
    expect(a).not.toBe(b);
  });

  it('differs when model changes', () => {
    const a = computeCacheKey('openai', 'gpt-4o-mini', grounding, userMsg);
    const b = computeCacheKey('openai', 'gpt-4o', grounding, userMsg);
    expect(a).not.toBe(b);
  });

  it('differs when grounding catalog changes', () => {
    const a = computeCacheKey('openai', 'gpt-4o-mini', grounding, userMsg);
    const altered = [...grounding, { label: 'extra', text: 'new rule' }];
    const b = computeCacheKey('openai', 'gpt-4o-mini', altered, userMsg);
    expect(a).not.toBe(b);
  });

  it('differs when user diff changes', () => {
    const a = computeCacheKey('openai', 'gpt-4o-mini', grounding, userMsg);
    const b = computeCacheKey('openai', 'gpt-4o-mini', grounding, userMsg + 'x');
    expect(a).not.toBe(b);
  });
});

describe('readCache / writeCache (file-based)', () => {
  let dir;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sa-cache-test-'));
  });
  afterEach(() => {
    if (dir && fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
  });

  it('round-trips a value through writeCache → readCache', () => {
    const key = 'a'.repeat(64);
    const value = { findings: [{ rule_id: 'R-02' }], cost_usd: 0.001 };
    writeCache(dir, key, value);
    expect(readCache(dir, key)).toEqual(value);
  });

  it('returns null when the entry does not exist', () => {
    expect(readCache(dir, 'b'.repeat(64))).toBeNull();
  });

  it('creates the cache directory if missing (mkdir recursive)', () => {
    const nested = path.join(dir, 'nested', 'sub');
    writeCache(nested, 'c'.repeat(64), { x: 1 });
    expect(fs.existsSync(path.join(nested, 'c'.repeat(64) + '.json'))).toBe(true);
  });

  it('treats entries older than 24h as expired (returns null)', () => {
    const key = 'd'.repeat(64);
    writeCache(dir, key, { x: 1 });
    // Backdate the file to 25 hours ago.
    const file = path.join(dir, key + '.json');
    const stat = fs.statSync(file);
    const past = new Date(stat.mtimeMs - 25 * 60 * 60 * 1000);
    fs.utimesSync(file, past, past);
    expect(readCache(dir, key)).toBeNull();
  });

  it('returns null gracefully on a corrupt JSON entry', () => {
    const key = 'e'.repeat(64);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, key + '.json'), '{not json');
    expect(readCache(dir, key)).toBeNull();
  });

  it('writes atomically — no stray .tmp left after success', () => {
    const key = 'f'.repeat(64);
    writeCache(dir, key, { ok: true });
    const entries = fs.readdirSync(dir);
    expect(entries).toContain(key + '.json');
    expect(entries.some(e => e.endsWith('.tmp'))).toBe(false);
  });

  it('does not throw if cacheDir is not writable (degrades silently)', () => {
    // Pass a path that mkdir cannot create (e.g. /dev/null is a file).
    expect(() => writeCache('/dev/null/cache', 'key', { x: 1 })).not.toThrow();
  });

  it('round-trips a pre-redacted report (proves cache stores no plaintext secrets)', () => {
    const key = 'r'.repeat(64);
    const report = redactReportSecrets({
      findings: [{
        rule_id: 'R-07',
        evidence: 'apiKey=AKIAIOSFODNN7EXAMPLE',
        rationale: 'AWS key visible at line 12',
        remediation: 'Move AKIAIOSFODNN7EXAMPLE out of the repo',
      }],
    });
    writeCache(dir, key, report);
    // Read raw file bytes — assert no leaked secret survives anywhere on disk
    const onDisk = fs.readFileSync(path.join(dir, key + '.json'), 'utf8');
    expect(onDisk).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(onDisk).toContain('<REDACTED:AWS_ACCESS_KEY>');
  });
});

describe('redactReportSecrets', () => {
  it('redacts evidence / rationale / remediation across all findings', () => {
    const out = redactReportSecrets({
      findings: [
        { evidence: 'token=ghp_abcdefghijklmnopqrstuvwxyz0123456789', rationale: 'x' },
        { rationale: 'leak: AKIAIOSFODNN7EXAMPLE', remediation: 'rotate AKIAIOSFODNN7EXAMPLE' },
      ],
    });
    expect(out.findings[0].evidence).toContain('<REDACTED:GITHUB_PAT>');
    expect(out.findings[1].rationale).toContain('<REDACTED:AWS_ACCESS_KEY>');
    expect(out.findings[1].remediation).toContain('<REDACTED:AWS_ACCESS_KEY>');
  });

  it('also redacts suppressed_findings (they live in the cache too)', () => {
    const out = redactReportSecrets({
      findings: [],
      suppressed_findings: [{ evidence: 'apiKey=AKIAIOSFODNN7EXAMPLE' }],
    });
    expect(out.suppressed_findings[0].evidence).toContain('<REDACTED:AWS_ACCESS_KEY>');
  });

  it('leaves non-redactable metadata alone', () => {
    const input = {
      findings: [{ rule_id: 'R-07', severity: 'critical', file: 'config.ts', line: 3, evidence: '' }],
      cost: 0.003,
      latency_ms: 25500,
    };
    const out = redactReportSecrets(input);
    expect(out.findings[0].rule_id).toBe('R-07');
    expect(out.findings[0].severity).toBe('critical');
    expect(out.cost).toBe(0.003);
    expect(out.latency_ms).toBe(25500);
  });

  it('is a no-op on null/undefined/non-objects', () => {
    expect(redactReportSecrets(null)).toBeNull();
    expect(redactReportSecrets(undefined)).toBeUndefined();
    expect(redactReportSecrets('hello')).toBe('hello');
  });

  it('handles findings=undefined gracefully', () => {
    expect(redactReportSecrets({ cost: 0.001 })).toEqual({
      cost: 0.001,
      findings: undefined,
      suppressed_findings: undefined,
    });
  });
});
