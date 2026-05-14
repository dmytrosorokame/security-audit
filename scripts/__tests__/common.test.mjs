import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  extractJsonFromText,
  roundCost,
  buildUserMessage,
  buildGroundingBlocks,
  ProviderError,
  envBool,
  withRetry,
} from '../providers/_common.mjs';

describe('extractJsonFromText — three strategies', () => {
  it('parses bare JSON', () => {
    const result = extractJsonFromText('{"findings":[]}');
    expect(result).toEqual({ findings: [] });
  });

  it('parses JSON with surrounding whitespace', () => {
    const result = extractJsonFromText('   \n{"a":1}\n  ');
    expect(result).toEqual({ a: 1 });
  });

  it('parses ```json fenced block (with json language hint)', () => {
    const text = 'Here is the result:\n```json\n{"x": 42}\n```\nDone.';
    expect(extractJsonFromText(text)).toEqual({ x: 42 });
  });

  it('parses ``` fenced block without language hint', () => {
    const text = 'preamble\n```\n{"y": 7}\n```';
    expect(extractJsonFromText(text)).toEqual({ y: 7 });
  });

  it('recovers JSON from prose-wrapped output (strategy 3)', () => {
    const text = 'Sure, here is the analysis: {"findings": [{"rule_id": "R-02"}]} — hope that helps!';
    expect(extractJsonFromText(text)).toEqual({ findings: [{ rule_id: 'R-02' }] });
  });

  it('throws on empty input with the context name in the message', () => {
    expect(() => extractJsonFromText('', 'OpenAI')).toThrow(/OpenAI returned empty/);
  });

  it('throws on whitespace-only input', () => {
    expect(() => extractJsonFromText('   \n  ')).toThrow(/empty response/);
  });

  it('throws an actionable error with head snippet when nothing parses', () => {
    const text = 'This is just prose with no JSON anywhere';
    expect(() => extractJsonFromText(text, 'Claude')).toThrow(/Claude did not return parseable JSON/);
  });

  it('prefers bare JSON over fenced JSON when both are valid', () => {
    // Bare JSON wins because strategy 1 runs first. This protects us against
    // accidentally pulling a "Here is what to do" example from the LLM's
    // prose explanation instead of the real output.
    const bare = '{"real": true}';
    expect(extractJsonFromText(bare)).toEqual({ real: true });
  });
});

describe('roundCost', () => {
  it('rounds to 6 decimal places', () => {
    expect(roundCost(0.0012345678)).toBe(0.001235);
  });

  it('returns null for null/undefined', () => {
    expect(roundCost(null)).toBeNull();
    expect(roundCost(undefined)).toBeNull();
  });

  it('returns null for NaN', () => {
    expect(roundCost(NaN)).toBeNull();
  });

  it('handles zero', () => {
    expect(roundCost(0)).toBe(0);
  });

  it('handles integers', () => {
    expect(roundCost(5)).toBe(5);
  });
});

describe('buildUserMessage', () => {
  it('wraps diff JSON in <diff>...</diff> markers', () => {
    const out = buildUserMessage({ files: [] });
    expect(out).toContain('<diff>');
    expect(out).toContain('</diff>');
  });

  it('serialises whitelisted stable fields, ignoring custom keys', () => {
    // Cache hygiene: only schema_version / mode / base / head / stats / files
    // are forwarded. Free-form fields like `a` are dropped to keep the cache
    // key stable across runs with different volatile metadata.
    const out = buildUserMessage({ a: 1, files: [{ path: 'foo.ts', hunks: [] }] });
    expect(out).not.toContain('"a": 1');
    expect(out).toContain('"path": "foo.ts"');
  });

  it('strips extracted_at and other volatile timestamps from the user message', () => {
    const a = buildUserMessage({ extracted_at: '2026-01-01T00:00:00Z', files: [] });
    const b = buildUserMessage({ extracted_at: '2030-12-31T23:59:59Z', files: [] });
    expect(a).toBe(b);
    expect(a).not.toContain('extracted_at');
  });

  it('mentions the OWASP catalog grounding requirement', () => {
    const out = buildUserMessage({});
    expect(out).toMatch(/OWASP catalog/);
  });

  it('asks for strict JSON output', () => {
    const out = buildUserMessage({});
    expect(out).toMatch(/strict JSON only/);
  });
});

describe('buildGroundingBlocks', () => {
  it('produces 4 blocks in the canonical order', () => {
    const blocks = buildGroundingBlocks({
      system: 'sys',
      fewShot: 'fs',
      owaspRules: 'rules',
      owaspMapping: 'mapping',
    });
    expect(blocks).toHaveLength(4);
    expect(blocks.map(b => b.label)).toEqual(['system', 'owasp-rules', 'owasp-mapping', 'few-shot']);
  });

  it('prepends a "Catalog (LLM grounding)" header to the rules block', () => {
    const blocks = buildGroundingBlocks({ system: '', fewShot: '', owaspRules: 'R-01 ...', owaspMapping: '' });
    expect(blocks[1].text).toContain('OWASP Vulnerability Pattern Catalog');
    expect(blocks[1].text).toContain('R-01 ...');
  });

  it('prepends headers to mapping and few-shot blocks too', () => {
    const blocks = buildGroundingBlocks({ system: '', fewShot: 'EX', owaspRules: '', owaspMapping: 'MAP' });
    expect(blocks[2].text).toContain('OWASP Top 10');
    expect(blocks[2].text).toContain('MAP');
    expect(blocks[3].text).toContain('Few-shot examples');
    expect(blocks[3].text).toContain('EX');
  });
});

describe('ProviderError', () => {
  it('embeds provider and kind in the message', () => {
    const err = new ProviderError('openai', 'rate_limit', 'too many requests');
    expect(err.message).toBe('[openai] rate_limit: too many requests');
    expect(err.provider).toBe('openai');
    expect(err.kind).toBe('rate_limit');
  });

  it('preserves the upstream cause', () => {
    const cause = new Error('underlying');
    const err = new ProviderError('anthropic', 'api', 'wrapped', cause);
    expect(err.cause).toBe(cause);
  });
});

describe('envBool', () => {
  const ORIG = process.env;
  beforeEach(() => { process.env = { ...ORIG }; });
  afterEach(() => { process.env = ORIG; });

  it.each([
    ['1', true],
    ['true', true],
    ['TRUE', true],
    ['yes', true],
    ['on', true],
    ['y', true],
    ['t', true],
    ['', false],
    ['0', false],
    ['false', false],
    ['no', false],
    ['nope', false],
  ])('envBool(%s) → %s', (val, expected) => {
    process.env.MY_TEST_VAR = val;
    expect(envBool('MY_TEST_VAR')).toBe(expected);
  });

  it('returns false for unset variables', () => {
    delete process.env.NEVER_SET_VAR;
    expect(envBool('NEVER_SET_VAR')).toBe(false);
  });
});

describe('withRetry', () => {
  it('returns the result on first success', async () => {
    const fn = vi.fn().mockResolvedValue('ok');
    const result = await withRetry(fn);
    expect(result).toBe('ok');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('retries up to `attempts` times on transient failures', async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error('transient'))
      .mockRejectedValueOnce(new Error('transient'))
      .mockResolvedValue('finally');
    const result = await withRetry(fn, { attempts: 3, baseDelayMs: 1, shouldRetry: () => true });
    expect(result).toBe('finally');
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it('throws the last error after exhausting attempts', async () => {
    const fn = vi.fn().mockRejectedValue(new Error('always fails'));
    await expect(withRetry(fn, { attempts: 2, baseDelayMs: 1, shouldRetry: () => true })).rejects.toThrow('always fails');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('does NOT retry when shouldRetry returns false (e.g. auth error)', async () => {
    const authErr = new Error('401 unauthorized');
    const fn = vi.fn().mockRejectedValue(authErr);
    await expect(withRetry(fn, { attempts: 3, baseDelayMs: 1, shouldRetry: () => false })).rejects.toThrow('401');
    // Critical guarantee: 401s should never burn through all 3 attempts.
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('invokes onRetry callback between attempts', async () => {
    const onRetry = vi.fn();
    const fn = vi.fn().mockRejectedValueOnce(new Error('e')).mockResolvedValue('ok');
    await withRetry(fn, { attempts: 2, baseDelayMs: 1, onRetry });
    expect(onRetry).toHaveBeenCalledTimes(1);
    expect(onRetry.mock.calls[0][1]).toBe(1); // attempt index
  });
});
