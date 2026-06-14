import { describe, it, expect } from 'vitest';
import { KNOWN_CORPORA, GAP_CHAIN, buildGapPairs } from '../run_benchmark.mjs';

describe('KNOWN_CORPORA', () => {
  it('includes the three diploma external corpora', () => {
    expect(KNOWN_CORPORA).toContain('nodegoat_corpus');
    expect(KNOWN_CORPORA).toContain('juiceshop_corpus');
    expect(KNOWN_CORPORA).toContain('snyk_corpus');
  });

  it('preserves the original auto-detected corpora', () => {
    expect(KNOWN_CORPORA).toContain('independent_corpus');
    expect(KNOWN_CORPORA).toContain('complex_corpus');
    expect(KNOWN_CORPORA).toContain('oss_pilot');
  });
});

describe('GAP_CHAIN', () => {
  it('is the honest degradation order and excludes snyk_corpus', () => {
    expect(GAP_CHAIN).toEqual([
      'expected',
      'independent_corpus',
      'complex_corpus',
      'nodegoat_corpus',
      'juiceshop_corpus',
      'oss_pilot',
    ]);
    expect(GAP_CHAIN).not.toContain('snyk_corpus');
  });
});

describe('buildGapPairs', () => {
  const corpus = (label) => ({ label, metrics: { strict: { f1: 1 }, loose: { f1: 1 } } });

  it('builds consecutive pairs only for corpora present in the run', () => {
    const corpora = [corpus('benchmark/expected'), corpus('benchmark/complex_corpus'), corpus('benchmark/nodegoat_corpus')];
    const pairs = buildGapPairs(corpora);
    expect(pairs.map(p => p.label)).toEqual(['smoke → complex', 'complex → nodegoat']);
  });

  it('returns empty when fewer than two chain corpora are present', () => {
    expect(buildGapPairs([corpus('benchmark/snyk_corpus')])).toEqual([]);
  });

  it('matches a corpus by label suffix', () => {
    const pairs = buildGapPairs([corpus('benchmark/independent_corpus'), corpus('benchmark/oss_pilot')]);
    expect(pairs).toHaveLength(1);
    expect(pairs[0].a.label).toBe('benchmark/independent_corpus');
    expect(pairs[0].b.label).toBe('benchmark/oss_pilot');
  });
});
