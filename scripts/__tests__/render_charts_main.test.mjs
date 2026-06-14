import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  main,
  parseResults,
  figLatencyCost,
  SvgCanvas,
} from '../render_charts.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');
const RESULTS = path.join(ROOT, 'benchmark', 'results.md');
const CATALOG = path.join(ROOT, 'references', 'owasp-rules.md');

// Drives the full render pipeline in-process (parseResults → all five figures →
// emit svg+png → writeGallery) against the committed benchmark fixtures. This
// is the coverage path for figConfusion/figCoverage/emit/writeGallery/main,
// which a subprocess run would not instrument.
describe('render_charts main — full pipeline', () => {
  let outDir;
  let savedArgv;

  beforeAll(() => {
    outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'render-charts-'));
    savedArgv = process.argv;
    process.argv = ['node', 'render_charts.mjs', `--results=${RESULTS}`, `--catalog=${CATALOG}`, `--out=${outDir}`];
    main();
  });

  afterAll(() => {
    process.argv = savedArgv;
    fs.rmSync(outDir, { recursive: true, force: true });
  });

  it('writes all five figures as both svg and png', () => {
    const names = ['f1_per_corpus', 'confusion_matrix', 'generalisation_gap', 'latency_cost', 'coverage_map'];
    for (const n of names) {
      expect(fs.existsSync(path.join(outDir, `${n}.svg`)), `${n}.svg`).toBe(true);
      expect(fs.existsSync(path.join(outDir, `${n}.png`)), `${n}.png`).toBe(true);
    }
  });

  it('emits a valid SVG document for each figure', () => {
    const svg = fs.readFileSync(path.join(outDir, 'f1_per_corpus.svg'), 'utf8');
    expect(svg).toMatch(/^<svg xmlns=/);
    expect(svg.trimEnd()).toMatch(/<\/svg>$/);
  });

  it('emits non-empty PNG buffers', () => {
    const png = fs.readFileSync(path.join(outDir, 'coverage_map.png'));
    expect(png.length).toBeGreaterThan(0);
    // PNG magic number.
    expect(png.subarray(0, 4).toString('hex')).toBe('89504e47');
  });

  it('writes a gallery index.md referencing every figure', () => {
    const idx = fs.readFileSync(path.join(outDir, 'index.md'), 'utf8');
    expect(idx).toMatch(/# Benchmark figures/);
    for (const n of ['f1_per_corpus', 'confusion_matrix', 'generalisation_gap', 'latency_cost', 'coverage_map']) {
      expect(idx, n).toContain(`![`);
      expect(idx, n).toContain(`${n}.svg`);
    }
  });
});

describe('render_charts main — svg-only / png-only', () => {
  it('--svg-only writes svg but no png', () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'render-svg-'));
    const saved = process.argv;
    try {
      process.argv = ['node', 'render_charts.mjs', `--results=${RESULTS}`, `--catalog=${CATALOG}`, `--out=${outDir}`, '--svg-only'];
      main();
      expect(fs.existsSync(path.join(outDir, 'f1_per_corpus.svg'))).toBe(true);
      expect(fs.existsSync(path.join(outDir, 'f1_per_corpus.png'))).toBe(false);
    } finally {
      process.argv = saved;
      fs.rmSync(outDir, { recursive: true, force: true });
    }
  });

  it('--png-only writes png but no svg', () => {
    const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'render-png-'));
    const saved = process.argv;
    try {
      process.argv = ['node', 'render_charts.mjs', `--results=${RESULTS}`, `--catalog=${CATALOG}`, `--out=${outDir}`, '--png-only'];
      main();
      expect(fs.existsSync(path.join(outDir, 'f1_per_corpus.png'))).toBe(true);
      expect(fs.existsSync(path.join(outDir, 'f1_per_corpus.svg'))).toBe(false);
    } finally {
      process.argv = saved;
      fs.rmSync(outDir, { recursive: true, force: true });
    }
  });
});

describe('figLatencyCost — direct render', () => {
  it('draws panel titles and corpus labels from parsed data', () => {
    const data = parseResults(fs.readFileSync(RESULTS, 'utf8'));
    const c = new SvgCanvas(900, 640);
    figLatencyCost(c, data);
    const svg = c.toBuffer().toString('utf8');
    expect(svg).toContain('Latency (s)');
    expect(svg).toContain('Cost (USD)');
    // Whiskers + bars produce a healthy number of primitives.
    expect(c.parts.length).toBeGreaterThan(20);
  });

  it('handles a corpus with no latency/cost data without throwing', () => {
    const data = { corpora: [{ short: 'empty', cases: [] }] };
    const c = new SvgCanvas(900, 640);
    expect(() => figLatencyCost(c, data)).not.toThrow();
  });
});
