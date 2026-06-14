import { describe, it, expect } from 'vitest';
import {
  SvgCanvas,
  figF1PerCorpus,
  figGeneralisation,
  latencyCostLayout,
} from '../render_charts.mjs';
import { PngCanvas } from '../png_canvas.mjs';

// Catalog series colours (private to render_charts.mjs; mirrored here).
const STRICT = '#1f77b4';

const textParts = c => c.parts.filter(p => p.startsWith('<text'));
const countLabel = (c, v) => textParts(c).filter(p => p.includes(`>${v}<`)).length;

describe('figF1PerCorpus — value labels', () => {
  it('draws ONE value label per corpus when strict F1 == loose F1 (no overlap)', () => {
    const data = {
      corpora: [
        { short: 'a', strict: { f1: { v: 0.939, lo: 0.7, hi: 1 } }, loose: { f1: { v: 0.939, lo: 0.7, hi: 1 } } },
        { short: 'b', strict: { f1: { v: 0.8, lo: 0.6, hi: 0.9 } }, loose: { f1: { v: 0.8, lo: 0.6, hi: 0.9 } } },
      ],
    };
    const c = new SvgCanvas(900, 520);
    figF1PerCorpus(c, data);
    // Pre-fix this is 2 (one per bar, overlapping); fixed it collapses to 1.
    expect(countLabel(c, '0.939')).toBe(1);
    expect(countLabel(c, '0.800')).toBe(1);
  });

  it('still draws two labels when strict and loose differ', () => {
    const data = {
      corpora: [
        { short: 'a', strict: { f1: { v: 0.90, lo: 0.7, hi: 1 } }, loose: { f1: { v: 0.95, lo: 0.8, hi: 1 } } },
      ],
    };
    const c = new SvgCanvas(900, 520);
    figF1PerCorpus(c, data);
    expect(countLabel(c, '0.900')).toBe(1);
    expect(countLabel(c, '0.950')).toBe(1);
  });
});

describe('figGeneralisation — coincident strict/loose series', () => {
  const data = {
    corpora: [
      { base: 'expected', short: 'smoke', strict: { f1: { v: 0.9 } }, loose: { f1: { v: 0.9 } } },
      { base: 'independent_corpus', short: 'independent', strict: { f1: { v: 0.9 } }, loose: { f1: { v: 0.9 } } },
    ],
  };

  it('renders the strict line dashed so it stays visible under the loose line', () => {
    const c = new SvgCanvas(900, 520);
    figGeneralisation(c, data);
    const strictDashed = c.parts.filter(
      p => p.startsWith('<line') && p.includes(STRICT) && p.includes('stroke-dasharray'),
    );
    expect(strictDashed.length).toBeGreaterThan(0);
  });

  it('draws one value label per point when strict == loose (no overlap)', () => {
    const c = new SvgCanvas(900, 520);
    figGeneralisation(c, data);
    // Two points, both 0.90; pre-fix each series labels it → 4, fixed → 2.
    expect(countLabel(c, '0.90')).toBe(2);
  });
});

describe('latencyCostLayout — no vertical overlap', () => {
  it("a panel's x-axis labels clear the next panel's title", () => {
    const { panels } = latencyCostLayout(900, 640);
    const LABEL_H = 12;
    // panel 1 x-labels must sit above panel 2's title with room for the text.
    expect(panels[0].xlabelY + LABEL_H).toBeLessThanOrEqual(panels[1].titleY);
    // panel 1 plot must not run into its own x-labels or panel 2.
    expect(panels[0].box.y + panels[0].box.h).toBeLessThanOrEqual(panels[1].titleY);
  });
});

describe('PngCanvas.line — termination & dashing', () => {
  it('terminates on a diagonal line (regression: integer-Bresenham infinite loop)', () => {
    const c = new PngCanvas(60, 40);
    c.line(2, 2, 58, 38, { stroke: '#000000', width: 2 }); // would spin forever pre-fix
    expect(c.toBuffer().length).toBeGreaterThan(0);
  });

  it('a dashed line paints fewer pixels than a solid one', () => {
    const solid = new PngCanvas(60, 10, { background: '#ffffff' });
    solid.line(0, 5, 59, 5, { stroke: '#000000', width: 1 });
    const dashed = new PngCanvas(60, 10, { background: '#ffffff' });
    dashed.line(0, 5, 59, 5, { stroke: '#000000', width: 1, dash: '6,4' });
    // Sum darkness over the red channel; anti-aliasing makes a 1px line
    // downsample to grey, so count any non-white pixel, not just pure black.
    const ink = c => {
      const px = c._downsample();
      let sum = 0;
      for (let i = 0; i < px.length; i += 4) sum += 255 - px[i];
      return sum;
    };
    expect(ink(dashed)).toBeLessThan(ink(solid));
    expect(ink(dashed)).toBeGreaterThan(0);
  });
});
