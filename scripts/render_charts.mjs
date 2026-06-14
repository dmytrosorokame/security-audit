#!/usr/bin/env node
/**
 * render_charts.mjs — diploma visualisation (spec §8, workstream 4).
 *
 * Reads the committed `benchmark/results.md` (the single source of truth the
 * benchmark harness emits) and renders five figures into `benchmark/figures/`,
 * each as both SVG (crisp, for results.md / the report) and PNG (drop-in for
 * the .docx):
 *
 *   1. f1_per_corpus      — strict vs loose F1 per corpus, with 95% CI error
 *                           bars.
 *   2. confusion_matrix   — TP / FP / FN / TN counts per corpus (loose mode).
 *   3. generalisation_gap — F1 along the synthetic→external corpus chain,
 *                           showing the honest degradation trend.
 *   4. latency_cost       — median latency and cost per corpus, with min–max
 *                           whiskers across the corpus's cases.
 *   5. coverage_map       — every catalog rule, coloured by whether the corpora
 *                           exercise it and whether it was detected; the rules
 *                           added during benchmarking (B-18…B-22) highlighted.
 *
 * Zero external dependencies: SVG is string-templated here, PNG is rasterised
 * by ./png_canvas.mjs (Node `zlib` only). Re-run after every benchmark to
 * refresh the figures; nothing here calls the model or costs anything.
 *
 * Usage:
 *   node scripts/render_charts.mjs
 *   node scripts/render_charts.mjs --results=PATH --catalog=PATH --out=DIR
 *   node scripts/render_charts.mjs --png-only        # or --svg-only
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { PngCanvas } from './png_canvas.mjs';
import { extractCatalogRuleIds } from './catalog_rules.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');

// Rules added during the diploma's coverage-driven benchmarking (spec §3.1):
// B-18..B-21 from the NodeGoat corpus, B-22 (JWT verification) from Juice Shop.
// Highlighted on the coverage map so "benchmarking closed these gaps" is legible.
const NEW_RULES = new Set(['B-18', 'B-19', 'B-20', 'B-21', 'B-22']);

// Short, human display names for corpus dir basenames.
const SHORT = {
  expected: 'smoke',
  independent_corpus: 'independent',
  complex_corpus: 'complex',
  nodegoat_corpus: 'nodegoat',
  juiceshop_corpus: 'juiceshop',
  snyk_corpus: 'snyk',
  oss_pilot: 'oss_pilot',
};
// Honest synthetic→external ordering for the generalisation-gap line (snyk is a
// breadth supplement, not a point on the degradation axis — spec §4.3).
const GAP_ORDER = ['expected', 'independent_corpus', 'complex_corpus', 'nodegoat_corpus', 'juiceshop_corpus', 'oss_pilot'];

const C = {
  strict: '#1f77b4',
  loose: '#ff7f0e',
  tp: '#2ca02c',
  fp: '#ff7f0e',
  fn: '#d62728',
  tn: '#7f7f7f',
  grid: '#dddddd',
  axis: '#444444',
  text: '#222222',
  subtle: '#888888',
  covered: '#2ca02c',
  missed: '#d62728',
  unexercised: '#e3e3e3',
  newRule: '#e6a700',
  white: '#ffffff',
};

// ── results.md parser ────────────────────────────────────────────────────────

function cellsOf(line) {
  return line
    .split('|')
    .slice(1, -1)
    .map(c => c.trim());
}

function isSeparator(line) {
  return /^\|[\s:|-]+\|$/.test(line);
}

/** "R-02" | "R-01, R-01" | "—" | "— (TN expected)" → ['R-02'] | [...] | [] */
function parseRuleList(cell) {
  if (!cell || cell.startsWith('—')) return [];
  return cell
    .split(',')
    .map(s => s.trim().replace(/`/g, ''))
    .filter(s => s && s !== '—' && /^[RBD]-\d+$/.test(s));
}

/** "1 [0.61, 1]" | "**0.857 [0.6, 1]**" → { v, lo, hi } */
function parseValCI(cell) {
  const clean = cell.replace(/[*`]/g, '').trim();
  const m = clean.match(/([\d.]+)\s*\[\s*([\d.]+)\s*,\s*([\d.]+)\s*\]/);
  if (m) return { v: parseFloat(m[1]), lo: parseFloat(m[2]), hi: parseFloat(m[3]) };
  const n = parseFloat(clean);
  return { v: Number.isFinite(n) ? n : 0, lo: null, hi: null };
}

export function parseResults(md) {
  const lines = md.split('\n');
  const meta = {};
  const corpora = [];
  const gaps = [];
  let cur = null;
  let mode = 'head'; // head | corpus | gaps

  for (const raw of lines) {
    const line = raw.trimEnd();
    let m;
    if ((m = line.match(/^_Generated:\s*(.+?)_\s*$/))) meta.generated = m[1];
    else if ((m = line.match(/^-\s*Corpora:\s*(\d+)/))) meta.corpora = +m[1];
    else if ((m = line.match(/^-\s*Total cases:\s*(\d+)/))) meta.totalCases = +m[1];
    else if ((m = line.match(/^-\s*Seeds per case:\s*(\d+)/))) meta.seeds = +m[1];
    else if ((m = line.match(/^-\s*Provider:\s*(.+)$/))) meta.provider = m[1].trim();
    else if ((m = line.match(/^-\s*Model:\s*(.+)$/))) meta.model = m[1].trim();

    if ((m = line.match(/^##\s+Corpus:\s*`(.+?)`/))) {
      const label = m[1];
      const base = label.split('/').pop();
      cur = { label, base, short: SHORT[base] || base, cases: [], strict: null, loose: null };
      corpora.push(cur);
      mode = 'corpus';
      continue;
    }
    if (/^##\s+Generalisation gaps/.test(line)) {
      mode = 'gaps';
      cur = null;
      continue;
    }

    if (!line.startsWith('|') || isSeparator(line)) continue;
    const cells = cellsOf(line);
    if (cells.length === 0) continue;

    if (mode === 'corpus' && cur) {
      const head = cells[0].toLowerCase();
      if (head === 'case' || head === 'mode') continue;
      if (/^strict/i.test(cells[0]) || /^loose/i.test(cells[0])) {
        const key = /^strict/i.test(cells[0]) ? 'strict' : 'loose';
        cur[key] = {
          tp: +cells[1],
          fp: +cells[2],
          fn: +cells[3],
          tn: +cells[4],
          precision: parseValCI(cells[5]),
          recall: parseValCI(cells[6]),
          f1: parseValCI(cells[7]),
        };
      } else if (cells.length >= 6 && /\d+\s*ms/i.test(cells[4])) {
        cur.cases.push({
          id: cells[0],
          expected: parseRuleList(cells[1]),
          detected: parseRuleList(cells[2]),
          verdict: cells[3],
          latencyMs: parseInt(cells[4].replace(/[^\d]/g, ''), 10),
          costUsd: cells[5] === '—' ? null : parseFloat(cells[5].replace(/[^\d.]/g, '')),
        });
      }
    } else if (mode === 'gaps') {
      if (/transition/i.test(cells[0])) continue;
      const nums = s => (s.match(/-?\d+\.?\d*/g) || []).map(Number);
      const sp = nums(cells[1].replace(/`/g, ''));
      const lp = nums(cells[3].replace(/`/g, ''));
      gaps.push({
        label: cells[0],
        strict: { a: sp[0], b: sp[1], gap: parseFloat(cells[2].replace(/[*`]/g, '')) },
        loose: { a: lp[0], b: lp[1], gap: parseFloat(cells[4].replace(/[*`]/g, '')) },
      });
    }
  }
  return { meta, corpora, gaps };
}

// ── SVG backend (mirrors PngCanvas API) ──────────────────────────────────────

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export class SvgCanvas {
  constructor(width, height, { background = '#ffffff' } = {}) {
    this.w = width;
    this.h = height;
    this.parts = [];
    if (background) this.parts.push(`<rect x="0" y="0" width="${width}" height="${height}" fill="${background}"/>`);
  }

  rect(x, y, w, h, { fill = 'none', stroke = 'none', strokeWidth = 1, opacity = 1 } = {}) {
    const op = opacity !== 1 ? ` fill-opacity="${opacity}"` : '';
    const st = stroke !== 'none' ? ` stroke="${stroke}" stroke-width="${strokeWidth}"` : '';
    this.parts.push(
      `<rect x="${r2(x)}" y="${r2(y)}" width="${r2(w)}" height="${r2(h)}" fill="${fill}"${op}${st}/>`,
    );
  }

  line(x1, y1, x2, y2, { stroke = '#000', width = 1, opacity = 1, dash } = {}) {
    const d = dash ? ` stroke-dasharray="${dash}"` : '';
    const op = opacity !== 1 ? ` stroke-opacity="${opacity}"` : '';
    this.parts.push(
      `<line x1="${r2(x1)}" y1="${r2(y1)}" x2="${r2(x2)}" y2="${r2(y2)}" stroke="${stroke}" stroke-width="${width}"${d}${op}/>`,
    );
  }

  text(x, y, str, { fill = '#000', size = 12, anchor = 'start', weight = 'normal', opacity = 1 } = {}) {
    const a = anchor === 'middle' ? 'middle' : anchor === 'end' ? 'end' : 'start';
    const op = opacity !== 1 ? ` fill-opacity="${opacity}"` : '';
    const w = weight !== 'normal' ? ` font-weight="${weight}"` : '';
    // (x, y) is the text-box top-left; nudge to an approximate baseline.
    this.parts.push(
      `<text x="${r2(x)}" y="${r2(y + size * 0.82)}" font-family="'DejaVu Sans','Segoe UI',Arial,sans-serif" ` +
        `font-size="${size}" fill="${fill}" text-anchor="${a}"${w}${op}>${esc(str)}</text>`,
    );
  }

  toBuffer() {
    return Buffer.from(
      `<svg xmlns="http://www.w3.org/2000/svg" width="${this.w}" height="${this.h}" ` +
        `viewBox="0 0 ${this.w} ${this.h}">\n${this.parts.join('\n')}\n</svg>\n`,
      'utf8',
    );
  }
}

function r2(n) {
  return Math.round(n * 100) / 100;
}

// ── shared chart primitives ──────────────────────────────────────────────────

/** Draw a 0..1 metric Y axis with gridlines and tick labels into a plot box. */
function drawMetricAxis(c, box, { ticks = 5 } = {}) {
  for (let i = 0; i <= ticks; i++) {
    const val = i / ticks;
    const y = box.y + box.h - val * box.h;
    c.line(box.x, y, box.x + box.w, y, { stroke: C.grid, width: 1 });
    c.text(box.x - 8, y - 6, val.toFixed(2), { fill: C.subtle, size: 11, anchor: 'end' });
  }
  c.line(box.x, box.y, box.x, box.y + box.h, { stroke: C.axis, width: 1.5 });
  c.line(box.x, box.y + box.h, box.x + box.w, box.y + box.h, { stroke: C.axis, width: 1.5 });
}

function legend(c, x, y, items, { size = 12, gap = 18 } = {}) {
  let cx = x;
  for (const it of items) {
    c.rect(cx, y, size, size, { fill: it.color });
    c.text(cx + size + 5, y + 1, it.label, { fill: C.text, size });
    cx += size + 7 + it.label.length * size * 0.6 + gap;
  }
}

// ── figure 1: per-corpus F1 (strict vs loose) with CI ────────────────────────

export function figF1PerCorpus(c, data) {
  const { corpora } = data;
  const W = c.w;
  const H = c.h;
  const box = { x: 70, y: 70, w: W - 110, h: H - 150 };
  c.text(W / 2, 18, 'Detection F1 per corpus (strict vs loose) — 95% CI', {
    size: 18,
    anchor: 'middle',
    weight: 'bold',
    fill: C.text,
  });
  drawMetricAxis(c, box);

  const n = corpora.length;
  const slot = box.w / n;
  const barW = Math.min(46, slot * 0.30);
  corpora.forEach((corp, i) => {
    const cx = box.x + slot * (i + 0.5);
    const groups = [
      { key: 'strict', color: C.strict, dx: -barW * 0.55 },
      { key: 'loose', color: C.loose, dx: barW * 0.55 },
    ];
    for (const g of groups) {
      const mt = corp[g.key];
      if (!mt) continue;
      const h = mt.f1.v * box.h;
      const bx = cx + g.dx - barW / 2;
      const by = box.y + box.h - h;
      c.rect(bx, by, barW, h, { fill: g.color });
      // CI whisker
      if (mt.f1.lo != null && mt.f1.hi != null) {
        const yl = box.y + box.h - mt.f1.lo * box.h;
        const yh = box.y + box.h - mt.f1.hi * box.h;
        c.line(cx + g.dx, yh, cx + g.dx, yl, { stroke: C.axis, width: 1.5 });
        c.line(cx + g.dx - 5, yh, cx + g.dx + 5, yh, { stroke: C.axis, width: 1.5 });
        c.line(cx + g.dx - 5, yl, cx + g.dx + 5, yl, { stroke: C.axis, width: 1.5 });
      }
    }
    // Value labels: one centred label when strict == loose (the two would
    // otherwise overlap into unreadable text); one above each bar otherwise.
    const s = corp.strict;
    const l = corp.loose;
    const lbl = (val, dx) =>
      c.text(cx + dx, box.y + box.h - val * box.h - 16, val.toFixed(3), { fill: C.text, size: 11, anchor: 'middle' });
    if (s && l && s.f1.v.toFixed(3) === l.f1.v.toFixed(3)) {
      lbl(s.f1.v, 0);
    } else {
      if (s) lbl(s.f1.v, -barW * 0.55);
      if (l) lbl(l.f1.v, barW * 0.55);
    }
    c.text(cx, box.y + box.h + 8, corp.short, { fill: C.text, size: 11, anchor: 'middle' });
  });

  legend(c, box.x, H - 28, [
    { label: 'strict (rule_id)', color: C.strict },
    { label: 'loose (OWASP+CWE)', color: C.loose },
  ]);
}

// ── figure 2: confusion matrix counts per corpus ─────────────────────────────

function figConfusion(c, data) {
  const { corpora } = data;
  const W = c.w;
  const H = c.h;
  const box = { x: 60, y: 70, w: W - 90, h: H - 150 };
  c.text(W / 2, 18, 'Outcome counts per corpus (loose mode)', {
    size: 18,
    anchor: 'middle',
    weight: 'bold',
    fill: C.text,
  });

  const maxCount = Math.max(
    1,
    ...corpora.flatMap(co => (co.loose ? [co.loose.tp, co.loose.fp, co.loose.fn, co.loose.tn] : [0])),
  );
  const ticks = Math.min(maxCount, 5);
  for (let i = 0; i <= ticks; i++) {
    const val = Math.round((maxCount * i) / ticks);
    const y = box.y + box.h - (val / maxCount) * box.h;
    c.line(box.x, y, box.x + box.w, y, { stroke: C.grid, width: 1 });
    c.text(box.x - 8, y - 6, String(val), { fill: C.subtle, size: 11, anchor: 'end' });
  }
  c.line(box.x, box.y, box.x, box.y + box.h, { stroke: C.axis, width: 1.5 });
  c.line(box.x, box.y + box.h, box.x + box.w, box.y + box.h, { stroke: C.axis, width: 1.5 });

  const kinds = [
    { key: 'tp', color: C.tp },
    { key: 'fp', color: C.fp },
    { key: 'fn', color: C.fn },
    { key: 'tn', color: C.tn },
  ];
  const n = corpora.length;
  const slot = box.w / n;
  const barW = Math.min(16, (slot * 0.7) / kinds.length);
  corpora.forEach((corp, i) => {
    const cx = box.x + slot * (i + 0.5);
    const groupW = barW * kinds.length;
    kinds.forEach((k, j) => {
      const v = corp.loose ? corp.loose[k.key] : 0;
      const h = (v / maxCount) * box.h;
      const bx = cx - groupW / 2 + j * barW;
      const by = box.y + box.h - h;
      c.rect(bx, by, barW - 2, h, { fill: k.color });
      if (v > 0) c.text(bx + (barW - 2) / 2, by - 14, String(v), { fill: C.text, size: 10, anchor: 'middle' });
    });
    c.text(cx, box.y + box.h + 8, corp.short, { fill: C.text, size: 11, anchor: 'middle' });
  });

  legend(c, box.x, H - 28, [
    { label: 'TP', color: C.tp },
    { label: 'FP', color: C.fp },
    { label: 'FN', color: C.fn },
    { label: 'TN', color: C.tn },
  ]);
}

// ── figure 3: generalisation gap line ────────────────────────────────────────

export function figGeneralisation(c, data) {
  const W = c.w;
  const H = c.h;
  const box = { x: 70, y: 70, w: W - 110, h: H - 150 };
  c.text(W / 2, 18, 'Generalisation: F1 along the synthetic → external chain', {
    size: 18,
    anchor: 'middle',
    weight: 'bold',
    fill: C.text,
  });
  drawMetricAxis(c, box);

  const byBase = new Map(data.corpora.map(co => [co.base, co]));
  const chain = GAP_ORDER.filter(b => byBase.has(b)).map(b => byBase.get(b));
  if (chain.length === 0) return;
  const n = chain.length;
  const xAt = i => box.x + (n === 1 ? box.w / 2 : (box.w * i) / (n - 1));
  const yAt = v => box.y + box.h - v * box.h;

  // Draw loose first (solid), then strict on top as a DASHED line, so when the
  // two series coincide (strict F1 == loose F1, as on every corpus here) the
  // strict line still reads as dashes over the loose line instead of being
  // hidden beneath it — keeping the legend honest.
  const seriesList = [
    { key: 'loose', color: C.loose, width: 2.5, dash: undefined },
    { key: 'strict', color: C.strict, width: 1.6, dash: '7,5' },
  ];
  for (const series of seriesList) {
    let prev = null;
    chain.forEach((corp, i) => {
      const mt = corp[series.key];
      if (!mt) return;
      const x = xAt(i);
      const y = yAt(mt.f1.v);
      if (prev) c.line(prev.x, prev.y, x, y, { stroke: series.color, width: series.width, dash: series.dash });
      prev = { x, y };
    });
    chain.forEach((corp, i) => {
      const mt = corp[series.key];
      if (!mt) return;
      c.rect(xAt(i) - 4, yAt(mt.f1.v) - 4, 8, 8, { fill: series.color });
    });
  }
  // Value labels: one per point when strict == loose (the two would overlap);
  // otherwise loose above and strict below the marker.
  chain.forEach((corp, i) => {
    const s = corp.strict;
    const l = corp.loose;
    const x = xAt(i);
    if (s && l && s.f1.v.toFixed(2) === l.f1.v.toFixed(2)) {
      c.text(x, yAt(s.f1.v) - 22, s.f1.v.toFixed(2), { fill: C.text, size: 11, anchor: 'middle' });
    } else {
      if (l) c.text(x, yAt(l.f1.v) - 22, l.f1.v.toFixed(2), { fill: C.loose, size: 11, anchor: 'middle' });
      if (s) c.text(x, yAt(s.f1.v) + 10, s.f1.v.toFixed(2), { fill: C.strict, size: 11, anchor: 'middle' });
    }
  });
  chain.forEach((corp, i) => {
    c.text(xAt(i), box.y + box.h + 8, corp.short, { fill: C.text, size: 11, anchor: 'middle' });
  });

  legend(c, box.x, H - 28, [
    { label: 'strict F1 (dashed)', color: C.strict },
    { label: 'loose F1', color: C.loose },
  ]);
}

// ── figure 4: latency & cost per corpus ──────────────────────────────────────

function median(arr) {
  if (arr.length === 0) return 0;
  const s = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

/**
 * Pure vertical layout for the stacked latency/cost panels. Returns the main
 * title baseline and, per panel, its plot `box`, its title baseline (`titleY`)
 * and its x-axis-label baseline (`xlabelY`). Extracted so the no-overlap
 * invariant (a panel's x-labels must clear the next panel's title) is testable
 * without rendering.
 */
export function latencyCostLayout(W, H) {
  const TOP = 44; // main-title band
  const TITLE_H = 22; // panel title block
  const XLABEL_H = 20; // x-axis label block beneath a panel
  const GAP = 22; // breathing room between a panel's x-labels and the next title
  const BOTTOM = 16;
  const plotH = (H - TOP - 2 * (TITLE_H + XLABEL_H) - GAP - BOTTOM) / 2;
  const x = 80;
  const w = W - 110;
  const p1Title = TOP;
  const p1BoxY = p1Title + TITLE_H;
  const p1XlabelY = p1BoxY + plotH + 4;
  const p2Title = p1XlabelY + XLABEL_H + GAP;
  const p2BoxY = p2Title + TITLE_H;
  const p2XlabelY = p2BoxY + plotH + 4;
  return {
    mainTitleY: 16,
    panels: [
      { box: { x, y: p1BoxY, w, h: plotH }, titleY: p1Title, xlabelY: p1XlabelY },
      { box: { x, y: p2BoxY, w, h: plotH }, titleY: p2Title, xlabelY: p2XlabelY },
    ],
  };
}

export function figLatencyCost(c, data) {
  const W = c.w;
  const H = c.h;
  const layout = latencyCostLayout(W, H);
  c.text(W / 2, layout.mainTitleY, 'Latency and cost per corpus (median, min–max whiskers)', {
    size: 18,
    anchor: 'middle',
    weight: 'bold',
    fill: C.text,
  });

  const stats = data.corpora.map(co => {
    const lat = co.cases.map(x => x.latencyMs).filter(Number.isFinite);
    const cost = co.cases.map(x => x.costUsd).filter(v => v != null);
    return {
      short: co.short,
      latMed: median(lat) / 1000,
      latMin: (lat.length ? Math.min(...lat) : 0) / 1000,
      latMax: (lat.length ? Math.max(...lat) : 0) / 1000,
      costMed: median(cost),
      costMin: cost.length ? Math.min(...cost) : 0,
      costMax: cost.length ? Math.max(...cost) : 0,
    };
  });

  const series = [
    { title: 'Latency (s)', max: Math.max(1, ...stats.map(s => s.latMax)), med: 'latMed', min: 'latMin', maxK: 'latMax', fmt: v => v.toFixed(1), color: C.strict },
    { title: 'Cost (USD)', max: Math.max(0.001, ...stats.map(s => s.costMax)), med: 'costMed', min: 'costMin', maxK: 'costMax', fmt: v => '$' + v.toFixed(4), color: C.loose },
  ];

  const n = stats.length;
  series.forEach((p, pi) => {
    const { box, titleY, xlabelY } = layout.panels[pi];
    c.text(box.x, titleY, p.title, { size: 13, weight: 'bold', fill: C.text });
    for (let i = 0; i <= 4; i++) {
      const val = (p.max * i) / 4;
      const y = box.y + box.h - (val / p.max) * box.h;
      c.line(box.x, y, box.x + box.w, y, { stroke: C.grid, width: 1 });
      c.text(box.x - 8, y - 6, p.fmt(val), { fill: C.subtle, size: 10, anchor: 'end' });
    }
    c.line(box.x, box.y, box.x, box.y + box.h, { stroke: C.axis, width: 1.5 });
    c.line(box.x, box.y + box.h, box.x + box.w, box.y + box.h, { stroke: C.axis, width: 1.5 });

    const slot = box.w / n;
    const barW = Math.min(40, slot * 0.4);
    stats.forEach((s, i) => {
      const cx = box.x + slot * (i + 0.5);
      const h = (s[p.med] / p.max) * box.h;
      const by = box.y + box.h - h;
      c.rect(cx - barW / 2, by, barW, h, { fill: p.color, opacity: 0.85 });
      const yMin = box.y + box.h - (s[p.min] / p.max) * box.h;
      const yMax = box.y + box.h - (s[p.maxK] / p.max) * box.h;
      c.line(cx, yMax, cx, yMin, { stroke: C.axis, width: 1.3 });
      c.line(cx - 4, yMax, cx + 4, yMax, { stroke: C.axis, width: 1.3 });
      c.line(cx - 4, yMin, cx + 4, yMin, { stroke: C.axis, width: 1.3 });
      c.text(cx, xlabelY, s.short, { fill: C.text, size: 10, anchor: 'middle' });
    });
  });
}

// ── figure 5: coverage map ───────────────────────────────────────────────────

function figCoverage(c, data, catalogRuleIds) {
  const W = c.w;
  const H = c.h;
  c.text(W / 2, 16, 'Catalog coverage map (rules exercised by the corpora)', {
    size: 18,
    anchor: 'middle',
    weight: 'bold',
    fill: C.text,
  });

  const expected = new Set();
  const detected = new Set();
  for (const co of data.corpora) {
    for (const cs of co.cases) {
      cs.expected.forEach(r => expected.add(r));
      cs.detected.forEach(r => detected.add(r));
    }
  }
  const statusOf = r => {
    if (!expected.has(r)) return 'unexercised';
    return detected.has(r) ? 'covered' : 'missed';
  };
  const colorOf = s => (s === 'covered' ? C.covered : s === 'missed' ? C.missed : C.unexercised);

  const tiers = [
    { name: 'Frontend (R)', rules: catalogRuleIds.filter(r => r.startsWith('R-')) },
    { name: 'Backend (B)', rules: catalogRuleIds.filter(r => r.startsWith('B-')) },
    { name: 'Container (D)', rules: catalogRuleIds.filter(r => r.startsWith('D-')) },
  ];

  const chipW = 56;
  const chipH = 30;
  const gapX = 10;
  const gapY = 12;
  const left = 30;
  const labelW = 130;
  const perRow = Math.floor((W - left - labelW - 20) / (chipW + gapX));
  let y = 56;
  for (const tier of tiers) {
    c.text(left, y + 6, tier.name, { size: 13, weight: 'bold', fill: C.text });
    let col = 0;
    let rowY = y;
    for (const rule of tier.rules) {
      if (col >= perRow) {
        col = 0;
        rowY += chipH + gapY;
      }
      const x = left + labelW + col * (chipW + gapX);
      const st = statusOf(rule);
      const isNew = NEW_RULES.has(rule);
      c.rect(x, rowY, chipW, chipH, {
        fill: colorOf(st),
        stroke: isNew ? C.newRule : C.subtle,
        strokeWidth: isNew ? 3 : 1,
      });
      const tColor = st === 'unexercised' ? C.text : C.white;
      c.text(x + chipW / 2, rowY + 7, rule, { size: 12, anchor: 'middle', fill: tColor, weight: isNew ? 'bold' : 'normal' });
      col++;
    }
    y = rowY + chipH + gapY + 14;
  }

  // legend
  const ly = H - 34;
  legend(c, left, ly, [
    { label: 'exercised + detected', color: C.covered },
    { label: 'exercised, missed', color: C.missed },
    { label: 'not exercised', color: C.unexercised },
  ]);
  c.rect(W - 230, ly, 16, 16, { fill: C.white, stroke: C.newRule, strokeWidth: 3 });
  c.text(W - 230 + 21, ly + 1, 'added via benchmarking', { fill: C.text, size: 12 });
}

// ── driver ───────────────────────────────────────────────────────────────────

function emit(outDir, name, w, h, draw, { svg, png }) {
  const written = [];
  if (svg) {
    const c = new SvgCanvas(w, h);
    draw(c);
    const p = path.join(outDir, `${name}.svg`);
    fs.writeFileSync(p, c.toBuffer());
    written.push(p);
  }
  if (png) {
    const c = new PngCanvas(w, h);
    draw(c);
    const p = path.join(outDir, `${name}.png`);
    fs.writeFileSync(p, c.toBuffer());
    written.push(p);
  }
  return written;
}

function writeGallery(outDir, data, figures) {
  const lines = ['# Benchmark figures', ''];
  lines.push(`_Rendered from \`${path.basename(data.resultsPath)}\` (generated ${data.meta.generated || 'n/a'})._`);
  lines.push('');
  lines.push(
    `Provider: ${data.meta.provider || 'n/a'} · model: ${data.meta.model || 'n/a'} · ` +
      `${data.corpora.length} corpora · ${data.meta.seeds || '?'} seed(s) per case.`,
  );
  lines.push('');
  for (const f of figures) {
    lines.push(`## ${f.title}`);
    lines.push('');
    lines.push(`![${f.title}](./${f.name}.svg)`);
    lines.push('');
    lines.push(`<sub>PNG: \`${f.name}.png\` · SVG: \`${f.name}.svg\`</sub>`);
    lines.push('');
  }
  fs.writeFileSync(path.join(outDir, 'index.md'), lines.join('\n') + '\n');
}

export function main() {
  const { values } = parseArgs({
    options: {
      results: { type: 'string', default: path.join(ROOT, 'benchmark', 'results.md') },
      catalog: { type: 'string', default: path.join(ROOT, 'references', 'owasp-rules.md') },
      out: { type: 'string', default: path.join(ROOT, 'benchmark', 'figures') },
      'svg-only': { type: 'boolean', default: false },
      'png-only': { type: 'boolean', default: false },
      help: { type: 'boolean', default: false },
    },
    strict: true,
  });
  if (values.help) {
    process.stdout.write(
      'Usage: node scripts/render_charts.mjs [--results=PATH] [--catalog=PATH] [--out=DIR] [--svg-only|--png-only]\n',
    );
    process.exit(0);
  }

  const md = fs.readFileSync(values.results, 'utf8');
  const data = parseResults(md);
  data.resultsPath = values.results;
  if (data.corpora.length === 0) {
    process.stderr.write(`No corpora parsed from ${values.results}\n`);
    process.exit(1);
  }
  const catalogRuleIds = extractCatalogRuleIds(values.catalog);

  fs.mkdirSync(values.out, { recursive: true });
  const svg = !values['png-only'];
  const png = !values['svg-only'];

  const figures = [
    { name: 'f1_per_corpus', title: 'F1 per corpus (strict vs loose)', w: 900, h: 520, draw: c => figF1PerCorpus(c, data) },
    { name: 'confusion_matrix', title: 'Outcome counts per corpus', w: 900, h: 520, draw: c => figConfusion(c, data) },
    { name: 'generalisation_gap', title: 'Generalisation gap', w: 900, h: 520, draw: c => figGeneralisation(c, data) },
    { name: 'latency_cost', title: 'Latency and cost per corpus', w: 900, h: 640, draw: c => figLatencyCost(c, data) },
    { name: 'coverage_map', title: 'Catalog coverage map', w: 940, h: 520, draw: c => figCoverage(c, data, catalogRuleIds) },
  ];

  let total = 0;
  for (const f of figures) {
    const written = emit(values.out, f.name, f.w, f.h, f.draw, { svg, png });
    total += written.length;
    process.stderr.write(`✓ ${f.name} (${written.length} file${written.length === 1 ? '' : 's'})\n`);
  }
  writeGallery(values.out, data, figures);
  process.stderr.write(`✓ wrote ${total} figure files + index.md to ${path.relative(process.cwd(), values.out) || values.out}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}
