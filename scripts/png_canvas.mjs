/**
 * png_canvas.mjs — a tiny dependency-free raster canvas that encodes to PNG.
 *
 * The diploma visualisation (scripts/render_charts.mjs) must emit both SVG
 * (crisp, embedded in results.md and the report) and PNG (drop-in for the
 * .docx). The project deliberately ships only two runtime dependencies (the
 * Anthropic + OpenAI SDKs); pulling in a charting / canvas / rasteriser
 * library to make five static figures is not worth the supply-chain surface.
 *
 * So this module rasterises into an RGBA buffer using only axis-aligned
 * fills, Bresenham lines and an embedded 5×7 bitmap font, then encodes a
 * PNG with Node's built-in `zlib` (deflate) — zero external deps. It renders
 * at `ss`× the logical resolution and box-downsamples on encode, which gives
 * cheap anti-aliasing so diagonal lines and text read cleanly.
 *
 * The drawing surface mirrors the SvgCanvas API in render_charts.mjs (same
 * method names, same logical coordinate space, colours as `#rrggbb` hex), so
 * each chart is described once and rendered to either backend.
 */
import zlib from 'node:zlib';

// ── 5×7 bitmap font ────────────────────────────────────────────────────────
// Each glyph is 7 rows × 5 columns. PNG labels are upper-cased before drawing
// (see asciify), so lowercase letters intentionally reuse the uppercase
// glyphs. Characters with no glyph render as a hollow box so a missing glyph
// is visually obvious rather than silently dropped.
const GLYPHS = {
  ' ': ['     ', '     ', '     ', '     ', '     ', '     ', '     '],
  '0': [' ### ', '#   #', '#  ##', '# # #', '##  #', '#   #', ' ### '],
  '1': ['  #  ', ' ##  ', '  #  ', '  #  ', '  #  ', '  #  ', ' ### '],
  '2': [' ### ', '#   #', '    #', '   # ', '  #  ', ' #   ', '#####'],
  '3': [' ### ', '#   #', '    #', '  ## ', '    #', '#   #', ' ### '],
  '4': ['   # ', '  ## ', ' # # ', '#  # ', '#####', '   # ', '   # '],
  '5': ['#####', '#    ', '#### ', '    #', '    #', '#   #', ' ### '],
  '6': [' ### ', '#   #', '#    ', '#### ', '#   #', '#   #', ' ### '],
  '7': ['#####', '    #', '   # ', '  #  ', ' #   ', ' #   ', ' #   '],
  '8': [' ### ', '#   #', '#   #', ' ### ', '#   #', '#   #', ' ### '],
  '9': [' ### ', '#   #', '#   #', ' ####', '    #', '#   #', ' ### '],
  'A': [' ### ', '#   #', '#   #', '#####', '#   #', '#   #', '#   #'],
  'B': ['#### ', '#   #', '#   #', '#### ', '#   #', '#   #', '#### '],
  'C': [' ### ', '#   #', '#    ', '#    ', '#    ', '#   #', ' ### '],
  'D': ['#### ', '#   #', '#   #', '#   #', '#   #', '#   #', '#### '],
  'E': ['#####', '#    ', '#    ', '#### ', '#    ', '#    ', '#####'],
  'F': ['#####', '#    ', '#    ', '#### ', '#    ', '#    ', '#    '],
  'G': [' ### ', '#   #', '#    ', '# ###', '#   #', '#   #', ' ####'],
  'H': ['#   #', '#   #', '#   #', '#####', '#   #', '#   #', '#   #'],
  'I': [' ### ', '  #  ', '  #  ', '  #  ', '  #  ', '  #  ', ' ### '],
  'J': ['  ###', '   # ', '   # ', '   # ', '#  # ', '#  # ', ' ##  '],
  'K': ['#   #', '#  # ', '# #  ', '##   ', '# #  ', '#  # ', '#   #'],
  'L': ['#    ', '#    ', '#    ', '#    ', '#    ', '#    ', '#####'],
  'M': ['#   #', '## ##', '# # #', '# # #', '#   #', '#   #', '#   #'],
  'N': ['#   #', '##  #', '# # #', '# # #', '#  ##', '#   #', '#   #'],
  'O': [' ### ', '#   #', '#   #', '#   #', '#   #', '#   #', ' ### '],
  'P': ['#### ', '#   #', '#   #', '#### ', '#    ', '#    ', '#    '],
  'Q': [' ### ', '#   #', '#   #', '#   #', '# # #', '#  # ', ' ## #'],
  'R': ['#### ', '#   #', '#   #', '#### ', '# #  ', '#  # ', '#   #'],
  'S': [' ####', '#    ', '#    ', ' ### ', '    #', '    #', '#### '],
  'T': ['#####', '  #  ', '  #  ', '  #  ', '  #  ', '  #  ', '  #  '],
  'U': ['#   #', '#   #', '#   #', '#   #', '#   #', '#   #', ' ### '],
  'V': ['#   #', '#   #', '#   #', '#   #', '#   #', ' # # ', '  #  '],
  'W': ['#   #', '#   #', '#   #', '# # #', '# # #', '## ##', '#   #'],
  'X': ['#   #', '#   #', ' # # ', '  #  ', ' # # ', '#   #', '#   #'],
  'Y': ['#   #', '#   #', ' # # ', '  #  ', '  #  ', '  #  ', '  #  '],
  'Z': ['#####', '    #', '   # ', '  #  ', ' #   ', '#    ', '#####'],
  '.': ['     ', '     ', '     ', '     ', '     ', '  ## ', '  ## '],
  ',': ['     ', '     ', '     ', '     ', '  ## ', '  ## ', ' #   '],
  '-': ['     ', '     ', '     ', '#####', '     ', '     ', '     '],
  '+': ['     ', '  #  ', '  #  ', '#####', '  #  ', '  #  ', '     '],
  '=': ['     ', '     ', '#####', '     ', '#####', '     ', '     '],
  ':': ['     ', '  ## ', '  ## ', '     ', '  ## ', '  ## ', '     '],
  '/': ['    #', '    #', '   # ', '  #  ', ' #   ', '#    ', '#    '],
  '(': ['   # ', '  #  ', ' #   ', ' #   ', ' #   ', '  #  ', '   # '],
  ')': [' #   ', '  #  ', '   # ', '   # ', '   # ', '  #  ', ' #   '],
  '[': [' ### ', ' #   ', ' #   ', ' #   ', ' #   ', ' #   ', ' ### '],
  ']': [' ### ', '   # ', '   # ', '   # ', '   # ', '   # ', ' ### '],
  '%': ['##  #', '##  #', '   # ', '  #  ', ' #   ', '#  ##', '#  ##'],
  '$': ['  #  ', ' ####', '# #  ', ' ### ', '  # #', '#### ', '  #  '],
  '_': ['     ', '     ', '     ', '     ', '     ', '     ', '#####'],
  '>': ['#    ', ' #   ', '  #  ', '   # ', '  #  ', ' #   ', '#    '],
  '<': ['    #', '   # ', '  #  ', ' #   ', '  #  ', '   # ', '    #'],
  '^': ['  #  ', ' # # ', '#   #', '     ', '     ', '     ', '     '],
  '#': [' # # ', ' # # ', '#####', ' # # ', '#####', ' # # ', ' # # '],
  '|': ['  #  ', '  #  ', '  #  ', '  #  ', '  #  ', '  #  ', '  #  '],
};
const MISSING = ['#####', '#   #', '#   #', '#   #', '#   #', '#   #', '#####'];

const GLYPH_W = 5;
const GLYPH_H = 7;
const GLYPH_ADVANCE = 6; // 5 + 1px spacing, in glyph units

// Replace characters absent from the bitmap font with ASCII stand-ins so the
// PNG never shows the missing-glyph box for symbols the SVG renders natively.
function asciify(str) {
  return String(str)
    .replace(/→/g, '>')
    .replace(/×/g, 'X')
    .replace(/↑/g, '^')
    .replace(/[–—]/g, '-')
    .replace(/[’']/g, '')
    .toUpperCase();
}

function hexToRgb(hex) {
  const h = hex.replace('#', '');
  const v =
    h.length === 3
      ? h
          .split('')
          .map(c => c + c)
          .join('')
      : h;
  return [parseInt(v.slice(0, 2), 16), parseInt(v.slice(2, 4), 16), parseInt(v.slice(4, 6), 16)];
}

export class PngCanvas {
  /**
   * @param {number} width  logical width in px (matches SvgCanvas)
   * @param {number} height logical height in px
   * @param {object} [opts]
   * @param {number} [opts.ss=2]   supersample factor for anti-aliasing
   * @param {string} [opts.background='#ffffff']
   */
  constructor(width, height, { ss = 2, background = '#ffffff' } = {}) {
    this.w = width;
    this.h = height;
    this.ss = ss;
    this.dw = width * ss;
    this.dh = height * ss;
    this.buf = new Uint8Array(this.dw * this.dh * 4);
    const [r, g, b] = hexToRgb(background);
    for (let i = 0; i < this.dw * this.dh; i++) {
      this.buf[i * 4] = r;
      this.buf[i * 4 + 1] = g;
      this.buf[i * 4 + 2] = b;
      this.buf[i * 4 + 3] = 255;
    }
  }

  _blendDev(x, y, [r, g, b], a) {
    if (x < 0 || y < 0 || x >= this.dw || y >= this.dh) return;
    const i = (y * this.dw + x) * 4;
    if (a >= 1) {
      this.buf[i] = r;
      this.buf[i + 1] = g;
      this.buf[i + 2] = b;
      return;
    }
    this.buf[i] = Math.round(this.buf[i] * (1 - a) + r * a);
    this.buf[i + 1] = Math.round(this.buf[i + 1] * (1 - a) + g * a);
    this.buf[i + 2] = Math.round(this.buf[i + 2] * (1 - a) + b * a);
  }

  _fillRectDev(x, y, w, h, rgb, a) {
    const x0 = Math.round(x);
    const y0 = Math.round(y);
    const x1 = Math.round(x + w);
    const y1 = Math.round(y + h);
    for (let yy = y0; yy < y1; yy++) {
      for (let xx = x0; xx < x1; xx++) this._blendDev(xx, yy, rgb, a);
    }
  }

  // ── public API (logical coordinates) ──────────────────────────────────────
  rect(x, y, w, h, { fill, stroke, strokeWidth = 1, opacity = 1 } = {}) {
    const ss = this.ss;
    if (fill && fill !== 'none') this._fillRectDev(x * ss, y * ss, w * ss, h * ss, hexToRgb(fill), opacity);
    if (stroke && stroke !== 'none') {
      const t = Math.max(1, strokeWidth * ss);
      const rgb = hexToRgb(stroke);
      this._fillRectDev(x * ss, y * ss, w * ss, t, rgb, opacity); // top
      this._fillRectDev(x * ss, (y + h) * ss - t, w * ss, t, rgb, opacity); // bottom
      this._fillRectDev(x * ss, y * ss, t, h * ss, rgb, opacity); // left
      this._fillRectDev((x + w) * ss - t, y * ss, t, h * ss, rgb, opacity); // right
    }
  }

  line(x1, y1, x2, y2, { stroke = '#000000', width = 1, opacity = 1, dash } = {}) {
    const ss = this.ss;
    const rgb = hexToRgb(stroke);
    const t = Math.max(1, Math.round(width * ss));
    // Optional dash pattern (e.g. '6,4'), lengths in logical px scaled to device.
    // We toggle paint on/off as we step along the line so dashed lines (strict
    // series, target line) read the same in PNG as in SVG.
    const dashLens = dash
      ? String(dash)
          .split(',')
          .map(v => Math.max(1, Math.round(parseFloat(v) * ss)))
      : null;
    let dashOn = true;
    let dashSeg = 0;
    let dashLeft = dashLens ? dashLens[0] : Infinity;
    // Round endpoints to the device grid FIRST, then derive the Bresenham
    // deltas from those integers. Deriving dx/dy from the float coordinates
    // instead lets the error term disagree with the integer endpoints on
    // diagonal lines, so (x, y) oscillates around (xe, ye) and the loop never
    // terminates. Integer-only Bresenham is guaranteed to reach the endpoint.
    let x = Math.round(x1 * ss);
    let y = Math.round(y1 * ss);
    const xe = Math.round(x2 * ss);
    const ye = Math.round(y2 * ss);
    const dx = Math.abs(xe - x);
    const dy = Math.abs(ye - y);
    const sx = x < xe ? 1 : -1;
    const sy = y < ye ? 1 : -1;
    let err = dx - dy;
    const half = Math.floor(t / 2);
    for (;;) {
      if (dashOn) this._fillRectDev(x - half, y - half, t, t, rgb, opacity);
      if (x === xe && y === ye) break;
      const e2 = 2 * err;
      if (e2 > -dy) {
        err -= dy;
        x += sx;
      }
      if (e2 < dx) {
        err += dx;
        y += sy;
      }
      if (dashLens && --dashLeft <= 0) {
        dashOn = !dashOn;
        dashSeg = (dashSeg + 1) % dashLens.length;
        dashLeft = dashLens[dashSeg];
      }
    }
  }

  textWidth(str, size) {
    const scale = Math.max(1, Math.round((size * this.ss) / GLYPH_H));
    return (asciify(str).length * GLYPH_ADVANCE * scale) / this.ss;
  }

  /**
   * Draw text. (x, y) is the top-left of the text box; `size` is its height in
   * logical px. `anchor` is 'start' | 'middle' | 'end' (matches SVG text-anchor).
   */
  text(x, y, str, { fill = '#000000', size = 12, anchor = 'start', opacity = 1 } = {}) {
    const ss = this.ss;
    const s = asciify(str);
    const scale = Math.max(1, Math.round((size * ss) / GLYPH_H));
    const rgb = hexToRgb(fill);
    const widthDev = s.length * GLYPH_ADVANCE * scale;
    let dx = Math.round(x * ss);
    if (anchor === 'middle') dx -= Math.round(widthDev / 2);
    else if (anchor === 'end') dx -= widthDev;
    const dy = Math.round(y * ss);
    for (let ci = 0; ci < s.length; ci++) {
      const glyph = GLYPHS[s[ci]] || MISSING;
      for (let row = 0; row < GLYPH_H; row++) {
        const bits = glyph[row];
        for (let col = 0; col < GLYPH_W; col++) {
          if (bits[col] === '#') {
            this._fillRectDev(dx + (ci * GLYPH_ADVANCE + col) * scale, dy + row * scale, scale, scale, rgb, opacity);
          }
        }
      }
    }
  }

  // ── PNG encode ─────────────────────────────────────────────────────────────
  _downsample() {
    const { ss, w, h } = this;
    if (ss === 1) return this.buf;
    const out = new Uint8Array(w * h * 4);
    const n = ss * ss;
    for (let y = 0; y < h; y++) {
      for (let x = 0; x < w; x++) {
        let r = 0;
        let g = 0;
        let b = 0;
        for (let oy = 0; oy < ss; oy++) {
          for (let ox = 0; ox < ss; ox++) {
            const i = ((y * ss + oy) * this.dw + (x * ss + ox)) * 4;
            r += this.buf[i];
            g += this.buf[i + 1];
            b += this.buf[i + 2];
          }
        }
        const o = (y * w + x) * 4;
        out[o] = Math.round(r / n);
        out[o + 1] = Math.round(g / n);
        out[o + 2] = Math.round(b / n);
        out[o + 3] = 255;
      }
    }
    return out;
  }

  toBuffer() {
    const px = this._downsample();
    const { w, h } = this;
    // Raw image data: each scanline prefixed with a filter-type byte (0 = none).
    const raw = Buffer.alloc((w * 4 + 1) * h);
    for (let y = 0; y < h; y++) {
      const ro = y * (w * 4 + 1);
      raw[ro] = 0;
      raw.set(px.subarray(y * w * 4, y * w * 4 + w * 4), ro + 1);
    }
    const idat = zlib.deflateSync(raw, { level: 9 });

    const ihdr = Buffer.alloc(13);
    ihdr.writeUInt32BE(w, 0);
    ihdr.writeUInt32BE(h, 4);
    ihdr[8] = 8; // bit depth
    ihdr[9] = 6; // colour type: truecolour + alpha
    ihdr[10] = 0; // compression
    ihdr[11] = 0; // filter
    ihdr[12] = 0; // interlace

    const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
    return Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', idat), chunk('IEND', Buffer.alloc(0))]);
  }
}

// ── PNG chunk + CRC32 ────────────────────────────────────────────────────────
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const body = Buffer.concat([typeBuf, data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crc]);
}
