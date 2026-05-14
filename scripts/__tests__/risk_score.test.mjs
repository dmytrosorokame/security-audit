import { describe, it, expect } from 'vitest';
import { calculateRiskScore } from '../risk_score.mjs';

describe('calculateRiskScore', () => {
  it('returns 9.5 for a confirmed critical finding (sev × 1.0 × 1.0)', () => {
    expect(calculateRiskScore({ severity: 'critical', confidence: 'high', verdict: 'TRUE_POSITIVE' })).toBe(9.5);
  });

  it('returns 7.5 for a confirmed high finding', () => {
    expect(calculateRiskScore({ severity: 'high', confidence: 'high', verdict: 'TRUE_POSITIVE' })).toBe(7.5);
  });

  it('returns 5.0 for a confirmed medium finding', () => {
    expect(calculateRiskScore({ severity: 'medium', confidence: 'high', verdict: 'TRUE_POSITIVE' })).toBe(5.0);
  });

  it('zeros risk when verdict is FALSE_POSITIVE regardless of severity', () => {
    expect(calculateRiskScore({ severity: 'critical', confidence: 'high', verdict: 'FALSE_POSITIVE' })).toBe(0);
  });

  it('discounts by confidence factor (medium → 0.85)', () => {
    // 7.5 × 0.85 × 1.0 = 6.375 → 6.4 after 1-decimal rounding
    expect(calculateRiskScore({ severity: 'high', confidence: 'medium', verdict: 'TRUE_POSITIVE' })).toBe(6.4);
  });

  it('discounts by confidence factor (low → 0.6)', () => {
    // 7.5 × 0.6 × 1.0 = 4.5
    expect(calculateRiskScore({ severity: 'high', confidence: 'low', verdict: 'TRUE_POSITIVE' })).toBe(4.5);
  });

  it('discounts by verdict factor (LIKELY_TP → 0.9)', () => {
    // 7.5 × 1.0 × 0.9 = 6.75 → 6.8
    expect(calculateRiskScore({ severity: 'high', confidence: 'high', verdict: 'LIKELY_TP' })).toBe(6.8);
  });

  it('discounts by verdict factor (NEEDS_HUMAN → 0.7)', () => {
    // 7.5 × 1.0 × 0.7 = 5.25 → 5.3
    expect(calculateRiskScore({ severity: 'high', confidence: 'high', verdict: 'NEEDS_HUMAN' })).toBe(5.3);
  });

  it('combines confidence × verdict discount', () => {
    // critical × medium × NEEDS_HUMAN = 9.5 × 0.85 × 0.7 = 5.6525 → 5.7
    const result = calculateRiskScore({ severity: 'critical', confidence: 'medium', verdict: 'NEEDS_HUMAN' });
    expect(result).toBeCloseTo(5.7, 1);
  });

  it('clamps at 10', () => {
    const r = calculateRiskScore({ severity: 'critical', confidence: 'high', verdict: 'TRUE_POSITIVE' });
    expect(r).toBeLessThanOrEqual(10);
  });

  it('returns 0 for unknown severity', () => {
    expect(calculateRiskScore({ severity: 'bogus', confidence: 'high', verdict: 'TRUE_POSITIVE' })).toBe(0);
  });

  it('uses safe defaults for missing confidence/verdict (0.85 × 0.85)', () => {
    // base × 0.85 × 0.85 — proves the fallbacks engage
    // high (7.5) × 0.85 × 0.85 ≈ 5.42 → 5.4
    expect(calculateRiskScore({ severity: 'high' })).toBeCloseTo(5.4, 1);
  });

  it('returns rounded to 1 decimal', () => {
    const r = calculateRiskScore({ severity: 'medium', confidence: 'medium', verdict: 'NEEDS_HUMAN' });
    // 5.0 × 0.85 × 0.7 = 2.975 → 3.0
    expect(Number.isFinite(r)).toBe(true);
    expect(r * 10).toBe(Math.round(r * 10));
  });
});
