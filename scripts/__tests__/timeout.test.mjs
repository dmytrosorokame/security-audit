import { describe, it, expect } from 'vitest';
import { withTimeout } from '../providers/_common.mjs';

describe('withTimeout', () => {
  it('passes through the resolved value when fn finishes before timeout', async () => {
    const result = await withTimeout(async () => 'ok', 1000);
    expect(result).toBe('ok');
  });

  it('rejects with TimeoutError if fn does not resolve within timeoutMs', async () => {
    const slow = (signal) =>
      new Promise((resolve, reject) => {
        const t = setTimeout(() => resolve('too-late'), 5000);
        signal.addEventListener('abort', () => {
          clearTimeout(t);
          reject(new Error('aborted by signal'));
        });
      });
    await expect(withTimeout(slow, 50)).rejects.toMatchObject({
      name: 'TimeoutError',
      code: 'ETIMEDOUT',
    });
  });

  it('forwards an AbortSignal that fires on timeout', async () => {
    let observedAbort = false;
    const slow = (signal) =>
      new Promise((_, reject) => {
        signal.addEventListener('abort', () => {
          observedAbort = true;
          reject(new Error('aborted'));
        });
        setTimeout(() => reject(new Error('safety net never reached')), 2000);
      });
    await expect(withTimeout(slow, 30)).rejects.toThrow();
    expect(observedAbort).toBe(true);
  });

  it('does not wrap when timeoutMs is 0 (disabled)', async () => {
    // Even a slow operation should resolve when timeout is disabled.
    const result = await withTimeout(async () => {
      await new Promise(r => setTimeout(r, 30));
      return 'no-timeout';
    }, 0);
    expect(result).toBe('no-timeout');
  });

  it('does not wrap when timeoutMs is negative', async () => {
    const result = await withTimeout(async () => 'ok', -100);
    expect(result).toBe('ok');
  });

  it('propagates non-timeout errors verbatim', async () => {
    const fn = async () => { throw new Error('upstream API 503'); };
    await expect(withTimeout(fn, 1000)).rejects.toThrow('upstream API 503');
  });
});
