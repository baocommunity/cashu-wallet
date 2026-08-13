import { describe, expect, it } from 'vitest';

import { allocateNut15Payment } from './nut15';

describe('allocateNut15Payment', () => {
  it('allocates an exact invoice total across supported mint balances', () => {
    const legs = allocateNut15Payment(100_000, [
      { mintUrl: 'https://b.example', balanceSats: 60 },
      { mintUrl: 'https://a.example', balanceSats: 60 },
    ]);
    expect(legs).toHaveLength(2);
    expect(legs.reduce((sum, leg) => sum + leg.amountMsats, 0)).toBe(100_000);
    expect(legs.every((leg) => leg.amountSats > 0 && leg.amountSats < leg.balanceSats)).toBe(true);
  });

  it('adds more legs when two fee-reserved capacities cannot cover the invoice', () => {
    const legs = allocateNut15Payment(120_000, [
      { mintUrl: 'https://a.example', balanceSats: 50 },
      { mintUrl: 'https://b.example', balanceSats: 50 },
      { mintUrl: 'https://c.example', balanceSats: 50 },
    ]);
    expect(legs).toHaveLength(3);
    expect(legs.reduce((sum, leg) => sum + leg.amountSats, 0)).toBe(120);
  });

  it('is deterministic and limits the number of correlated mint legs', () => {
    const candidates = Array.from({ length: 6 }, (_, index) => ({
      mintUrl: `https://${String.fromCharCode(102 - index)}.example`,
      balanceSats: 100,
    }));
    const first = allocateNut15Payment(250_000, candidates);
    const second = allocateNut15Payment(250_000, [...candidates].reverse());
    expect(first).toEqual(second);
    expect(first.length).toBeLessThanOrEqual(4);
  });

  it('rejects amountless, fractional-sat, and underfunded plans', () => {
    expect(() => allocateNut15Payment(0, [])).toThrow(/positive whole-sat/);
    expect(() => allocateNut15Payment(1_001, [])).toThrow(/positive whole-sat/);
    expect(() => allocateNut15Payment(100_000, [{ mintUrl: 'https://a.example', balanceSats: 200 }]))
      .toThrow(/two supported mints/);
    expect(() => allocateNut15Payment(100_000, [
      { mintUrl: 'https://a.example', balanceSats: 20 },
      { mintUrl: 'https://b.example', balanceSats: 20 },
    ])).toThrow(/insufficient/);
  });
});
