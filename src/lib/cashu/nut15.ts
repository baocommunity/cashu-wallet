export interface Nut15MintCapacity {
  mintUrl: string;
  balanceSats: number;
}

export interface Nut15Allocation {
  mintUrl: string;
  amountSats: number;
  amountMsats: number;
  balanceSats: number;
}

export interface Nut15PreparedLeg extends Nut15Allocation {
  quote: {
    quote: string;
    amount: number;
    fee_reserve: number;
    state?: string;
    expiry?: number;
    request?: string;
    unit?: string;
  };
}

export interface Nut15PaymentPlan {
  id: string;
  invoice: string;
  amountSats: number;
  totalFeeReserveSats: number;
  createdAt: number;
  legs: Nut15PreparedLeg[];
}

/** Maximum number of simultaneous mint legs exposed by the wallet. */
export const MAX_NUT15_LEGS = 4;

/**
 * Deterministically allocate one whole-sat BOLT11 amount across at least two
 * NUT-15 mints. Five percent is retained at each mint for its melt fee reserve;
 * the real quotes are checked before the user can confirm.
 */
export function allocateNut15Payment(
  invoiceAmountMsats: number,
  candidates: readonly Nut15MintCapacity[],
  feeReservePpm = 50_000,
): Nut15Allocation[] {
  if (!Number.isSafeInteger(invoiceAmountMsats) || invoiceAmountMsats <= 0 || invoiceAmountMsats % 1000 !== 0) {
    throw new Error('NUT-15 requires a positive whole-sat BOLT11 amount');
  }
  if (!Number.isSafeInteger(feeReservePpm) || feeReservePpm < 0 || feeReservePpm > 1_000_000) {
    throw new Error('Invalid NUT-15 fee reserve');
  }

  const usable = candidates
    .filter((candidate) => Number.isSafeInteger(candidate.balanceSats) && candidate.balanceSats > 1)
    .map((candidate) => ({
      ...candidate,
      capacity: Math.floor(candidate.balanceSats * 1_000_000 / (1_000_000 + feeReservePpm)),
    }))
    .filter((candidate) => candidate.capacity > 0)
    .sort((a, b) => b.capacity - a.capacity || a.mintUrl.localeCompare(b.mintUrl))
    .slice(0, MAX_NUT15_LEGS);

  const amountSats = invoiceAmountMsats / 1000;
  if (usable.length < 2) throw new Error('NUT-15 requires balances at two supported mints');

  let count = 2;
  while (count < usable.length && usable.slice(0, count).reduce((sum, item) => sum + item.capacity, 0) < amountSats) {
    count++;
  }
  const selected = usable.slice(0, count);
  if (selected.reduce((sum, item) => sum + item.capacity, 0) < amountSats) {
    throw new Error('Combined NUT-15 mint balances are insufficient after fee reserves');
  }

  let remaining = amountSats;
  return selected.map((candidate, index) => {
    const laterLegs = selected.length - index - 1;
    const amount = index === selected.length - 1
      ? remaining
      : Math.min(candidate.capacity, remaining - laterLegs);
    if (!Number.isSafeInteger(amount) || amount <= 0) {
      throw new Error('Unable to allocate a positive amount to every NUT-15 leg');
    }
    remaining -= amount;
    return {
      mintUrl: candidate.mintUrl,
      amountSats: amount,
      amountMsats: amount * 1000,
      balanceSats: candidate.balanceSats,
    };
  });
}
