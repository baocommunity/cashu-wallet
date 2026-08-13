import { devLog } from '@/lib/cashu/devLog';

export interface BaoFaucetRequest {
  /** User npub to associate with the faucet grant. */
  npub: string;
  /** Amount in signet/demo sats. */
  amount: number;
}

export interface BaoFaucetResponse {
  /** Cashu token string that can be received by the wallet. */
  token?: string;
  /** Human-readable status message from the faucet. */
  message?: string;
  /** Remaining sats the caller can claim in the current 24h rolling window. */
  remaining24h?: number;
  /** Unix timestamp (seconds) when the 24h rolling window resets. */
  resetsAt?: number;
}

/** Maximum sats a client should ask the BAO faucet for in a single claim.
 * The faucet enforces its own 24h rolling cap; this constant keeps individual
 * requests small and well-behaved. */
export const BAO_FAUCET_DAILY_MAX_SATS = 10_000;

/** Clamp a requested BAO faucet amount to a sensible per-claim ceiling and to
 * the remaining 24h allowance reported by the faucet. */
export function clampBaoFaucetAmount(requested: number, remaining24h?: number): number {
  const positive = Math.max(0, Math.floor(requested));
  const clamped = Math.min(positive, BAO_FAUCET_DAILY_MAX_SATS);
  if (remaining24h === undefined) return clamped;
  return Math.min(clamped, Math.max(0, Math.floor(remaining24h)));
}

/** True if the faucet reports no remaining daily allowance. */
export function isBaoFaucetDailyExhausted(res: BaoFaucetResponse | null): boolean {
  return res?.remaining24h !== undefined && res.remaining24h <= 0;
}

/**
 * Claim signet/demo sats from the BAO faucet.
 *
 * The expected contract is a POST to the faucet URL with a JSON body
 * `{ npub, amount }` and a JSON response `{ token?: string, message?: string }`.
 * The returned Cashu token is then redeemed by the wallet.
 */
export async function claimBaoSignetFaucet(
  endpoint: string,
  request: BaoFaucetRequest,
): Promise<BaoFaucetResponse | null> {
  const url = endpoint.trim();
  if (!url) {
    devLog.warn('BAO faucet URL is not configured');
    return null;
  }
  if (!request.npub || !request.amount || request.amount <= 0) {
    devLog.warn('Invalid BAO faucet request:', request);
    return null;
  }

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
    if (!response.ok) {
      const text = await response.text().catch(() => 'unknown error');
      devLog.warn('BAO faucet returned error:', response.status, text);
      return {
        message: `₿AO faucet error ${response.status}: ${text}`,
      };
    }
    const json = (await response.json()) as unknown;
    if (!json || typeof json !== 'object') return { message: '₿AO faucet returned an empty response.' };
    const obj = json as Record<string, unknown>;
    const { token, message, remaining24h, resetsAt } = obj;
    return {
      token: typeof token === 'string' ? token : undefined,
      message: typeof message === 'string' ? message : undefined,
      remaining24h: typeof remaining24h === 'number' ? remaining24h : undefined,
      resetsAt: typeof resetsAt === 'number' ? resetsAt : undefined,
    };
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    devLog.error('BAO faucet request failed:', e);
    return { message: `₿AO faucet request failed: ${message}` };
  }
}
