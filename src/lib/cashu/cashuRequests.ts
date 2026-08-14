import { getDecodedToken, PaymentRequest } from '@cashu/cashu-ts';
import type { Proof } from '@cashu/cashu-ts';

import { devLog } from './devLog';

/**
 * NUT-18 Cashu Payment Request payload delivered over a Nostr DM.
 *
 * The payload contains the mint URL and the proofs the sender is transferring.
 * It may be P2PK-locked to the recipient's Nostr or Nutzap pubkey.
 */
export interface CashuPaymentRequestPayload {
  id?: string;
  memo?: string;
  unit: string;
  mint: string;
  proofs: Proof[];
}

/**
 * Detect whether a string looks like an encoded Cashu token.
 *
 * Encoded tokens start with "cashuA" (v3) or "cashuB" (v4).
 */
export function isEncodedCashuToken(value: string): boolean {
  const trimmed = value.trim();
  return /^cashu[AB][A-Za-z0-9+/=]+$/.test(trimmed);
}

/**
 * Try to decode a string as a Cashu token.
 *
 * Returns the encoded token if it is valid, otherwise null.
 */
export function extractCashuToken(content: string): string | null {
  const trimmed = content.trim();
  if (!isEncodedCashuToken(trimmed)) return null;
  try {
    getDecodedToken(trimmed);
    return trimmed;
  } catch {
    return null;
  }
}

/**
 * Try to parse a NUT-18 PaymentRequest payload from DM content.
 *
 * The content may be either:
 *   - a raw JSON payload (`{ mint, proofs, ... }`)
 *   - an encoded `creqA`/`creq1` Payment Request string
 *
 * Returns the extracted payload, or null if the content is not a recognizable
 * Cashu request.
 */
export function parseCashuPaymentRequestPayload(
  content: string,
): CashuPaymentRequestPayload | null {
  const trimmed = content.trim();
  if (!trimmed) return null;

  // Try encoded NUT-18 Payment Request (creqA/creq1).
  if (/^creq[A-Za-z0-9+/=]+$/.test(trimmed)) {
    try {
      const pr = PaymentRequest.fromEncodedRequest(trimmed);
      const nostrTransport = pr.getTransport('nostr' as never);
      if (!nostrTransport) {
        devLog.warn('Received creq without nostr transport; ignoring.');
        return null;
      }
      // Encoded requests describe what the recipient should pay; they do not
      // contain proofs. For our flow we expect the sender to attach a raw
      // payload in the DM instead, so treat this as a request-only marker.
      return null;
    } catch {
      // Not a valid creq.
    }
  }

  // Try raw JSON payload.
  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (
      parsed &&
      typeof parsed === 'object' &&
      'mint' in parsed &&
      typeof (parsed as Record<string, unknown>).mint === 'string' &&
      'proofs' in parsed &&
      Array.isArray((parsed as Record<string, unknown>).proofs)
    ) {
      return parsed as CashuPaymentRequestPayload;
    }
  } catch {
    // Not JSON.
  }

  return null;
}

/**
 * Extract any Cashu value (token string or PaymentRequest payload) from DM content.
 *
 * Tokens take precedence because they are immediately redeemable. If no token is
 * found, falls back to a PaymentRequest payload.
 */
export function extractCashuValue(
  content: string,
): { type: 'token'; token: string } | { type: 'payload'; payload: CashuPaymentRequestPayload } | null {
  const token = extractCashuToken(content);
  if (token) return { type: 'token', token };

  const payload = parseCashuPaymentRequestPayload(content);
  if (payload) return { type: 'payload', payload };

  return null;
}
