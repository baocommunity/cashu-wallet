// src/lib/cashu/escrowMultisig.ts
//
// The general ₿AO escrow primitive: 2-of-3 P2PK multisig locks (NUT-11).
//
// A deposit is locked to THREE keys — the two counterparties and an escrow
// operator — with `n_sigs = 2`. Spending requires any two of the three:
//
//   happy path  — winner + operator co-sign after the outcome is attested
//                 (the operator only ever SIGNS; it never holds the funds)
//   dispute     — operator + the honest party
//   abandonment — after `locktime`, each depositor's own `refund` key
//                 reclaims their own stake unilaterally (n_sigs_refund = 1)
//
// This is outcome-agnostic on purpose: pet battles are the cheapest testnet
// for the lock → signed outcome → verify → pay loop that ₿AO bounties need,
// but nothing here knows what a battle is. The operator's release endpoint
// takes an opaque "outcome proof" (for battles, a signed battle-finished
// event) and never learns what it attests to.
//
// TRUST MODEL (mirrored in the user-facing EscrowExplainer):
//   - The operator alone can do NOTHING — one key of three.
//   - The operator + one party can steal the pot — that collusion is the
//     residual trust assumption, mitigated by the operator's public identity
//     and (later) bonded/replicated operators.
//   - The mint remains the ecash custodian; multisig escrow removes OPERATOR
//     custody, not mint custody.
//   - Nobody can be rugged by abandonment: the refund path self-heals.

import { decodeCashuToken, normalizeMintUrl, type DecodedTokenEntry } from './cashu';

/** NUT-11 lock options accepted by cashu-ts `wallet.swap(amount, proofs, { p2pk })`. */
export interface MultisigP2pkOptions {
  pubkey: string[];
  locktime?: number;
  refundKeys?: string[];
  requiredSignatures?: number;
  requiredRefundSignatures?: number;
}

/**
 * How long after deposit creation the refund path activates (unix seconds).
 * Must comfortably exceed the longest expected outcome window: after the
 * locktime the LOSER can reclaim their own stake, so the operator refuses to
 * co-sign once the locktime is near (see OPERATOR_SIGN_MIN_LOCKTIME_MARGIN).
 * 24h is generous for battles (minutes) and still reasonable for bounties.
 */
export const MULTISIG_REFUND_PERIOD_SECONDS = 24 * 60 * 60;

/**
 * The operator must not co-sign a release when the refund locktime is this
 * close (or passed): past the locktime the mint honors the depositor's refund
 * key instead, so a late operator signature would race the depositors'
 * self-recovery and could double-pay.
 */
export const OPERATOR_SIGN_MIN_LOCKTIME_MARGIN_SECONDS = 60 * 60;

/** Signatures required to spend a multisig escrow deposit pre-locktime. */
export const MULTISIG_REQUIRED_SIGNATURES = 2;

/** Normalize a secp256k1 pubkey to lowercase x-only (64-hex). Null if invalid. */
export function normalizeMultisigPubkey(pubkey: string | null | undefined): string | null {
  if (typeof pubkey !== 'string') return null;
  const lower = pubkey.toLowerCase();
  if (/^[0-9a-f]{64}$/.test(lower)) return lower;
  if (/^0[23][0-9a-f]{64}$/.test(lower)) return lower.slice(2);
  return null;
}

/** x-only → 33-byte compressed form ('02'-prefixed) for NUT-11 secret fields. */
function toCompressed(xonly: string): string {
  return '02' + xonly;
}

export interface MultisigEscrowLockRequest {
  /** Counterparty A's P2PK pubkey (any hex form). */
  partyAPubkey: string;
  /** Counterparty B's P2PK pubkey (any hex form). */
  partyBPubkey: string;
  /** Escrow operator's P2PK pubkey (any hex form). */
  operatorPubkey: string;
  /**
   * The DEPOSITOR's own pubkey — sole refund signer after the locktime.
   * Must be one of the two parties (a third refund key would let a stranger
   * reclaim the stake).
   */
  refundPubkey: string;
  /** Unix seconds when the refund path activates. */
  locktime: number;
}

/**
 * Build the cashu-ts `p2pk` swap options for a 2-of-3 escrow lock.
 *
 * Keys are sorted (x-only) before being compressed so both clients construct
 * byte-identical secrets for the same battle — validation compares key SETS,
 * but determinism keeps debugging and mint logs sane.
 *
 * Throws when any key is invalid, the refund key is not a party, the parties
 * are not distinct, or the locktime is not a safe future timestamp.
 */
export function buildMultisigEscrowLock(req: MultisigEscrowLockRequest): MultisigP2pkOptions {
  const a = normalizeMultisigPubkey(req.partyAPubkey);
  const b = normalizeMultisigPubkey(req.partyBPubkey);
  const op = normalizeMultisigPubkey(req.operatorPubkey);
  const refund = normalizeMultisigPubkey(req.refundPubkey);
  if (!a || !b || !op || !refund) {
    throw new Error('Invalid escrow pubkey');
  }
  if (new Set([a, b, op]).size !== 3) {
    throw new Error('Escrow parties and operator must be three distinct keys');
  }
  if (refund !== a && refund !== b) {
    throw new Error('Refund key must be one of the two escrow parties');
  }
  if (!Number.isSafeInteger(req.locktime) || req.locktime <= 0) {
    throw new Error('Invalid escrow refund locktime');
  }
  const sorted = [a, b, op].sort();
  return {
    pubkey: sorted.map(toCompressed),
    requiredSignatures: MULTISIG_REQUIRED_SIGNATURES,
    locktime: req.locktime,
    refundKeys: [toCompressed(refund)],
  };
}

export interface ParsedMultisigLock {
  /** The three authorized spending keys, x-only, sorted. */
  lockKeys: string[];
  /** n_sigs (defaults to 1 when the tag is absent). */
  requiredSignatures: number;
  /** Unix seconds, undefined when no locktime tag. */
  locktime?: number;
  /** Refund keys (x-only), empty when no refund tag. */
  refundKeys: string[];
  /** n_sigs_refund (defaults to 1 when the tag is absent). */
  requiredRefundSignatures: number;
}

/**
 * Parse a NUT-11 P2PK proof secret into the multisig shape, or return null
 * when the secret is not a well-formed P2PK secret. Unknown tags are
 * tolerated here (validation decides what is acceptable).
 */
export function parseMultisigLockSecret(secret: unknown): ParsedMultisigLock | null {
  if (typeof secret !== 'string') return null;
  try {
    const parsed = JSON.parse(secret);
    if (!Array.isArray(parsed) || parsed.length < 2 || parsed[0] !== 'P2PK') return null;
    const body: unknown = parsed[1];
    let dataKey: string | null = null;
    let rawTags: unknown[] = [];
    if (typeof body === 'string') {
      // Legacy form: ["P2PK", <pubkey>, ...tags]
      dataKey = body;
      rawTags = parsed.slice(2);
    } else if (body && typeof body === 'object' && !Array.isArray(body)) {
      const obj = body as Record<string, unknown>;
      if (typeof obj.data !== 'string') return null;
      dataKey = obj.data;
      if (obj.tags !== undefined && !Array.isArray(obj.tags)) return null;
      rawTags = (obj.tags as unknown[]) ?? [];
    } else {
      return null;
    }

    const data = normalizeMultisigPubkey(dataKey);
    if (!data) return null;

    let pubkeysTag: string[] = [];
    let refundTag: string[] = [];
    let locktime: number | undefined;
    let requiredSignatures = 1;
    let requiredRefundSignatures = 1;
    for (const tag of rawTags) {
      if (!Array.isArray(tag) || tag.length === 0 || typeof tag[0] !== 'string') return null;
      const [, ...values] = tag as [string, ...unknown[]];
      switch (tag[0]) {
        case 'pubkeys':
          pubkeysTag = values.map((v) => normalizeMultisigPubkey(typeof v === 'string' ? v : null) ?? '');
          if (pubkeysTag.some((k) => !k)) return null;
          break;
        case 'refund':
          refundTag = values.map((v) => normalizeMultisigPubkey(typeof v === 'string' ? v : null) ?? '');
          if (refundTag.some((k) => !k)) return null;
          break;
        case 'locktime': {
          const value = Number(values[0]);
          if (!Number.isSafeInteger(value) || value <= 0) return null;
          locktime = value;
          break;
        }
        case 'n_sigs': {
          const value = Number(values[0]);
          if (!Number.isSafeInteger(value) || value < 1) return null;
          requiredSignatures = value;
          break;
        }
        case 'n_sigs_refund': {
          const value = Number(values[0]);
          if (!Number.isSafeInteger(value) || value < 1) return null;
          requiredRefundSignatures = value;
          break;
        }
        default:
          // Unknown tag — tolerated at parse level, rejected by validation.
          break;
      }
    }

    const lockKeys = [data, ...pubkeysTag].sort();
    return { lockKeys, requiredSignatures, locktime, refundKeys: refundTag, requiredRefundSignatures };
  } catch {
    return null;
  }
}

/**
 * Decode a token via the app's defensive decoder (length cap, cashu:// prefix
 * stripping, mint-URL allowlist, per-proof shape validation). Returns null for
 * anything malformed — multisig validation treats that as an invalid deposit.
 */
function decodeTokenEntries(tokenStr: string): DecodedTokenEntry[] | null {
  const entries = decodeCashuToken(tokenStr);
  return entries && entries.length > 0 ? entries : null;
}

/**
 * Normalize mint URLs for comparison via the shared helper — origin is
 * lowercased but the PATH keeps its case, because mint paths are
 * case-sensitive (the default Minibits mint's `/Bitcoin` 404s as `/bitcoin`).
 */
function normalizeMintUrlLite(url: string): string {
  return normalizeMintUrl(url) ?? url.trim().replace(/\/+$/, '');
}

export interface MultisigDepositExpectation {
  expectedAmount: number;
  partyAPubkey: string;
  partyBPubkey: string;
  operatorPubkey: string;
  /** Whose deposit this is — must equal the refund key on every proof. */
  depositorPubkey: string;
  /** Every proof's locktime must be at least this unix-seconds value. */
  minLocktime: number;
  /** When provided and non-empty, every entry must come from one of these mints. */
  allowedMints?: string[];
}

export interface MultisigDepositValidation {
  valid: boolean;
  reason?: string;
  amount: number;
}

/**
 * Validate that a deposit token is EXACTLY the agreed 2-of-3 escrow lock:
 * every proof locked to {partyA, partyB, operator} with n_sigs = 2, the
 * depositor's own key as the sole refund signer, a locktime at least
 * `minLocktime`, the expected amount, and an allowed mint.
 *
 * Strictness here is what makes the co-sign release safe: the operator signs
 * only deposits whose shape guarantees neither it nor anyone can spend alone.
 */
export function validateMultisigEscrowDeposit(
  tokenStr: string,
  expectation: MultisigDepositExpectation,
): MultisigDepositValidation {
  const fail = (reason: string, amount = 0): MultisigDepositValidation => ({ valid: false, reason, amount });

  const entries = decodeTokenEntries(tokenStr);
  if (!entries) return fail('Token is empty or invalid');
  const amount = entries.reduce((sum, e) => sum + e.amount, 0);
  if (amount <= 0) return fail('Token is empty or invalid');
  if (amount !== expectation.expectedAmount) {
    return fail(`Token amount ${amount} does not match expected ${expectation.expectedAmount}`, amount);
  }

  const a = normalizeMultisigPubkey(expectation.partyAPubkey);
  const b = normalizeMultisigPubkey(expectation.partyBPubkey);
  const op = normalizeMultisigPubkey(expectation.operatorPubkey);
  const depositor = normalizeMultisigPubkey(expectation.depositorPubkey);
  if (!a || !b || !op || !depositor) return fail('Escrow pubkeys are not configured', amount);
  const expectedSet = [a, b, op].sort().join(',');

  if (expectation.allowedMints && expectation.allowedMints.length > 0) {
    const allowed = new Set(expectation.allowedMints.map(normalizeMintUrlLite));
    for (const entry of entries) {
      if (!allowed.has(normalizeMintUrlLite(entry.mintUrl))) {
        return fail(`Token mint ${entry.mintUrl} is not the agreed escrow mint`, amount);
      }
    }
  }

  for (const entry of entries) {
    for (const proof of entry.proofs) {
      const lock = parseMultisigLockSecret((proof as { secret?: unknown }).secret);
      if (!lock) return fail('Deposit proof is not a multisig P2PK lock', amount);
      if (lock.lockKeys.length !== 3 || lock.lockKeys.join(',') !== expectedSet) {
        return fail('Deposit is not locked to the two players and the escrow operator', amount);
      }
      if (lock.requiredSignatures !== MULTISIG_REQUIRED_SIGNATURES) {
        return fail('Deposit does not require two-of-three signatures', amount);
      }
      if (lock.refundKeys.length !== 1 || lock.refundKeys[0] !== depositor) {
        return fail('Deposit refund key is not the depositor — the stake could be reclaimed by someone else', amount);
      }
      if (lock.locktime === undefined || lock.locktime < expectation.minLocktime) {
        return fail('Deposit refund locktime is missing or too soon', amount);
      }
    }
  }
  return { valid: true, amount };
}

/**
 * The soonest refund locktime across all proofs in a multisig deposit token,
 * or null when any proof is missing a locktime (or the token doesn't parse).
 * Drives the "reclaim stake" UI.
 */
export function getMultisigDepositLocktime(tokenStr: string): number | null {
  const entries = decodeTokenEntries(tokenStr);
  if (!entries) return null;
  let soonest: number | null = null;
  for (const entry of entries) {
    for (const proof of entry.proofs) {
      const lock = parseMultisigLockSecret((proof as { secret?: unknown }).secret);
      if (!lock || lock.locktime === undefined) return null;
      soonest = soonest === null ? lock.locktime : Math.min(soonest, lock.locktime);
    }
  }
  return soonest;
}
