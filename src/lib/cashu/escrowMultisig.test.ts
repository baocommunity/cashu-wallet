// Tests for the 2-of-3 multisig escrow primitive (₿AO escrow, NUT-11).
import { describe, expect, it } from 'vitest';
import { getEncodedToken } from '@cashu/cashu-ts';
import { signP2PKProofs, verifyP2PKSecretSignature } from '@cashu/cashu-ts/crypto/client/NUT11';
import { bytesToHex, hexToBytes } from '@noble/curves/utils.js';
import { schnorr } from '@noble/curves/secp256k1.js';

import {
  buildMultisigEscrowLock,
  getMultisigDepositLocktime,
  MULTISIG_REQUIRED_SIGNATURES,
  normalizeMultisigPubkey,
  parseMultisigLockSecret,
  validateMultisigEscrowDeposit,
  type MultisigDepositExpectation,
} from './escrowMultisig';

const mintUrl = 'https://mint.example.com';

// Deterministic test keys (never used anywhere else).
const PARTY_A_PRIV = bytesToHex(Uint8Array.from({ length: 32 }, () => 1));
const PARTY_B_PRIV = bytesToHex(Uint8Array.from({ length: 32 }, () => 2));
const OPERATOR_PRIV = bytesToHex(Uint8Array.from({ length: 32 }, () => 3));
const STRANGER_PRIV = bytesToHex(Uint8Array.from({ length: 32 }, () => 4));

const xonly = (priv: string) => bytesToHex(schnorr.getPublicKey(hexToBytes(priv)));
const PARTY_A = xonly(PARTY_A_PRIV);
const PARTY_B = xonly(PARTY_B_PRIV);
const OPERATOR = xonly(OPERATOR_PRIV);
const STRANGER = xonly(STRANGER_PRIV);

const LOCKTIME = Math.floor(Date.now() / 1000) + 24 * 3600;

/** The compressed key list buildMultisigEscrowLock should produce (sorted x-only, 02-prefixed). */
const sortedCompressed = [PARTY_A, PARTY_B, OPERATOR].sort().map((k) => '02' + k);

function makeToken(proofs: Array<{ amount: number; secret: string }>, mint = mintUrl) {
  return getEncodedToken({
    mint,
    proofs: proofs.map((p, i) => ({
      id: '00ad268c6d1f09e6',
      amount: p.amount,
      secret: p.secret,
      C: '02' + String(i + 1).padStart(2, '0').repeat(32),
    })),
    unit: 'sat',
  });
}

/** The exact secret JSON a mint-side swap would store for the 2-of-3 lock. */
function multisigSecret(overrides?: {
  keys?: string[];
  nSigs?: number;
  refund?: string[];
  locktime?: number;
  extraTags?: unknown[];
}): string {
  const keys = overrides?.keys ?? sortedCompressed;
  const tags: unknown[] = [
    ['pubkeys', ...keys.slice(1)],
    ['n_sigs', String(overrides?.nSigs ?? 2)],
    ['refund', ...(overrides?.refund ?? ['02' + PARTY_A])],
    ['locktime', String(overrides?.locktime ?? LOCKTIME)],
    ...(overrides?.extraTags ?? []),
  ];
  return JSON.stringify(['P2PK', { nonce: 'a'.repeat(64), data: keys[0], tags }]);
}

function validExpectation(overrides?: Partial<MultisigDepositExpectation>): MultisigDepositExpectation {
  return {
    expectedAmount: 21,
    partyAPubkey: PARTY_A,
    partyBPubkey: PARTY_B,
    operatorPubkey: OPERATOR,
    depositorPubkey: PARTY_A,
    minLocktime: LOCKTIME - 3600,
    allowedMints: [mintUrl],
    ...overrides,
  };
}

describe('normalizeMultisigPubkey', () => {
  it('accepts x-only and compressed forms, rejects garbage', () => {
    expect(normalizeMultisigPubkey(PARTY_A)).toBe(PARTY_A);
    expect(normalizeMultisigPubkey('02' + PARTY_A)).toBe(PARTY_A);
    expect(normalizeMultisigPubkey('03' + PARTY_A)).toBe(PARTY_A);
    expect(normalizeMultisigPubkey(('02' + PARTY_A).toUpperCase())).toBe(PARTY_A);
    expect(normalizeMultisigPubkey('04' + PARTY_A)).toBeNull();
    expect(normalizeMultisigPubkey('xyz')).toBeNull();
    expect(normalizeMultisigPubkey(null)).toBeNull();
  });
});

describe('buildMultisigEscrowLock', () => {
  it('produces the sorted 2-of-3 lock with refund and locktime', () => {
    const lock = buildMultisigEscrowLock({
      partyAPubkey: PARTY_A,
      partyBPubkey: '03' + PARTY_B, // compressed input form accepted
      operatorPubkey: OPERATOR,
      refundPubkey: PARTY_A,
      locktime: LOCKTIME,
    });
    expect(lock.pubkey).toEqual(sortedCompressed);
    expect(lock.requiredSignatures).toBe(MULTISIG_REQUIRED_SIGNATURES);
    expect(lock.locktime).toBe(LOCKTIME);
    expect(lock.refundKeys).toEqual(['02' + PARTY_A]);
  });

  it('rejects invalid keys, duplicate parties, foreign refund keys, bad locktimes', () => {
    const base = {
      partyAPubkey: PARTY_A,
      partyBPubkey: PARTY_B,
      operatorPubkey: OPERATOR,
      refundPubkey: PARTY_A,
      locktime: LOCKTIME,
    };
    expect(() => buildMultisigEscrowLock({ ...base, partyAPubkey: 'nope' })).toThrow('Invalid escrow pubkey');
    expect(() => buildMultisigEscrowLock({ ...base, partyBPubkey: PARTY_A })).toThrow('distinct');
    expect(() => buildMultisigEscrowLock({ ...base, operatorPubkey: PARTY_A })).toThrow('distinct');
    expect(() => buildMultisigEscrowLock({ ...base, refundPubkey: STRANGER })).toThrow('one of the two escrow parties');
    expect(() => buildMultisigEscrowLock({ ...base, locktime: -5 })).toThrow('locktime');
    expect(() => buildMultisigEscrowLock({ ...base, locktime: 1.5 })).toThrow('locktime');
  });
});

describe('parseMultisigLockSecret', () => {
  it('parses the real NUT-11 object form', () => {
    const lock = parseMultisigLockSecret(multisigSecret());
    expect(lock).not.toBeNull();
    expect(lock!.lockKeys).toEqual([PARTY_A, PARTY_B, OPERATOR].sort());
    expect(lock!.requiredSignatures).toBe(2);
    expect(lock!.locktime).toBe(LOCKTIME);
    expect(lock!.refundKeys).toEqual([PARTY_A]);
    expect(lock!.requiredRefundSignatures).toBe(1);
  });

  it('parses the legacy string form', () => {
    const legacy = JSON.stringify([
      'P2PK',
      '02' + PARTY_A,
      ['pubkeys', '02' + PARTY_B, '02' + OPERATOR],
      ['n_sigs', '2'],
    ]);
    const lock = parseMultisigLockSecret(legacy);
    expect(lock!.lockKeys).toEqual([PARTY_A, PARTY_B, OPERATOR].sort());
    expect(lock!.requiredSignatures).toBe(2);
  });

  it('returns null for non-P2PK and malformed secrets', () => {
    expect(parseMultisigLockSecret('not json')).toBeNull();
    expect(parseMultisigLockSecret('{"pubkey":"x"}')).toBeNull();
    expect(parseMultisigLockSecret(JSON.stringify(['HTLC', { data: 'x' }]))).toBeNull();
    expect(parseMultisigLockSecret(JSON.stringify(['P2PK', { data: 'zz' }]))).toBeNull();
    expect(parseMultisigLockSecret(42)).toBeNull();
  });
});

describe('validateMultisigEscrowDeposit', () => {
  it('accepts a well-formed deposit', () => {
    const token = makeToken([
      { amount: 13, secret: multisigSecret() },
      { amount: 8, secret: multisigSecret() },
    ]);
    const result = validateMultisigEscrowDeposit(token, validExpectation());
    expect(result).toEqual({ valid: true, amount: 21 });
  });

  it('rejects wrong amounts', () => {
    const token = makeToken([{ amount: 20, secret: multisigSecret() }]);
    const result = validateMultisigEscrowDeposit(token, validExpectation());
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/amount 20/);
  });

  it('rejects a single-key (legacy custodial) lock', () => {
    const legacySecret = JSON.stringify(['P2PK', { nonce: 'a'.repeat(64), data: '02' + OPERATOR, tags: [] }]);
    const token = makeToken([{ amount: 21, secret: legacySecret }]);
    const result = validateMultisigEscrowDeposit(token, validExpectation());
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/two players and the escrow operator/);
  });

  it('rejects a swapped-in stranger key', () => {
    const keys = [PARTY_A, PARTY_B, STRANGER].sort().map((k) => '02' + k);
    const token = makeToken([{ amount: 21, secret: multisigSecret({ keys }) }]);
    const result = validateMultisigEscrowDeposit(token, validExpectation());
    expect(result.valid).toBe(false);
  });

  it('rejects n_sigs = 1 (unilateral operator release)', () => {
    const token = makeToken([{ amount: 21, secret: multisigSecret({ nSigs: 1 }) }]);
    const result = validateMultisigEscrowDeposit(token, validExpectation());
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/two-of-three/);
  });

  it('rejects a refund key that is not the depositor', () => {
    const token = makeToken([{ amount: 21, secret: multisigSecret({ refund: ['02' + PARTY_B] }) }]);
    const result = validateMultisigEscrowDeposit(token, validExpectation());
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/refund key is not the depositor/);
  });

  it('rejects a missing or too-soon locktime', () => {
    const noLocktime = JSON.stringify([
      'P2PK',
      {
        nonce: 'a'.repeat(64),
        data: sortedCompressed[0],
        tags: [
          ['pubkeys', ...sortedCompressed.slice(1)],
          ['n_sigs', '2'],
          ['refund', '02' + PARTY_A],
        ],
      },
    ]);
    expect(validateMultisigEscrowDeposit(makeToken([{ amount: 21, secret: noLocktime }]), validExpectation()).reason)
      .toMatch(/locktime/);

    const soon = makeToken([{ amount: 21, secret: multisigSecret({ locktime: LOCKTIME - 7200 }) }]);
    expect(validateMultisigEscrowDeposit(soon, validExpectation()).reason).toMatch(/locktime/);
  });

  it('rejects a disallowed mint', () => {
    const token = makeToken([{ amount: 21, secret: multisigSecret() }], 'https://other.mint.example.com');
    const result = validateMultisigEscrowDeposit(token, validExpectation());
    expect(result.valid).toBe(false);
    expect(result.reason).toMatch(/agreed escrow mint/);
  });

  it('rejects empty and malformed tokens', () => {
    expect(validateMultisigEscrowDeposit('garbage', validExpectation()).valid).toBe(false);
    expect(validateMultisigEscrowDeposit('', validExpectation()).valid).toBe(false);
  });
});

describe('getMultisigDepositLocktime', () => {
  it('returns the soonest locktime across proofs', () => {
    const token = makeToken([
      { amount: 13, secret: multisigSecret({ locktime: LOCKTIME + 500 }) },
      { amount: 8, secret: multisigSecret() },
    ]);
    expect(getMultisigDepositLocktime(token)).toBe(LOCKTIME);
  });

  it('returns null when any proof lacks a locktime or the token is invalid', () => {
    const bearer = makeToken([{ amount: 21, secret: 'plain-secret' }]);
    expect(getMultisigDepositLocktime(bearer)).toBeNull();
    expect(getMultisigDepositLocktime('garbage')).toBeNull();
  });
});

describe('two-of-three witness assembly (operator co-sign + winner receive)', () => {
  /**
   * The release flow in miniature, with real schnorr signatures and no mint:
   * the operator signs each deposit proof (1st sig), then the winner's wallet
   * signs the same proofs at receive time (2nd sig). Both signatures must
   * verify against the secret, and neither party may sign twice.
   */
  it('operator + winner produce two distinct valid signatures', () => {
    const proof = {
      id: '00ad268c6d1f09e6',
      amount: 21,
      secret: multisigSecret(),
      C: '02' + '22'.repeat(32),
    };

    const [operatorSigned] = signP2PKProofs([proof], OPERATOR_PRIV, true);
    expect(operatorSigned.witness).toEqual(
      expect.objectContaining({ signatures: [expect.any(String)] }),
    );

    const [fullySigned] = signP2PKProofs([operatorSigned], PARTY_A_PRIV, true);
    const sigs = (fullySigned.witness as { signatures: string[] }).signatures;
    expect(sigs).toHaveLength(2);
    expect(new Set(sigs).size).toBe(2);

    // Both signatures verify against the secret for their respective keys.
    expect(verifyP2PKSecretSignature(sigs[0], proof.secret, OPERATOR)).toBe(true);
    expect(verifyP2PKSecretSignature(sigs[1], proof.secret, PARTY_A)).toBe(true);
  });

  it('refuses a signature from a key outside the lock', () => {
    const proof = { id: 'x', amount: 21, secret: multisigSecret(), C: '02' + '22'.repeat(32) };
    expect(() => signP2PKProofs([proof], STRANGER_PRIV, true)).toThrow(/Signature not required/);
  });

  it('refuses a second signature from the same key', () => {
    const proof = { id: 'x', amount: 21, secret: multisigSecret(), C: '02' + '22'.repeat(32) };
    const [signed] = signP2PKProofs([proof], OPERATOR_PRIV, true);
    expect(() => signP2PKProofs([signed], OPERATOR_PRIV, true)).toThrow(/already signed/);
  });

  it('authorizes the refund key (and only the refund key) after the locktime', () => {
    const expired = multisigSecret({ locktime: Math.floor(Date.now() / 1000) - 60 });
    const proof = { id: 'x', amount: 21, secret: expired, C: '02' + '22'.repeat(32) };
    // Depositor (refund key) can sign alone post-locktime...
    const [refunded] = signP2PKProofs([proof], PARTY_A_PRIV, true);
    expect(refunded.witness).toBeDefined();
    // ...but the operator and the other party no longer can.
    expect(() => signP2PKProofs([proof], OPERATOR_PRIV, true)).toThrow(/Signature not required/);
    expect(() => signP2PKProofs([proof], PARTY_B_PRIV, true)).toThrow(/Signature not required/);
  });
});
