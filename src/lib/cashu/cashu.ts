/**
 * Cashu wallet utilities
 * Based on patterns from satoshi-pay-wallet and cashu.me
 * References:
 * - https://github.com/Codepocketdev/satoshi-pay-wallet (MIT)
 * - https://github.com/cashubtc/cashu.me
 */
import { generateMnemonic, mnemonicToSeedSync, entropyToMnemonic, mnemonicToEntropy } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { CashuMint, CashuWallet, getDecodedToken } from '@cashu/cashu-ts';
import { hashToCurve, pointFromHex } from '@cashu/cashu-ts/crypto/common';
import { verifyDLEQProof_reblind } from '@cashu/cashu-ts/crypto/client/NUT12';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import type { WeierstrassPoint } from '@noble/curves/abstract/weierstrass.js';
import { hexToBytes, bytesToNumberBE, bytesToHex } from '@noble/curves/utils.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { getPublicKey } from 'nostr-tools';
import { bytesToBase64, base64ToBytes } from './base64';
import { devLog } from './devLog';

export const DEFAULT_MINTS = [
  { name: 'Mint.btcforplebs', url: 'https://mint.btcforplebs.com' },
  { name: 'Kashu', url: 'https://kashu.me' },
  { name: 'Minibits', url: 'https://mint.minibits.cash/Bitcoin' },
];

export const WALLET_NAME = 'Freedom ID Wallet';

/** Maximum length of an encoded Cashu token string we will decode (bytes). */
export const MAX_TOKEN_LENGTH = 100_000;

/** Maximum length of individual proof fields (id, C, secret, witness). */
export const MAX_PROOF_FIELD_LENGTH = 4096;

/** Reject mint fees above this ppm (parts per million) to prevent runaway fees.
 *  Default 5% — override only after explicit user acknowledgement.
 */
export const MAX_MINT_FEE_PPM = 50_000;

const PROOF_ENCRYPTION_INFO = 'freedomid:cashu:proof-encryption:v1';
const NUTZAP_KEY_INFO = 'ditto:cashu:nutzap:v1';
const NIP60_WALLET_KEY_INFO = 'ditto:cashu:walletkey:v1';
const BAO_WALLET_KEY_INFO = 'ditto:cashu:bao:walletkey:v1';
const BAO_MNEMONIC_INFO = '2140:cashu:bao:seed:v1';
const CIPHER_VERSION_PREFIX = 'v1:';
const PROOF_CONTEXT_PREFIX = 'freedomid:proofs:';
const TRANSACTION_CONTEXT = 'freedomid:transactions';

/** Zero a Uint8Array to reduce sensitive material lifetime in memory. */
function secureZero(buf: Uint8Array): void {
  if (buf && typeof buf.fill === 'function') {
    buf.fill(0);
  }
}

/** Reject negative fees and fees that exceed a ppm cap relative to the amount. */
export function isFeeWithinMaxPpm(fee: number, amount: number, ppm = MAX_MINT_FEE_PPM): boolean {
  if (!Number.isFinite(fee) || fee < 0 || !Number.isFinite(amount) || amount < 0) return false;
  return fee <= Math.floor((amount * ppm) / 1_000_000);
}

function hasToHex(obj: unknown): obj is { toHex(isCompressed?: boolean): string } {
  return !!obj && typeof (obj as { toHex?: unknown }).toHex === 'function';
}

/** Convert a proof's C field to a secp256k1 point, handling both hex strings
 *  and WeierstrassPoint objects returned by cashu-ts.
 */
function proofCtoPoint(C: unknown): { point: WeierstrassPoint<bigint> | undefined; valid: boolean } {
  try {
    if (typeof C === 'string' && C.length > 0) {
      return { point: secp256k1.Point.fromHex(C), valid: true };
    }
    if (hasToHex(C)) {
      return { point: secp256k1.Point.fromHex(C.toHex(true)), valid: true };
    }
  } catch {
    // fall through to invalid
  }
  return { point: undefined, valid: false };
}

function parseDleqBytes(value: unknown): Uint8Array | null {
  if (typeof value === 'string') {
    try {
      const bytes = hexToBytes(value);
      if (bytes.length === 32) return bytes;
    } catch { /* ignore */ }
  }
  if (value instanceof Uint8Array && value.length === 32) return value;
  return null;
}

function parseDleqR(value: unknown): bigint | null {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isInteger(value) && value >= 0) return BigInt(value);
  if (typeof value === 'string') {
    try {
      const bytes = hexToBytes(value);
      if (bytes.length > 0) return bytesToNumberBE(bytes);
    } catch { /* ignore */ }
  }
  if (value instanceof Uint8Array && value.length > 0) return bytesToNumberBE(value);
  return null;
}

export interface ValidateReceivedProofsOptions {
  activeKeysetIds: Set<string>;
  /** Secrets already held locally; a mint returning one of these is trying to
   *  pass off an existing (possibly spent) proof as new change.
   */
  localSecrets?: Set<string>;
  /** Look up public keys for a keyset id (used for DLEQ verification). */
  getKeyset?: (id: string) => { keys: Record<number, string> } | undefined;
  /** When true, any proof missing a verifiable DLEQ is rejected. */
  requireDleq?: boolean;
}

/** Validate proofs returned by a mint after a receive/swap.
 *  Checks keyset membership, curve-point validity, local-secret duplication,
 *  and (optionally) DLEQ proofs against the mint's published keys.
 */
export function validateReceivedProofs(
  proofs: unknown[],
  options: ValidateReceivedProofsOptions,
): { valid: boolean; reason?: string } {
  if (!Array.isArray(proofs)) return { valid: false, reason: 'proofs must be an array' };
  const { activeKeysetIds, localSecrets, getKeyset, requireDleq } = options;

  for (const p of proofs) {
    if (!p || typeof p !== 'object') return { valid: false, reason: 'proof is not an object' };
    const proof = p as Record<string, unknown>;

    const id = String(proof.id);
    const secret = String(proof.secret);
    const amount = Number(proof.amount);

    if (!activeKeysetIds.has(id)) {
      return { valid: false, reason: `received proof has invalid keyset id: ${id}` };
    }
    if (!Number.isInteger(amount) || amount <= 0 || amount > Number.MAX_SAFE_INTEGER) {
      return { valid: false, reason: `received proof has invalid amount: ${amount}` };
    }
    if (secret.length === 0 || secret.length > MAX_PROOF_FIELD_LENGTH) {
      return { valid: false, reason: 'received proof has invalid secret' };
    }
    if (localSecrets?.has(secret)) {
      return { valid: false, reason: 'received proof reuses a secret already in local store' };
    }

    const C = proofCtoPoint(proof.C);
    if (!C.valid) {
      return { valid: false, reason: `received proof C is not a valid curve point: ${String(proof.C).slice(0, 24)}` };
    }

    if (requireDleq) {
      const dleq = proof.dleq;
      if (!dleq || typeof dleq !== 'object') {
        return { valid: false, reason: 'received proof is missing a DLEQ proof' };
      }
      const dleqObj = dleq as Record<string, unknown>;
      const s = parseDleqBytes(dleqObj.s);
      const e = parseDleqBytes(dleqObj.e);
      const r = parseDleqR(dleqObj.r);
      if (!s || !e || r === null) {
        return { valid: false, reason: 'received proof has malformed DLEQ proof' };
      }
      const keyset = getKeyset?.(id);
      if (!keyset) {
        return { valid: false, reason: `cannot verify DLEQ: keyset ${id} keys unavailable` };
      }
      const Ahex = keyset.keys[amount];
      if (!Ahex || typeof Ahex !== 'string') {
        return { valid: false, reason: `no public key for amount ${amount} in keyset ${id}` };
      }
      let A: WeierstrassPoint<bigint> | undefined;
      try {
        A = secp256k1.Point.fromHex(Ahex);
      } catch {
        return { valid: false, reason: `invalid public key for keyset ${id}` };
      }
      try {
        const secretBytes = new TextEncoder().encode(secret);
        // cashu-ts bundles its own secp256k1 point class. Rehydrate the
        // points through that package before calling its verifier; passing our
        // direct @noble/curves points throws "Weierstrass Point expected".
        const ok = verifyDLEQProof_reblind(
          secretBytes,
          { s, e, r },
          pointFromHex(C.point!.toHex(true)),
          pointFromHex(A!.toHex(true)),
        );
        if (!ok) {
          return { valid: false, reason: 'received proof has invalid DLEQ proof' };
        }
      } catch (err: unknown) {
        return { valid: false, reason: `DLEQ verification failed: ${err instanceof Error ? err.message : String(err)}` };
      }
    }
  }

  return { valid: true };
}

async function importAesKey(rawKey: BufferSource): Promise<CryptoKey> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('Web Crypto API not available. HTTPS or secure context required.');
  }
  return crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** Generate a 12-word BIP-39 seed phrase */
export function generateWalletSeed(): string {
  return generateMnemonic(wordlist, 128); // 128 bits = 12 words
}

/** Derive the BIP-39 seed bytes from a mnemonic */
export function deriveMasterKey(seedPhrase: string): Uint8Array {
  const trimmed = seedPhrase.trim();
  if (trimmed.length === 0) {
    throw new Error('Invalid seed phrase');
  }
  if (trimmed.length > 2000) {
    throw new Error('Seed phrase too long');
  }
  return mnemonicToSeedSync(trimmed);
}

/** Derive an encryption key from the seed (for local proof storage) using HKDF-SHA256. */
export async function deriveEncryptionKey(seedPhrase: string): Promise<CryptoKey> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('Web Crypto API not available. HTTPS or secure context required.');
  }
  const seed = deriveMasterKey(seedPhrase);
  try {
    const keyBytes = hkdf(sha256, seed, new Uint8Array(0), new TextEncoder().encode(PROOF_ENCRYPTION_INFO), 32);
    const keyBuf = keyBytes.buffer.slice(keyBytes.byteOffset, keyBytes.byteOffset + keyBytes.byteLength) as ArrayBuffer;
    return await importAesKey(keyBuf);
  } finally {
    secureZero(seed);
  }
}

export interface NutzapKeyPair {
  privkey: Uint8Array;
  /** Compressed secp256k1 public key (hex). */
  pubkey: string;
}

/**
 * Derive a deterministic NIP-61 Nutzap key pair from the wallet seed.
 *
 * The private key is never published; only the compressed pubkey is exposed in
 * the optional kind:10019 receiver ad.
 */
export function deriveNutzapKey(seedPhrase: string): NutzapKeyPair {
  const seed = deriveMasterKey(seedPhrase);
  try {
    const privkey = hkdf(sha256, seed, new Uint8Array(0), new TextEncoder().encode(NUTZAP_KEY_INFO), 32);
    const pubkeyBytes = secp256k1.getPublicKey(privkey, true);
    return { privkey, pubkey: bytesToHex(pubkeyBytes) };
  } finally {
    secureZero(seed);
  }
}

/** Deterministic secp256k1 keypair used to sign NIP-60 token/history/deletion events.
 *  The pubkey is the x-only hex form used inside kind:10019 and for P2PK locks. */
export function deriveNip60WalletKey(seedPhrase: string): { privkey: Uint8Array; pubkey: string } {
  const seed = deriveMasterKey(seedPhrase);
  try {
    const privkey = hkdf(sha256, seed, new Uint8Array(0), new TextEncoder().encode(NIP60_WALLET_KEY_INFO), 32);
    const pubkey = getPublicKey(privkey);
    return { privkey, pubkey };
  } finally {
    secureZero(seed);
  }
}

/** Deterministic BAO wallet keypair used for the BAO signet/demo Cashu wallet. */
export function deriveBaoWalletKey(seedPhrase: string): { privkey: Uint8Array; pubkey: string } {
  const seed = deriveMasterKey(seedPhrase);
  try {
    const privkey = hkdf(sha256, seed, new Uint8Array(0), new TextEncoder().encode(BAO_WALLET_KEY_INFO), 32);
    const pubkey = getPublicKey(privkey);
    return { privkey, pubkey };
  } finally {
    secureZero(seed);
  }
}

/** Derive a dedicated BIP-39 mnemonic for the BAO wallet from the user's main Cashu seed. */
export function deriveBaoCashuMnemonic(userSeedPhrase: string): string {
  const trimmed = userSeedPhrase.trim();
  if (trimmed.length === 0) {
    throw new Error('Invalid seed phrase');
  }
  const userEntropy = mnemonicToEntropy(trimmed, wordlist);
  const derivedEntropy = hkdf(sha256, userEntropy, new Uint8Array(0), new TextEncoder().encode(BAO_MNEMONIC_INFO), 16);
  try {
    return entropyToMnemonic(derivedEntropy, wordlist);
  } finally {
    secureZero(derivedEntropy);
    secureZero(userEntropy);
  }
}

/** Legacy key derivation (raw SHA-256) for decrypting data written before HKDF migration. */
export async function deriveLegacyEncryptionKey(seedPhrase: string): Promise<CryptoKey> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('Web Crypto API not available. HTTPS or secure context required.');
  }
  const seed = deriveMasterKey(seedPhrase);
  try {
    const hash = await crypto.subtle.digest('SHA-256', seed as unknown as BufferSource);
    return await importAesKey(hash);
  } finally {
    secureZero(seed);
  }
}

function encodeAad(context?: string): BufferSource | undefined {
  if (!context) return undefined;
  return new TextEncoder().encode(context) as BufferSource;
}

function aesGcmParams(iv: Uint8Array, aad?: BufferSource): AesGcmParams {
  // Chromium rejects an `additionalData: undefined` property even though
  // WebCrypto treats an omitted field as valid. Only include AAD when a
  // context was supplied so legacy/context-free storage works in browsers.
  return aad === undefined
    ? ({ name: 'AES-GCM', iv } as AesGcmParams)
    : ({ name: 'AES-GCM', iv, additionalData: aad } as AesGcmParams);
}

/** Encrypt proofs for local storage.
 *  The ciphertext is prefixed with a version header and bound to the supplied
 *  context string via AES-GCM AAD.
 */
export async function encryptProofs(proofs: unknown, key: CryptoKey, context?: string): Promise<string> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('Web Crypto API not available. HTTPS or secure context required.');
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(JSON.stringify(proofs));
  const aad = encodeAad(context);
  const encrypted = await crypto.subtle.encrypt(aesGcmParams(iv, aad), key, data);
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);
  return CIPHER_VERSION_PREFIX + bytesToBase64(combined);
}

function parseVersionedCiphertext(encryptedData: string): { combined: Uint8Array; context?: string } | null {
  if (encryptedData.startsWith(CIPHER_VERSION_PREFIX)) {
    try {
      const combined = base64ToBytes(encryptedData.slice(CIPHER_VERSION_PREFIX.length));
      return { combined };
    } catch {
      return null;
    }
  }
  try {
    return { combined: base64ToBytes(encryptedData) };
  } catch {
    return null;
  }
}

async function decryptAesGcm(
  combined: Uint8Array,
  key: CryptoKey,
  context?: string,
): Promise<ArrayBuffer> {
  if (combined.length < 12) {
    throw new Error('Ciphertext too short');
  }
  const iv = combined.slice(0, 12);
  const data = combined.slice(12);
  const aad = encodeAad(context);
  return crypto.subtle.decrypt(aesGcmParams(iv, aad), key, data);
}

/** Decrypt proofs from local storage. Throws on crypto or format errors so callers know data is unreadable.
 *  If a legacyKey is supplied and decryption with the primary key fails, the legacy key is tried as a fallback.
 *  Supports both v1 (prefixed, AAD-bound) and legacy (unprefixed, no AAD) ciphertexts.
 */
export async function decryptProofs(encryptedData: string, key: CryptoKey, legacyKey?: CryptoKey, context?: string): Promise<unknown> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('Web Crypto API not available. HTTPS or secure context required.');
  }
  const parsed = parseVersionedCiphertext(encryptedData);
  if (!parsed) {
    throw new Error('Invalid base64 encoding');
  }
  const { combined } = parsed;
  const isVersioned = encryptedData.startsWith(CIPHER_VERSION_PREFIX);
  const aadContext = isVersioned ? context : undefined;

  let decrypted: ArrayBuffer;
  try {
    decrypted = await decryptAesGcm(combined, key, aadContext);
  } catch {
    if (legacyKey) {
      try {
        decrypted = await decryptAesGcm(combined, legacyKey, aadContext);
      } catch {
        throw new Error('Decryption failed — wrong key or corrupted data');
      }
    } else {
      throw new Error('Decryption failed — wrong key or corrupted data');
    }
  }
  try {
    return JSON.parse(new TextDecoder().decode(decrypted));
  } catch {
    throw new Error('Decrypted data is not valid JSON');
  }
}

/** Generic AES-GCM encrypt for local storage (transactions, settings, etc.).
 *  The ciphertext is prefixed with a version header and bound to the supplied
 *  context string via AES-GCM AAD.
 */
export async function encryptData(plaintext: string, key: CryptoKey, context?: string): Promise<string> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('Web Crypto API not available. HTTPS or secure context required.');
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(plaintext);
  const aad = encodeAad(context);
  const encrypted = await crypto.subtle.encrypt(aesGcmParams(iv, aad), key, data);
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);
  return CIPHER_VERSION_PREFIX + bytesToBase64(combined);
}

/** Generic AES-GCM decrypt for local storage. Throws on crypto or format errors.
 *  If a legacyKey is supplied and decryption with the primary key fails, the legacy key is tried as a fallback.
 *  Supports both v1 (prefixed, AAD-bound) and legacy (unprefixed, no AAD) ciphertexts.
 */
export async function decryptData(encryptedData: string, key: CryptoKey, legacyKey?: CryptoKey, context?: string): Promise<string | null> {
  if (!encryptedData) return null;
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('Web Crypto API not available. HTTPS or secure context required.');
  }
  const parsed = parseVersionedCiphertext(encryptedData);
  if (!parsed) {
    throw new Error('Invalid base64 encoding');
  }
  const { combined } = parsed;
  const isVersioned = encryptedData.startsWith(CIPHER_VERSION_PREFIX);
  const aadContext = isVersioned ? context : undefined;

  let decrypted: ArrayBuffer;
  try {
    decrypted = await decryptAesGcm(combined, key, aadContext);
  } catch {
    if (legacyKey) {
      try {
        decrypted = await decryptAesGcm(combined, legacyKey, aadContext);
      } catch {
        throw new Error('Decryption failed — wrong key or corrupted data');
      }
    } else {
      throw new Error('Decryption failed — wrong key or corrupted data');
    }
  }
  return new TextDecoder().decode(decrypted);
}

export { PROOF_CONTEXT_PREFIX, TRANSACTION_CONTEXT };

/** Vibrate device (if supported) */
export function vibrate(pattern: number[] = [100]): void {
  if ('vibrate' in navigator) {
    navigator.vibrate(pattern);
  }
}

export type TokenType =
  | 'lightning'
  | 'cashu'
  | 'cashu_request'
  | 'lightning_address'
  | 'lnurl'
  | 'freedomid'
  | 'event_checkin'
  | 'unknown';

export interface DetectedToken {
  type: TokenType;
  data: string | Record<string, unknown>;
  raw: string;
}

/** Detect what kind of token/invoice a string contains */
export function detectTokenType(data: string): DetectedToken {
  if (typeof data !== 'string') return { type: 'unknown', data: String(data), raw: String(data) };
  if (data.length > 10000) return { type: 'unknown', data: data.slice(0, 100), raw: data };
  const lower = data.toLowerCase().trim();

  // Lightning invoice
  if (lower.startsWith('lightning:') || lower.startsWith('lightning://') || lower.startsWith('lnbc') || lower.startsWith('lntb')) {
    let invoice = data;
    if (lower.startsWith('lightning://')) {
      invoice = data.slice('lightning://'.length);
    } else if (lower.startsWith('lightning:')) {
      invoice = data.slice('lightning:'.length);
    }
    if (!invoice) return { type: 'unknown', data, raw: data };
    return { type: 'lightning', data: invoice, raw: data };
  }

  // Cashu token
  if (lower.startsWith('cashu')) {
    let token: string;
    if (lower.startsWith('cashu:')) {
      token = data.slice(6);
      if (token.startsWith('//')) token = token.slice(2);
    } else {
      token = data;
    }
    if (!token || token.toLowerCase() === 'cashu') return { type: 'unknown', data, raw: data };
    if (token.toLowerCase().startsWith('creq')) {
      return { type: 'cashu_request', data: token, raw: data };
    }
    return { type: 'cashu', data: token, raw: data };
  }

  // Cashu request without prefix
  if (lower.startsWith('creq')) {
    return { type: 'cashu_request', data, raw: data };
  }

  // LNURL
  if (lower.startsWith('lnurl')) {
    return { type: 'lnurl', data, raw: data };
  }

  // Lightning address (user@domain.com)
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(data)) {
    return { type: 'lightning_address', data, raw: data };
  }

  // Freedom ID verification QR
  if (lower.startsWith('freedomid:')) {
    return { type: 'freedomid', data: data.slice('freedomid:'.length), raw: data };
  }

  // Event check-in QR
  if (data.trim().startsWith('{')) {
    try {
      const parsed = JSON.parse(data);
      if (parsed && parsed.t === 'fid:event-checkin') {
        return { type: 'event_checkin', data: parsed, raw: data };
      }
    } catch {
      // fall through to unknown
    }
  }

  return { type: 'unknown', data, raw: data };
}

export interface DecodedTokenEntry {
  mintUrl: string;
  proofs: unknown[];
  amount: number;
}

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.');
  if (parts.length !== 4) return NaN;
  // Strict numeric check: parseInt('other', 10) & 0xff collapses to 0, so a
  // 4-LABEL HOSTNAME ('other.mint.example.com') would parse as 0.0.0.0 and be
  // misclassified as a private IP — rejecting every token from any mint whose
  // host happens to have exactly four dot-separated labels.
  if (!parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)) return NaN;
  return parts.reduce((acc, part) => (acc << 8) + Number(part), 0) >>> 0;
}

function isPrivateIPv4(ip: string): boolean {
  const n = ipv4ToInt(ip);
  if (Number.isNaN(n)) return false;
  // 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16
  if ((n >>> 24) === 127) return true;
  if ((n >>> 24) === 10) return true;
  if ((n >>> 20) === 0xac1) return true;
  if ((n >>> 16) === 0xc0a8) return true;
  if ((n >>> 16) === 0xa9fe) return true;
  if (n === 0) return true;
  return false;
}

function isPrivateIPv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  // ::1 loopback; fc00::/7 unique local; fe80::/10 link-local
  if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true;
  if (lower.startsWith('fe8') || lower.startsWith('fe9') || lower.startsWith('fea') || lower.startsWith('feb')) return true;
  return false;
}

/** Reject localhost, loopback, and private-network mint hosts.
 *  Require HTTPS for production mint URLs; HTTP is not auto-allowed.
 *  Optionally compare against an allow-list of normalized mint URLs.
 */
export function isAllowedMintUrl(url: string, allowList?: string[]): boolean {
  try {
    const u = new URL(url);
    // Require HTTPS for mint URLs; HTTP is not auto-allowed.
    if (u.protocol !== 'https:') return false;
    // The URL constructor normalizes IDN hosts to punycode automatically.
    const host = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    if (host === 'localhost') return false;
    if (isPrivateIPv4(host) || isPrivateIPv6(host)) return false;
    if (allowList && allowList.length > 0) {
      const normalized = u.href.replace(/\/+$/, '');
      const normalizedList = allowList
        .map((item) => {
          try {
            return new URL(item).href.replace(/\/+$/, '');
          } catch {
            return '';
          }
        })
        .filter(Boolean);
      if (!normalizedList.includes(normalized)) {
        devLog.warn('Mint URL not in allow-list:', url);
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

export function normalizeMintUrl(url: string): string | null {
  const trimmed = url.trim();
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    // Strip default ports so equivalent URLs share storage keys.
    if (parsed.protocol === 'https:' && parsed.port === '443') parsed.port = '';
    if (parsed.protocol === 'http:' && parsed.port === '80') parsed.port = '';
    // Strip trailing slashes from pathname only (URL serialization re-adds a
    // root slash, so remove it from the final string).
    parsed.pathname = parsed.pathname.replace(/\/+$/, '');
    // Only lowercase the origin (scheme + host + port), not path or query
    parsed.host = parsed.host.toLowerCase();
    return parsed.toString().replace(/\/$/, '');
  } catch {
    // Fallback for invalid URLs — only lowercase host-like portion before first /
    const withoutTrailing = trimmed.replace(/\/+$/, '');
    const schemeHostMatch = withoutTrailing.match(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/]+)(.*)$/);
    if (schemeHostMatch) {
      const scheme = schemeHostMatch[1].split('://')[0].toLowerCase();
      if (scheme !== 'http' && scheme !== 'https') return null;
      let hostPort = schemeHostMatch[1].toLowerCase();
      // Strip default ports in fallback path as well.
      hostPort = hostPort.replace(/:443(?=\/|$)/, '').replace(/:80(?=\/|$)/, '');
      return hostPort + schemeHostMatch[2];
    }
    return null;
  }
}

export function safeNormalizeMintUrl(url: string): string {
  return normalizeMintUrl(url) ?? url.trim();
}

/**
 * Prepare a decoded proof for RE-encoding with cashu-ts getEncodedToken.
 *
 * getDecodedToken yields a proof's witness as a JSON STRING, but the token
 * serializer only handles the OBJECT form correctly — given a string it
 * JSON-encodes it again, producing a double-encoded witness the mint cannot
 * parse (every P2PK signature check then fails). This burned the multisig
 * escrow release flow: the operator returns deposit proofs carrying its
 * witness signature, and receiveToken re-encodes entries per mint before
 * calling wallet.receive. Parse string witnesses back to objects; anything
 * unparseable is left untouched.
 */
export function normalizeProofWitnessForEncode<T extends object>(proof: T): T {
  const witness = (proof as { witness?: unknown }).witness;
  if (typeof witness !== 'string') return proof;
  try {
    const parsed: unknown = JSON.parse(witness);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return { ...proof, witness: parsed };
    }
  } catch {
    // keep the original — an unparseable witness fails at the mint either way
  }
  return proof;
}

function isValidProof(p: unknown): p is { id: string; amount: number; secret: string; C: string } {
  if (!p || typeof p !== 'object') return false;
  const proof = p as Record<string, unknown>;
  if (typeof proof.id !== 'string' || proof.id.length === 0 || proof.id.length > MAX_PROOF_FIELD_LENGTH) return false;
  if (typeof proof.C !== 'string' || proof.C.length === 0 || proof.C.length > MAX_PROOF_FIELD_LENGTH) return false;
  if (typeof proof.secret !== 'string' || proof.secret.length === 0 || proof.secret.length > MAX_PROOF_FIELD_LENGTH) return false;
  if (proof.witness !== undefined && (typeof proof.witness !== 'string' || proof.witness.length > MAX_PROOF_FIELD_LENGTH)) return false;
  if (typeof proof.amount !== 'number') return false;
  const amount = proof.amount;
  return Number.isInteger(amount) && amount > 0 && amount <= Number.MAX_SAFE_INTEGER;
}

/** Deterministic hash of decoded token entries. Used to deduplicate receive attempts. */
export function hashDecodedToken(entries: DecodedTokenEntry[]): string {
  const sorted = [...entries]
    .map((e) => ({
      mintUrl: normalizeMintUrl(e.mintUrl) ?? e.mintUrl,
      proofs: [...e.proofs]
        .map((p) => {
          const proof = p as Record<string, unknown>;
          return {
            id: String(proof.id),
            amount: Number(proof.amount),
            secret: String(proof.secret),
            C: String(proof.C),
          };
        })
        .sort((a, b) => a.secret.localeCompare(b.secret)),
    }))
    .sort((a, b) => a.mintUrl.localeCompare(b.mintUrl));
  const hash = sha256(new TextEncoder().encode(JSON.stringify(sorted)));
  return bytesToBase64(hash);
}

/** Validate and decode a Cashu token string */
export function decodeCashuToken(tokenStr: string): DecodedTokenEntry[] | null {
  if (typeof tokenStr !== 'string' || tokenStr.length > MAX_TOKEN_LENGTH) return null;
  let toDecode = tokenStr.trim();
  if (toDecode.toLowerCase().startsWith('cashu://')) {
    toDecode = toDecode.slice('cashu://'.length);
  } else if (toDecode.toLowerCase().startsWith('cashu:')) {
    toDecode = toDecode.slice('cashu:'.length);
  } else if (toDecode.toLowerCase().startsWith('cashu')) {
    toDecode = toDecode.slice('cashu'.length);
  }
  if (!toDecode) return null;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let decoded: any;
  try {
    decoded = getDecodedToken(toDecode);
  } catch {
    return null;
  }

  const entries: DecodedTokenEntry[] = [];

  if ('token' in decoded && Array.isArray(decoded.token)) {
    for (const entry of decoded.token) {
      const mintUrl = entry?.mint;
      const proofs = entry?.proofs;
      if (typeof mintUrl !== 'string' || mintUrl.length === 0 || !isAllowedMintUrl(mintUrl) || !Array.isArray(proofs) || proofs.length === 0) continue;
      const validProofs = proofs.filter(isValidProof);
      if (validProofs.length === 0) continue;
      const amount = validProofs.reduce((sum: number, p) => sum + p.amount, 0);
      entries.push({ mintUrl, proofs: validProofs, amount });
    }
  } else if ('mint' in decoded && 'proofs' in decoded) {
    const mintUrl = decoded.mint;
    const proofs = decoded.proofs;
    if (typeof mintUrl !== 'string' || mintUrl.length === 0 || !isAllowedMintUrl(mintUrl) || !Array.isArray(proofs) || proofs.length === 0) return null;
    const validProofs = proofs.filter(isValidProof);
    if (validProofs.length === 0) return null;
    const amount = validProofs.reduce((sum: number, p) => sum + p.amount, 0);
    entries.push({ mintUrl, proofs: validProofs, amount });
  }

  return entries.length > 0 ? entries : null;
}

/**
 * Check whether every proof in a token is already SPENT at its mint.
 *
 * Returns `true` (all proofs spent — the token was definitely redeemed by
 * someone), `false` (at least one proof is not spent — the token is still
 * redeemable), or `null` when the check could not be completed (undecodable
 * token, mint unreachable, malformed response).
 *
 * Used to distinguish "the recipient never saw this token" from "the
 * recipient redeemed it but the response was lost" — e.g. Routstr creates the
 * balance server-side before responding, so a lost HTTP response leaves the
 * proofs spent with no API key delivered.
 */
export async function checkTokenProofsSpent(tokenStr: string): Promise<boolean | null> {
  const entries = decodeCashuToken(tokenStr);
  if (!entries || entries.length === 0) return null;
  const encoder = new TextEncoder();
  for (const entry of entries) {
    const normalized = normalizeMintUrl(entry.mintUrl);
    if (!normalized) return null;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let states: any[];
    try {
      const w = new CashuWallet(new CashuMint(normalized));
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      states = await w.checkProofsStates(entry.proofs as any);
    } catch {
      return null;
    }
    if (!Array.isArray(states) || states.length !== entry.proofs.length) return null;
    const stateByY = new Map<string, string>();
    for (const s of states) {
      if (!s || typeof s !== 'object' || typeof s.Y !== 'string' || typeof s.state !== 'string') return null;
      stateByY.set(s.Y, s.state);
    }
    for (const p of entry.proofs) {
      let Y: string;
      try {
        Y = hashToCurve(encoder.encode(String((p as { secret: unknown }).secret))).toHex(true);
      } catch {
        return null;
      }
      if (stateByY.get(Y) !== 'SPENT') return false;
    }
  }
  return true;
}
