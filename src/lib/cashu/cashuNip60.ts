/**
 * NIP-60 / NIP-61 Cashu wallet sync utilities.
 *
 * Implements the standard Nostr Cashu wallet protocol:
 *   - kind:17375 wallet config (NIP-44 encrypted wallet key + mint list)
 *   - kind:7375 token events (NIP-44 encrypted per-mint unspent proofs)
 *   - kind:7376 history events (NIP-44 encrypted spend/receive audit log)
 *   - kind:5   deletions for spent token events
 *   - kind:10019 Nutzap receiver info
 *   - kind:9321 Nutzap payment
 *
 * Local encrypted storage remains the source of truth for spending. Relay events
 * are used for restore and cross-device convergence.
 */
import { finalizeEvent, getPublicKey, nip44, verifyEvent } from 'nostr-tools';
import { bytesToHex, hexToBytes } from '@noble/curves/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import type { NostrEvent } from '@nostrify/nostrify';
import type { NostrFilter } from '@nostrify/nostrify';
import type { NostrSigner } from '@nostrify/types';

import { devLog } from './devLog';
import { normalizeMintUrl, encryptData, decryptData } from './cashu';

export const WALLET_CONFIG_KIND = 17375;
export const TOKEN_KIND = 7375;
export const HISTORY_KIND = 7376;
export const QUOTE_KIND = 7374;
export const DELETE_KIND = 5;
export const NUTZAP_INFO_KIND = 10019;
export const NUTZAP_KIND = 9321;

const UNIT = 'sat';
const LOCAL_TOKEN_EVENT_KEY_PREFIX = '2140_nip60_token_event_';
const LOCAL_TOKEN_HASH_KEY_PREFIX = '2140_nip60_token_hash_';
const LOCAL_CONFIG_HASH_KEY = '2140_nip60_config_hash';
const LOCAL_NUTZAP_INFO_HASH_KEY = '2140_nip60_nutzap_info_hash';

function resolveNip60Key(key: string, namespace?: string): string {
  return namespace ? `${namespace}${key}` : key;
}

export type Nip60EventTemplate = Omit<NostrEvent, 'id' | 'pubkey' | 'sig'>;

/** Minimal signer abstraction so this module does not depend on React context. */
export interface Nip60Signer {
  pubkey: string;
  nip44Encrypt: (pubkey: string, plaintext: string) => Promise<string | null>;
  nip44Decrypt: (pubkey: string, ciphertext: string) => Promise<string | null>;
  signEvent: (template: Nip60EventTemplate) => Promise<NostrEvent | null>;
}

/** Sync adapter passed in by the host (e.g. a React hook). */
export interface Nip60SyncApi {
  /** The user's Nostr identity signer (used for kind:17375 / kind:10019 / kind:9321). */
  signer: Nip60Signer;
  /** Publish a signed event to relays. Returns the event id on success or null. */
  publish: (event: NostrEvent) => Promise<string | null>;
  /** Query relays for events matching a filter. */
  query: (filter: NostrFilter) => Promise<NostrEvent[]>;
  /** Optional: query specific relays outside the default pool (e.g. the relay
   * a Nutzap recipient lists in their kind:10019). */
  queryRelays?: (urls: string[], filter: NostrFilter) => Promise<NostrEvent[]>;
  /** Optional: publish to specific relays outside the default pool (e.g. the
   * relay another app's NIP-60 wallet lives on). */
  publishToRelays?: (urls: string[], event: NostrEvent) => Promise<string | null>;
  /** Relays the user reads/writes from (for Nutzap info tags). */
  relays: string[];
}

/** Encrypted wallet config payload stored in kind:17375 content. */
export interface Nip60WalletConfig {
  /** Wallet identifier. 'default' is the normal Cashu wallet; 'bao' is the BAO demo wallet. */
  id?: string;
  /** Hex private key used for P2PK / Nutzaps. Not the Nostr identity key. */
  privkey: string;
  /** Normalized mint URLs. */
  mints: string[];
}

/** Encrypted payload stored in kind:7375 content. */
export interface Nip60TokenContent {
  mint: string;
  unit: 'sat';
  proofs: unknown[];
  /** Ids of destroyed token events from older rollovers. */
  del?: string[];
}

/** Encrypted payload stored in kind:7376 content. */
export interface Nip60HistoryContent {
  direction: 'in' | 'out';
  amount: number;
  unit: 'sat';
  mint: string;
  /** Referenced token event ids with marker. */
  events?: Array<{ id: string; marker: 'created' | 'destroyed' }>;
}

/** Decrypted state carried by an optional NIP-60 kind:7374 mint quote. */
export interface Nip60MintQuoteContent {
  eventId: string;
  quoteId: string;
  mint: string;
  /** NUT-20 per-quote signing key. It is always NIP-44 encrypted on relays. */
  quotePrivateKey?: string;
  createdAt: number;
  expiresAt?: number;
}

export interface Nip60RestoreResult {
  /** The default ('default') wallet config if present. */
  config: Nip60WalletConfig | null;
  /** All wallet configs found in the newest kind:17375 event. */
  configs: Nip60WalletConfig[];
  /** Latest unspent proofs grouped by normalized mint URL. */
  proofsByMint: Record<string, unknown[]>;
  /** Parsed history events (newest first). */
  history: Nip60HistoryContent[];
}

/** Wrap the app's identity signer into a NIP-60 signer. */
export function createIdentityNip60Signer(user: { pubkey: string; signer: NostrSigner }): Nip60Signer {
  return {
    pubkey: user.pubkey,
    nip44Encrypt: async (pubkey, plaintext) => {
      try {
        return await user.signer.nip44!.encrypt(pubkey, plaintext);
      } catch (e) {
        devLog.error('Identity NIP-44 encrypt failed:', e);
        return null;
      }
    },
    nip44Decrypt: async (pubkey, ciphertext) => {
      try {
        return await user.signer.nip44!.decrypt(pubkey, ciphertext);
      } catch (e) {
        devLog.error('Identity NIP-44 decrypt failed:', e);
        return null;
      }
    },
    signEvent: async (template) => {
      try {
        return await user.signer.signEvent(template);
      } catch (e) {
        devLog.error('Identity sign failed:', e);
        return null;
      }
    },
  };
}

/** Create a signer from a raw secp256k1 private key (used for the wallet key). */
export function createNip60Signer(privkey: Uint8Array): Nip60Signer {
  const pubkey = getPublicKey(privkey);
  return {
    pubkey,
    nip44Encrypt: async (_pubkey, plaintext) => {
      try {
        const ck = nip44.v2.utils.getConversationKey(privkey, _pubkey);
        return nip44.v2.encrypt(plaintext, ck);
      } catch (e) {
        devLog.error('NIP-60 encrypt failed:', e);
        return null;
      }
    },
    nip44Decrypt: async (_pubkey, ciphertext) => {
      try {
        const ck = nip44.v2.utils.getConversationKey(privkey, _pubkey);
        return nip44.v2.decrypt(ciphertext, ck);
      } catch (e) {
        devLog.error('NIP-60 decrypt failed:', e);
        return null;
      }
    },
    signEvent: async (template) => {
      try {
        return finalizeEvent(template, privkey) as NostrEvent;
      } catch (e) {
        devLog.error('NIP-60 sign failed:', e);
        return null;
      }
    },
  };
}

/** Build the encrypted kind:17375 wallet config payload. */
export function buildWalletConfigPayload(
  walletPrivkey: Uint8Array,
  mints: string[],
): Nip60WalletConfig {
  const normalized = [...new Set(mints.map((m) => normalizeMintUrl(m)).filter(Boolean))] as string[];
  return {
    id: 'default',
    privkey: bytesToHex(walletPrivkey),
    mints: normalized,
  };
}

export function computeContentHash(payload: unknown): string {
  return bytesToHex(sha256(new TextEncoder().encode(JSON.stringify(payload))));
}

export async function loadLastWalletConfigHash(encKey: CryptoKey, namespace?: string): Promise<string | null> {
  let raw: string | null = null;
  try { raw = localStorage.getItem(resolveNip60Key(LOCAL_CONFIG_HASH_KEY, namespace)); } catch { return null; }
  if (!raw) return null;
  try {
    return await decryptData(raw, encKey);
  } catch {
    return null;
  }
}

export async function saveLastWalletConfigHash(hash: string, encKey: CryptoKey, namespace?: string): Promise<void> {
  try {
    const encrypted = await encryptData(hash, encKey);
    localStorage.setItem(resolveNip60Key(LOCAL_CONFIG_HASH_KEY, namespace), encrypted);
  } catch (e) {
    devLog.warn('Failed to save NIP-60 wallet config hash:', e);
  }
}

export async function loadLastNutzapInfoHash(encKey: CryptoKey, namespace?: string): Promise<string | null> {
  let raw: string | null = null;
  try { raw = localStorage.getItem(resolveNip60Key(LOCAL_NUTZAP_INFO_HASH_KEY, namespace)); } catch { return null; }
  if (!raw) return null;
  try {
    return await decryptData(raw, encKey);
  } catch {
    return null;
  }
}

export async function saveLastNutzapInfoHash(hash: string, encKey: CryptoKey, namespace?: string): Promise<void> {
  try {
    const encrypted = await encryptData(hash, encKey);
    localStorage.setItem(resolveNip60Key(LOCAL_NUTZAP_INFO_HASH_KEY, namespace), encrypted);
  } catch (e) {
    devLog.warn('Failed to save NIP-60 Nutzap info hash:', e);
  }
}

function makeLocalMintKey(prefix: string, mintUrl: string, namespace?: string): string | null {
  const normalized = normalizeMintUrl(mintUrl);
  if (!normalized) return null;
  // Full hex of the normalized URL — no truncation. The old `.slice(0, 32)`
  // kept only the first 16 URL bytes (mostly the shared "https://" prefix),
  // so different mints could share last-token-event localStorage keys.
  return (namespace || '') + prefix + bytesToHex(new TextEncoder().encode(normalized));
}

export async function loadLastTokenEventId(mintUrl: string, encKey: CryptoKey, namespace?: string): Promise<string | null> {
  const key = makeLocalMintKey(LOCAL_TOKEN_EVENT_KEY_PREFIX, mintUrl, namespace);
  if (!key) return null;
  let raw: string | null = null;
  try { raw = localStorage.getItem(key); } catch { return null; }
  if (!raw) return null;
  try {
    return await decryptData(raw, encKey);
  } catch {
    return null;
  }
}

export async function saveLastTokenEventId(mintUrl: string, eventId: string, encKey: CryptoKey, namespace?: string): Promise<void> {
  const key = makeLocalMintKey(LOCAL_TOKEN_EVENT_KEY_PREFIX, mintUrl, namespace);
  if (!key) return;
  try {
    const encrypted = await encryptData(eventId, encKey);
    localStorage.setItem(key, encrypted);
  } catch (e) {
    devLog.warn('Failed to save NIP-60 token event id:', e);
  }
}

export async function loadLastTokenEventHash(mintUrl: string, encKey: CryptoKey, namespace?: string): Promise<string | null> {
  const key = makeLocalMintKey(LOCAL_TOKEN_HASH_KEY_PREFIX, mintUrl, namespace);
  if (!key) return null;
  let raw: string | null = null;
  try { raw = localStorage.getItem(key); } catch { return null; }
  if (!raw) return null;
  try {
    return await decryptData(raw, encKey);
  } catch {
    return null;
  }
}

export async function saveLastTokenEventHash(mintUrl: string, hash: string, encKey: CryptoKey, namespace?: string): Promise<void> {
  const key = makeLocalMintKey(LOCAL_TOKEN_HASH_KEY_PREFIX, mintUrl, namespace);
  if (!key) return;
  try {
    const encrypted = await encryptData(hash, encKey);
    localStorage.setItem(key, encrypted);
  } catch (e) {
    devLog.warn('Failed to save NIP-60 token hash:', e);
  }
}

export function clearLastTokenEventId(mintUrl: string, namespace?: string): void {
  const key = makeLocalMintKey(LOCAL_TOKEN_EVENT_KEY_PREFIX, mintUrl, namespace);
  if (!key) return;
  try { localStorage.removeItem(key); } catch { /* ignore */ }
}

function mergeExtraTags(tags: string[][], extraTags?: string[][]): string[][] {
  if (!extraTags || extraTags.length === 0) return tags;
  return [...tags, ...extraTags];
}

function addPublishedAt(tags: string[][], publishedAt?: number): string[][] {
  if (!publishedAt) return tags;
  if (tags.some(([name]) => name === 'published_at')) return tags;
  return [...tags, ['published_at', String(publishedAt)]];
}

/** Build the encrypted kind:17375 wallet config event.
 *  Accepts a single config or multiple wallet configs (e.g. default + BAO). */
export async function buildWalletConfigEvent(
  configs: Nip60WalletConfig | Nip60WalletConfig[],
  signer: Nip60Signer,
  opts?: { extraTags?: string[][]; publishedAt?: number; createdAt?: number },
): Promise<NostrEvent | null> {
  const list = Array.isArray(configs) ? configs : [configs];
  const entries: string[][] = [];
  for (const config of list) {
    const id = config.id ?? 'default';
    if (id === 'default') {
      entries.push(['privkey', config.privkey]);
    } else {
      entries.push(['privkey', id, config.privkey]);
    }
    for (const m of config.mints) {
      const normalized = normalizeMintUrl(m);
      if (normalized) entries.push(['mint', normalized]);
    }
  }
  const plaintext = JSON.stringify(entries);
  const content = await signer.nip44Encrypt(signer.pubkey, plaintext);
  if (!content) return null;
  let tags = opts?.extraTags ? [...opts.extraTags] : [];
  tags = addPublishedAt(tags, opts?.publishedAt);
  return signer.signEvent({
    kind: WALLET_CONFIG_KIND,
    content,
    tags,
    created_at: opts?.createdAt ?? Math.floor(Date.now() / 1000),
  });
}

/** Parse a decrypted kind:17375 event into all wallet configs. */
export async function parseWalletConfigEvents(
  event: NostrEvent,
  signer: Nip60Signer,
): Promise<Nip60WalletConfig[]> {
  if (event.kind !== WALLET_CONFIG_KIND) return [];
  if (!verifyEvent(event)) return [];
  const plaintext = await signer.nip44Decrypt(event.pubkey, event.content);
  if (!plaintext) return [];
  try {
    const parsed = JSON.parse(plaintext) as unknown;
    if (!Array.isArray(parsed)) return [];
    const entries = parsed as string[][];
    const configs: Nip60WalletConfig[] = [];
    let current: Nip60WalletConfig | null = null;
    for (const entry of entries) {
      if (!Array.isArray(entry) || entry.length < 2) continue;
      const [key, ...rest] = entry;
      if (key === 'privkey') {
        if (current && current.privkey.length === 64) configs.push(current);
        // Reset BEFORE the shape checks: a malformed privkey entry must not
        // leave `current` pointing at the already-pushed config — trailing
        // mint entries would attach to it (misattributing the mint) and the
        // final push would emit the same config twice.
        current = null;
        if (rest.length === 1 && typeof rest[0] === 'string') {
          current = { id: 'default', privkey: rest[0], mints: [] };
        } else if (rest.length === 2 && typeof rest[0] === 'string' && typeof rest[1] === 'string') {
          current = { id: rest[0], privkey: rest[1], mints: [] };
        }
      } else if (key === 'mint' && current && typeof rest[0] === 'string') {
        const normalized = normalizeMintUrl(rest[0]);
        if (normalized) current.mints.push(normalized);
      }
    }
    if (current && current.privkey.length === 64) configs.push(current);
    return configs.filter((c) => c.mints.length > 0);
  } catch {
    return [];
  }
}

/** Parse a decrypted kind:17375 event into the default wallet config. */
export async function parseWalletConfigEvent(
  event: NostrEvent,
  signer: Nip60Signer,
): Promise<Nip60WalletConfig | null> {
  const configs = await parseWalletConfigEvents(event, signer);
  return configs.find((c) => (c.id ?? 'default') === 'default') ?? configs[0] ?? null;
}

/** Build a kind:7375 token event for a single mint's unspent proofs. */
export async function buildTokenEvent(
  mintUrl: string,
  proofs: unknown[],
  signer: Nip60Signer,
  delEventIds?: string[],
  extraTags?: string[][],
  createdAt?: number,
): Promise<NostrEvent | null> {
  const normalized = normalizeMintUrl(mintUrl);
  if (!normalized) return null;
  const payload: Nip60TokenContent = {
    mint: normalized,
    unit: UNIT,
    proofs: proofs.slice(),
  };
  if (delEventIds && delEventIds.length > 0) {
    payload.del = [...new Set(delEventIds)];
  }
  const content = await signer.nip44Encrypt(signer.pubkey, JSON.stringify(payload));
  if (!content) return null;
  return signer.signEvent({
    kind: TOKEN_KIND,
    content,
    tags: extraTags ? [...extraTags] : [],
    created_at: createdAt ?? Math.floor(Date.now() / 1000),
  });
}

/** Decrypt and parse a kind:7375 token event. */
export async function parseTokenEvent(
  event: NostrEvent,
  signer: Nip60Signer,
): Promise<Nip60TokenContent | null> {
  if (event.kind !== TOKEN_KIND) return null;
  if (!verifyEvent(event)) return null;
  const plaintext = await signer.nip44Decrypt(event.pubkey, event.content);
  if (!plaintext) return null;
  try {
    const parsed = JSON.parse(plaintext) as unknown;
    if (!parsed || typeof parsed !== 'object') return null;
    const p = parsed as Record<string, unknown>;
    if (typeof p.mint !== 'string' || p.unit !== UNIT || !Array.isArray(p.proofs)) return null;
    const normalized = normalizeMintUrl(p.mint);
    if (!normalized) return null;
    const content: Nip60TokenContent = {
      mint: normalized,
      unit: UNIT,
      proofs: p.proofs,
    };
    if (Array.isArray(p.del)) {
      content.del = p.del.filter((id): id is string => typeof id === 'string');
    }
    return content;
  } catch {
    return null;
  }
}

/** Build a kind:5 deletion request for spent token events. */
export async function buildDeletionEvent(
  eventIds: string[],
  signer: Nip60Signer,
  reason = 'spent',
  extraTags?: string[][],
  createdAt?: number,
): Promise<NostrEvent | null> {
  const ids = [...new Set(eventIds)].filter((id) => typeof id === 'string' && id.length === 64);
  if (ids.length === 0) return null;
  return signer.signEvent({
    kind: DELETE_KIND,
    content: reason,
    tags: mergeExtraTags(ids.map((id): [string, string] => ['e', id]), extraTags),
    created_at: createdAt ?? Math.floor(Date.now() / 1000),
  });
}

/** Build an optional kind:7376 history event. */
export async function buildHistoryEvent(
  direction: 'in' | 'out',
  amount: number,
  mintUrl: string,
  signer: Nip60Signer,
  referencedEvents?: Array<{ id: string; marker: 'created' | 'destroyed' }>,
  extraTags?: string[][],
  createdAt?: number,
): Promise<NostrEvent | null> {
  const normalized = normalizeMintUrl(mintUrl);
  if (!normalized) return null;
  const entries: string[][] = [
    ['direction', direction],
    ['amount', String(amount)],
    ['unit', UNIT],
    ['mint', normalized],
  ];
  if (referencedEvents) {
    for (const ev of referencedEvents) {
      entries.push(['e', ev.id, '', ev.marker]);
    }
  }
  const content = await signer.nip44Encrypt(signer.pubkey, JSON.stringify(entries));
  if (!content) return null;
  return signer.signEvent({
    kind: HISTORY_KIND,
    content,
    tags: extraTags ? [...extraTags] : [],
    created_at: createdAt ?? Math.floor(Date.now() / 1000),
  });
}

/** Parse a kind:7376 history event. */
export async function parseHistoryEvent(
  event: NostrEvent,
  signer: Nip60Signer,
): Promise<Nip60HistoryContent | null> {
  if (event.kind !== HISTORY_KIND) return null;
  if (!verifyEvent(event)) return null;
  const plaintext = await signer.nip44Decrypt(event.pubkey, event.content);
  if (!plaintext) return null;
  try {
    const parsed = JSON.parse(plaintext) as unknown;
    if (!Array.isArray(parsed)) return null;
    const entries = parsed as string[][];
    const get = (key: string) => entries.find(([k]) => k === key)?.[1];
    const direction = get('direction');
    const amount = Number(get('amount'));
    const mint = get('mint');
    if ((direction !== 'in' && direction !== 'out') || !Number.isFinite(amount) || typeof mint !== 'string') {
      return null;
    }
    const events: Nip60HistoryContent['events'] = [];
    for (const tag of entries) {
      if (tag[0] === 'e' && typeof tag[1] === 'string') {
        const marker = tag[3] === 'created' || tag[3] === 'destroyed' ? tag[3] : 'created';
        events.push({ id: tag[1], marker });
      }
    }
    return { direction, amount, unit: UNIT, mint, events };
  } catch {
    return null;
  }
}

/** Build the optional NIP-60 kind:7374 used to resume a Lightning mint.
 *
 * The JSON field names match Amethyst/Quartz. Quotes without a NUT-20 key use
 * the legacy plain-string payload required by NIP-60.
 */
export async function buildMintQuoteEvent(
  quoteId: string,
  mintUrl: string,
  signer: Nip60Signer,
  opts?: {
    quotePrivateKey?: string;
    expiration?: number;
    extraTags?: string[][];
    createdAt?: number;
  },
): Promise<NostrEvent | null> {
  const normalized = normalizeMintUrl(mintUrl);
  if (!normalized || !quoteId || quoteId.length > 1000) return null;
  const quotePrivateKey = opts?.quotePrivateKey;
  if (quotePrivateKey !== undefined && !/^[0-9a-f]{64}$/.test(quotePrivateKey)) return null;

  const plaintext = quotePrivateKey
    ? JSON.stringify({ quote_id: quoteId, p2pk_priv: quotePrivateKey })
    : quoteId;
  const content = await signer.nip44Encrypt(signer.pubkey, plaintext);
  if (!content) return null;
  const createdAt = opts?.createdAt ?? Math.floor(Date.now() / 1000);
  const expiration = opts?.expiration ?? createdAt + 14 * 24 * 60 * 60;
  return signer.signEvent({
    kind: QUOTE_KIND,
    content,
    tags: mergeExtraTags([
      ['expiration', String(expiration)],
      ['mint', normalized],
    ], opts?.extraTags),
    created_at: createdAt,
  });
}

/** Decrypt either the standard legacy quote-id string or the NUT-20 JSON
 * extension used by Amethyst/Quartz. */
export async function parseMintQuoteEvent(
  event: NostrEvent,
  signer: Nip60Signer,
): Promise<Nip60MintQuoteContent | null> {
  if (event.kind !== QUOTE_KIND || event.pubkey !== signer.pubkey || !verifyEvent(event)) return null;
  const mintTag = event.tags.find((tag) => tag[0] === 'mint')?.[1];
  if (typeof mintTag !== 'string') return null;
  const mint = normalizeMintUrl(mintTag);
  if (!mint) return null;
  const plaintext = await signer.nip44Decrypt(event.pubkey, event.content);
  if (!plaintext) return null;

  let quoteId = plaintext;
  let quotePrivateKey: string | undefined;
  try {
    const parsed = JSON.parse(plaintext) as unknown;
    if (!parsed || typeof parsed !== 'object') return null;
    const payload = parsed as Record<string, unknown>;
    const candidate = payload.quote_id ?? payload.quoteId ?? payload.quote;
    if (typeof candidate !== 'string') return null;
    quoteId = candidate;
    const key = payload.p2pk_priv ?? payload.quotePrivateKey ?? payload.signingPrivkey;
    if (key !== undefined) {
      if (typeof key !== 'string' || !/^[0-9a-f]{64}$/.test(key)) return null;
      quotePrivateKey = key;
    }
  } catch {
    // NIP-60's original payload is the decrypted quote id itself.
  }
  if (!quoteId || quoteId.length > 1000) return null;

  const expirationRaw = event.tags.find((tag) => tag[0] === 'expiration')?.[1];
  const expiration = expirationRaw === undefined ? undefined : Number(expirationRaw);
  return {
    eventId: event.id,
    quoteId,
    mint,
    quotePrivateKey,
    createdAt: event.created_at,
    expiresAt: Number.isSafeInteger(expiration) && (expiration ?? 0) > 0 ? expiration! * 1000 : undefined,
  };
}

/** Restore live pending mint quotes and ignore deleted/expired duplicates. */
export async function restoreMintQuoteEvents(
  signer: Nip60Signer,
  queryFn: (filter: NostrFilter) => Promise<NostrEvent[]>,
  now = Date.now(),
): Promise<Nip60MintQuoteContent[]> {
  const [quoteEvents, deletionEvents] = await Promise.all([
    queryFn({ kinds: [QUOTE_KIND], authors: [signer.pubkey], limit: 200 }),
    queryFn({ kinds: [DELETE_KIND], authors: [signer.pubkey], limit: 500 }),
  ]);
  const deletedIds = new Set<string>();
  for (const event of deletionEvents) {
    if (event.kind !== DELETE_KIND || event.pubkey !== signer.pubkey || !verifyEvent(event)) continue;
    for (const tag of event.tags) {
      if (tag[0] === 'e' && typeof tag[1] === 'string') deletedIds.add(tag[1]);
    }
  }

  const parsed = await Promise.all(
    quoteEvents
      .filter((event) => !deletedIds.has(event.id))
      .map((event) => parseMintQuoteEvent(event, signer)),
  );
  const newestByQuote = new Map<string, Nip60MintQuoteContent>();
  for (const quote of parsed) {
    if (!quote || (quote.expiresAt !== undefined && quote.expiresAt <= now)) continue;
    const existing = newestByQuote.get(quote.quoteId);
    if (!existing || quote.createdAt > existing.createdAt) newestByQuote.set(quote.quoteId, quote);
  }
  return [...newestByQuote.values()].sort((a, b) => b.createdAt - a.createdAt);
}

/** Build a kind:10019 Nutzap info event. Signed by the user's identity key. */
export async function buildNutzapInfoEvent(
  mints: string[],
  relays: string[],
  walletPubkey: string,
  signer: Nip60Signer,
  opts?: { extraTags?: string[][]; publishedAt?: number; createdAt?: number },
): Promise<NostrEvent | null> {
  const tags: string[][] = [];
  for (const r of [...new Set(relays)]) {
    const trimmed = r.trim();
    if (trimmed) tags.push(['relay', trimmed]);
  }
  for (const m of [...new Set(mints.map((m) => normalizeMintUrl(m)).filter((m): m is string => !!m))]) {
    tags.push(['mint', m, UNIT]);
  }
  if (!walletPubkey || walletPubkey.length !== 64) return null;
  tags.push(['pubkey', walletPubkey]);
  const finalTags = addPublishedAt(mergeExtraTags(tags, opts?.extraTags), opts?.publishedAt);
  return signer.signEvent({
    kind: NUTZAP_INFO_KIND,
    content: '',
    tags: finalTags,
    created_at: opts?.createdAt ?? Math.floor(Date.now() / 1000),
  });
}

/** Parse a kind:10019 Nutzap info event into the recipient's trusted mints/relays/P2PK pubkey.
 *  When `expectedAuthor` is provided, the event must be authored by that pubkey.
 */
export function parseNutzapInfoEvent(
  event: NostrEvent,
  expectedAuthor?: string,
): { pubkey: string; mints: string[]; relays: string[] } | null {
  if (event.kind !== NUTZAP_INFO_KIND) return null;
  if (!verifyEvent(event)) return null;
  if (expectedAuthor && event.pubkey.toLowerCase() !== expectedAuthor.toLowerCase()) return null;
  const relays: string[] = [];
  const mints: string[] = [];
  let pubkey: string | null = null;
  for (const tag of event.tags) {
    if (!Array.isArray(tag) || tag.length < 2) continue;
    const [name, value] = tag;
    if (name === 'relay' && typeof value === 'string' && value.trim()) {
      relays.push(value.trim());
    } else if (name === 'mint' && typeof value === 'string') {
      const normalized = normalizeMintUrl(value);
      if (normalized) mints.push(normalized);
    } else if (name === 'pubkey' && typeof value === 'string') {
      const cleaned = value.trim().toLowerCase();
      // Accept both x-only (64) and compressed secp256k1 (66) pubkeys.
      if (/^[0-9a-f]{64}$/.test(cleaned) || /^0[23][0-9a-f]{64}$/.test(cleaned)) {
        pubkey = cleaned;
      }
    }
  }
  if (!pubkey || mints.length === 0) return null;
  return { pubkey, mints: [...new Set(mints)], relays: [...new Set(relays)] };
}

/** Build a kind:9321 Nutzap event. Signed by the sender's identity key. */
export async function buildNutzapEvent(
  recipientPubkey: string,
  mintUrl: string,
  proofs: unknown[],
  signer: Nip60Signer,
  opts?: {
    memo?: string;
    zappedEvent?: { id: string; kind: number; relay?: string };
    extraTags?: string[][];
    createdAt?: number;
  },
): Promise<NostrEvent | null> {
  const normalized = normalizeMintUrl(mintUrl);
  if (!normalized) return null;
  if (!recipientPubkey || recipientPubkey.length !== 64) return null;
  if (!Array.isArray(proofs) || proofs.length === 0) return null;
  const tags: string[][] = [
    ['p', recipientPubkey],
    ['u', normalized],
    ['unit', UNIT],
  ];
  if (opts?.zappedEvent) {
    tags.push(['e', opts.zappedEvent.id, opts.zappedEvent.relay ?? '']);
    tags.push(['k', String(opts.zappedEvent.kind)]);
  }
  for (const p of proofs) {
    tags.push(['proof', JSON.stringify(p)]);
  }
  return signer.signEvent({
    kind: NUTZAP_KIND,
    content: opts?.memo ?? '',
    tags: opts?.extraTags ? [...tags, ...opts.extraTags] : tags,
    created_at: opts?.createdAt ?? Math.floor(Date.now() / 1000),
  });
}

/** Parse a kind:9321 Nutzap event into its mint, proofs, and recipient.
 *  When `expectedAuthor` is provided, the event must be authored by that pubkey.
 */
export function parseNutzapEvent(
  event: NostrEvent,
  expectedAuthor?: string,
): { mint: string; proofs: unknown[]; recipient: string; sender: string; amount: number } | null {
  if (event.kind !== NUTZAP_KIND) return null;
  if (!verifyEvent(event)) return null;
  if (expectedAuthor && event.pubkey.toLowerCase() !== expectedAuthor.toLowerCase()) return null;
  let mint = '';
  let recipient = '';
  const proofs: unknown[] = [];
  for (const tag of event.tags) {
    if (!Array.isArray(tag) || tag.length < 2) continue;
    if (tag[0] === 'u' && typeof tag[1] === 'string') mint = tag[1];
    if (tag[0] === 'p' && typeof tag[1] === 'string') recipient = tag[1];
    if (tag[0] === 'proof' && typeof tag[1] === 'string') {
      try {
        proofs.push(JSON.parse(tag[1]));
      } catch { /* ignore malformed proof */ }
    }
  }
  if (!mint || !recipient || proofs.length === 0) return null;
  const amount: number = (proofs as unknown[]).reduce<number>((sum, p) => {
    if (p && typeof p === 'object' && 'amount' in p) {
      const amt = Number((p as Record<string, unknown>).amount);
      if (Number.isInteger(amt) && amt > 0) return sum + amt;
    }
    return sum;
  }, 0);
  return { mint, proofs, recipient, sender: event.pubkey, amount };
}

/** Build a kind:7376 history event that publicly marks a Nutzap as redeemed. Signed by the wallet key. */
export async function buildNutzapRedemptionHistoryEvent(
  amount: number,
  mintUrl: string,
  nutzapEventId: string,
  senderPubkey: string,
  createdTokenEventId: string,
  walletSigner: Nip60Signer,
  extraTags?: string[][],
  createdAt?: number,
): Promise<NostrEvent | null> {
  const normalized = normalizeMintUrl(mintUrl);
  if (!normalized) return null;
  if (!createdTokenEventId || createdTokenEventId.length !== 64) return null;
  const contentEntries: string[][] = [
    ['direction', 'in'],
    ['amount', String(amount)],
    ['unit', UNIT],
    ['mint', normalized],
    ['e', createdTokenEventId, '', 'created'],
  ];
  const content = await walletSigner.nip44Encrypt(walletSigner.pubkey, JSON.stringify(contentEntries));
  if (!content) return null;
  const tags: string[][] = [
    ['e', nutzapEventId, '', 'redeemed'],
    ['p', senderPubkey],
  ];
  return walletSigner.signEvent({
    kind: HISTORY_KIND,
    content,
    tags: extraTags ? [...tags, ...extraTags] : tags,
    created_at: createdAt ?? Math.floor(Date.now() / 1000),
  });
}

/** Rebuild the unspent proof set from token events and deletion events.
 *
 * Unions proofs from all non-deleted token events for a given mint. In a
 * multi-device scenario two devices may publish token events from the same
 * ancestor with different remaining proofs; keeping only the newest event would
 * silently drop proofs. The caller is responsible for filtering the returned
 * proofs against the mint and for deduplicating by secret/`C` before merging
 * into local storage.
 */
export function rebuildProofSet(
  tokenEvents: Array<{ id: string; content: Nip60TokenContent; created_at: number }>,
  deletionEventIds: Set<string>,
): Record<string, unknown[]> {
  const sorted = [...tokenEvents].sort((a, b) => b.created_at - a.created_at || b.id.localeCompare(a.id));
  const excluded = new Set<string>(deletionEventIds);
  const result: Record<string, unknown[]> = {};

  for (const ev of sorted) {
    if (excluded.has(ev.id)) {
      if (ev.content.del) {
        for (const id of ev.content.del) excluded.add(id);
      }
      continue;
    }
    const existing = result[ev.content.mint];
    if (!existing) {
      result[ev.content.mint] = ev.content.proofs.slice();
    } else {
      existing.push(...ev.content.proofs);
    }
    if (ev.content.del) {
      for (const id of ev.content.del) excluded.add(id);
    }
  }

  return result;
}

/** Query relays for NIP-60 wallet state. */
export async function restoreNip60Wallet(
  walletSigner: Nip60Signer,
  configSigner: Nip60Signer,
  queryFn: (filter: NostrFilter) => Promise<NostrEvent[]>,
): Promise<Nip60RestoreResult> {
  const result: Nip60RestoreResult = { config: null, configs: [], proofsByMint: {}, history: [] };
  try {
    const [configEvents, tokenEvents, deletionEvents, historyEvents] = await Promise.all([
      queryFn({ kinds: [WALLET_CONFIG_KIND], authors: [configSigner.pubkey], limit: 5 }),
      queryFn({ kinds: [TOKEN_KIND], authors: [walletSigner.pubkey], limit: 500 }),
      queryFn({ kinds: [DELETE_KIND], authors: [walletSigner.pubkey], limit: 500 }),
      queryFn({ kinds: [HISTORY_KIND], authors: [walletSigner.pubkey], limit: 200 }),
    ]);

    const newestConfig = configEvents
      .filter((ev) => verifyEvent(ev))
      .sort((a, b) => b.created_at - a.created_at)[0];
    if (newestConfig) {
      result.configs = await parseWalletConfigEvents(newestConfig, configSigner);
      result.config = result.configs.find((c) => (c.id ?? 'default') === 'default') ?? result.configs[0] ?? null;
    }

    const deletedIds = new Set<string>();
    for (const ev of deletionEvents) {
      if (!verifyEvent(ev)) continue;
      for (const tag of ev.tags) {
        if (tag[0] === 'e' && typeof tag[1] === 'string') deletedIds.add(tag[1]);
      }
    }

    const parsedTokens: Array<{ id: string; content: Nip60TokenContent; created_at: number }> = [];
    for (const ev of tokenEvents) {
      const content = await parseTokenEvent(ev, walletSigner);
      if (content) {
        parsedTokens.push({ id: ev.id, content, created_at: ev.created_at });
      }
    }
    result.proofsByMint = rebuildProofSet(parsedTokens, deletedIds);

    for (const ev of historyEvents) {
      const parsed = await parseHistoryEvent(ev, walletSigner);
      if (parsed) {
        result.history.push(parsed);
      }
    }
    result.history.sort((a, b) => b.amount - a.amount);
  } catch (e) {
    devLog.error('NIP-60 restore failed:', e);
  }
  return result;
}

/**
 * Mint-URL aliases for the BAO signet mint. bao.markets can be configured to
 * reach the mint through the API proxy path while 2140wtf uses the direct
 * path; both URLs are the same mint backend, so proofs minted under either
 * URL must merge into one logical mint.
 */
export const BAO_SIGNET_MINT_ALIASES: Record<string, string> = {
  'https://relay.bao.network/bao-api/v1/proxy/cashu': 'https://relay.bao.network/cashu',
};

/** Resolve a mint URL to its canonical form when it is a known alias. */
export function resolveMintAlias(url: string): string {
  return BAO_SIGNET_MINT_ALIASES[url] ?? url;
}

export interface CrossAppNip60Restore {
  result: Nip60RestoreResult;
  /** Wallet key recovered from the identity's published config (null when the
   * other app never published one — nothing to restore or mirror then). */
  walletPrivkey: Uint8Array | null;
  walletPubkey: string | null;
}

/**
 * Cross-app NIP-60 restore: recover a wallet ANOTHER app (e.g. bao.markets)
 * published for the same Nostr identity, without sharing key derivation.
 *
 * Every NIP-60 wallet stores its wallet privkey inside the identity-signed
 * kind:17375 config (NIP-44 encrypted to self). Reading that config with the
 * identity signer yields the wallet key, which then decrypts and filters the
 * foreign wallet's token/history/deletion events. Works with any identity
 * signer that supports NIP-44 (including NIP-07, where no nsec is available).
 *
 * The caller decides which relays to query via `queryFn` (target the other
 * app's relay, e.g. wss://relay.bao.network) and how to merge the proofs.
 */
export async function restoreCrossAppNip60Wallet(
  identitySigner: Nip60Signer,
  queryFn: (filter: NostrFilter) => Promise<NostrEvent[]>,
): Promise<CrossAppNip60Restore> {
  const empty: CrossAppNip60Restore = {
    result: { config: null, configs: [], proofsByMint: {}, history: [] },
    walletPrivkey: null,
    walletPubkey: null,
  };
  try {
    const configEvents = await queryFn({ kinds: [WALLET_CONFIG_KIND], authors: [identitySigner.pubkey], limit: 5 });
    const newestConfig = configEvents
      .filter((ev) => verifyEvent(ev))
      .sort((a, b) => b.created_at - a.created_at)[0];
    if (!newestConfig) return empty;

    const configs = await parseWalletConfigEvents(newestConfig, identitySigner);
    const config = configs.find((c) => (c.id ?? 'default') === 'default') ?? configs[0] ?? null;
    if (!config || !/^[0-9a-f]{64}$/i.test(config.privkey)) return empty;

    const walletPrivkey = hexToBytes(config.privkey);
    const walletSigner = createNip60Signer(walletPrivkey);
    const result = await restoreNip60Wallet(walletSigner, identitySigner, queryFn);
    return { result, walletPrivkey, walletPubkey: walletSigner.pubkey };
  } catch (e) {
    devLog.error('Cross-app NIP-60 restore failed:', e);
    return empty;
  }
}
