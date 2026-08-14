/**
 * 2140.wtf Private Cashu Sync (DPCS).
 *
 * The wallet state is encrypted with the user's own NIP-44 signer
 * (self-encryption) and published as a kind 30078 addressable event with an
 * opaque, pubkey-derived d-tag. All mint/proof/transaction metadata lives
 * inside the ciphertext; the public d-tag reveals nothing about the wallet.
 */
import { SimplePool, verifyEvent, type Event } from 'nostr-tools';
import type { NostrSigner } from '@nostrify/types';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/curves/utils.js';
import { devLog } from './devLog';

export const BACKUP_KIND = 30078;
/** Legacy public d-tag. Kept only as a read fallback for migration. */
export const LEGACY_BACKUP_D_TAG = 'freedomid:cashu';

const BACKUP_D_TAG_PREFIX = 'ditto:cashu:v1:';
const BACKUP_D_TAG_BYTES = 8;
const BACKUP_RELAY_TIMEOUT = 8000;

export interface CashuTransactionBackup {
  id: string;
  type: string;
  amount: number;
  memo: string;
  mintUrl: string;
  status: string;
  createdAt: number;
}

export interface CashuProofBackup {
  mintUrl: string;
  proofs: unknown[];
}

export interface ProcessedTokenHashBackup {
  hash: string;
  expiresAt: number;
}

export interface CashuBackupPayloadV1 {
  version: 1;
  timestamp: number;
  epoch: number;
  mints: string[];
  proofs: CashuProofBackup[];
  transactions: CashuTransactionBackup[];
  selectedMintUrl: string;
  customMints?: Array<{ name: string; url: string }>;
}

export interface CashuBackupPayloadV2 extends Omit<CashuBackupPayloadV1, 'version'> {
  version: 2;
  /** Compressed secp256k1 pubkey used for receiving NIP-61 Nutzaps. */
  nutzapPubkey?: string;
  /** Quote IDs that have already been minted, to prevent double-mint across devices. */
  mintedQuoteIds?: string[];
  /** Cross-device duplicate-token guard. */
  processedTokenHashes?: ProcessedTokenHashBackup[];
}

export type CashuBackupPayload = CashuBackupPayloadV1 | CashuBackupPayloadV2;

interface BackupUser {
  pubkey: string;
  signer: NostrSigner;
}

/**
 * Return the opaque DPCS d-tag for a given pubkey.
 *
 * The tag is deterministic (same pubkey -> same tag on every device) but
 * reveals no wallet-specific information to an observer scanning relays.
 */
export function getCashuBackupDTag(pubkey: string): string {
  const input = new TextEncoder().encode(`${BACKUP_D_TAG_PREFIX}${pubkey}`);
  const hash = sha256(input);
  return bytesToHex(hash.slice(0, BACKUP_D_TAG_BYTES));
}

function isValidV1Transaction(t: unknown): t is CashuTransactionBackup {
  if (!t || typeof t !== 'object') return false;
  const r = t as Record<string, unknown>;
  return (
    typeof r.id === 'string' &&
    typeof r.type === 'string' &&
    typeof r.amount === 'number' &&
    typeof r.memo === 'string' &&
    typeof r.mintUrl === 'string' &&
    typeof r.status === 'string' &&
    typeof r.createdAt === 'number'
  );
}

function isValidV1ProofEntry(entry: unknown): entry is CashuProofBackup {
  if (!entry || typeof entry !== 'object') return false;
  const r = entry as Record<string, unknown>;
  return typeof r.mintUrl === 'string' && Array.isArray(r.proofs);
}

function isValidCommonPayload(parsed: unknown): parsed is Omit<CashuBackupPayloadV1, 'version'> {
  if (!parsed || typeof parsed !== 'object') return false;
  const p = parsed as Record<string, unknown>;
  if (
    typeof p.timestamp !== 'number' ||
    !Number.isFinite(p.timestamp) ||
    p.timestamp < 0 ||
    typeof p.epoch !== 'number' ||
    !Number.isFinite(p.epoch) ||
    p.epoch < 0 ||
    !Array.isArray(p.mints) ||
    !p.mints.every((m: unknown) => typeof m === 'string') ||
    !Array.isArray(p.proofs) ||
    !p.proofs.every(isValidV1ProofEntry) ||
    !Array.isArray(p.transactions) ||
    !p.transactions.every(isValidV1Transaction) ||
    typeof p.selectedMintUrl !== 'string'
  ) {
    return false;
  }
  if (p.customMints !== undefined) {
    if (!Array.isArray(p.customMints)) return false;
    for (const m of p.customMints) {
      if (
        !m ||
        typeof m !== 'object' ||
        typeof (m as Record<string, unknown>).name !== 'string' ||
        typeof (m as Record<string, unknown>).url !== 'string'
      ) {
        return false;
      }
    }
  }
  return true;
}

function isValidV1Payload(parsed: unknown): parsed is CashuBackupPayloadV1 {
  if (!isValidCommonPayload(parsed)) return false;
  return (parsed as Record<string, unknown>).version === 1;
}

function isValidV2Payload(parsed: unknown): parsed is CashuBackupPayloadV2 {
  if (!isValidCommonPayload(parsed)) return false;
  const p = parsed as Record<string, unknown>;
  if (p.version !== 2) return false;
  if (p.nutzapPubkey !== undefined && typeof p.nutzapPubkey !== 'string') return false;
  if (p.mintedQuoteIds !== undefined) {
    if (!Array.isArray(p.mintedQuoteIds) || !p.mintedQuoteIds.every((q) => typeof q === 'string')) {
      return false;
    }
  }
  if (p.processedTokenHashes !== undefined) {
    if (!Array.isArray(p.processedTokenHashes)) return false;
    for (const h of p.processedTokenHashes) {
      if (
        !h ||
        typeof h !== 'object' ||
        typeof (h as Record<string, unknown>).hash !== 'string' ||
        typeof (h as Record<string, unknown>).expiresAt !== 'number'
      ) {
        return false;
      }
    }
  }
  return true;
}

function isValidBackupPayload(parsed: unknown): CashuBackupPayload | null {
  if (isValidV2Payload(parsed)) return parsed;
  if (isValidV1Payload(parsed)) return parsed;
  return null;
}

async function queryBackup(
  user: BackupUser,
  relayUrls: string[],
  dTag: string,
): Promise<Event | null> {
  const pool = new SimplePool();
  try {
    const events = await pool.querySync(
      relayUrls,
      {
        kinds: [BACKUP_KIND],
        authors: [user.pubkey],
        '#d': [dTag],
        limit: 20,
      },
      { maxWait: 15000 },
    );
    const newest = events
      .filter((ev) => verifyEvent(ev))
      .sort((a, b) => b.created_at - a.created_at)[0];
    return newest ?? null;
  } catch (err: unknown) {
    devLog.warn('Cashu backup query failed:', err instanceof Error ? err.message : String(err));
    return null;
  } finally {
    pool.close(relayUrls);
  }
}

async function decryptBackup(user: BackupUser, event: Event): Promise<CashuBackupPayload | null> {
  try {
    const plaintext = await user.signer.nip44!.decrypt(user.pubkey, event.content);
    if (!plaintext) {
      devLog.warn('Cashu backup: NIP-44 decryption returned empty');
      return null;
    }
    const parsed = JSON.parse(plaintext) as unknown;
    const payload = isValidBackupPayload(parsed);
    if (!payload) {
      devLog.warn('Cashu backup: decrypted payload does not match expected shape');
      return null;
    }
    return payload;
  } catch (err: unknown) {
    devLog.error('Cashu backup: failed to decrypt:', err instanceof Error ? err.message : String(err));
    return null;
  }
}

/**
 * Encrypt and publish the Cashu wallet state to Nostr relays.
 * Returns the published event id, or null on failure.
 */
export async function syncCashuState(
  payload: CashuBackupPayload,
  user: BackupUser,
  relayUrls: string[],
  dTag?: string,
): Promise<string | null> {
  if (!user?.signer?.nip44?.encrypt) {
    devLog.warn('Cashu sync: signer does not support NIP-44');
    return null;
  }
  if (relayUrls.length === 0) {
    devLog.warn('Cashu sync: no relays configured');
    return null;
  }

  const effectiveDTag = dTag ?? getCashuBackupDTag(user.pubkey);

  try {
    const plaintext = JSON.stringify(payload);
    const content = await user.signer.nip44.encrypt(user.pubkey, plaintext);

    const template = {
      kind: BACKUP_KIND,
      content,
      tags: [
        ['d', effectiveDTag],
        ['client', '2140'],
      ],
      created_at: Math.floor(Date.now() / 1000),
    };

    const event = (await user.signer.signEvent(template)) as Event;

    if (!verifyEvent(event)) {
      devLog.error('Cashu sync: generated event has invalid signature');
      return null;
    }

    const pool = new SimplePool();
    try {
      await Promise.race([
        Promise.any(relayUrls.map((url) => pool.publish([url], event))),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error('Backup relay timeout')), BACKUP_RELAY_TIMEOUT),
        ),
      ]);
      return event.id;
    } catch (err: unknown) {
      devLog.error('Cashu sync: failed to publish to any relay:', err instanceof Error ? err.message : String(err));
      return null;
    } finally {
      pool.close(relayUrls);
    }
  } catch (err: unknown) {
    devLog.error('Cashu sync error:', err instanceof Error ? err.message : String(err));
    return null;
  }
}

/**
 * Query Nostr relays for the newest encrypted Cashu backup and decrypt it.
 * Returns the payload or null if no valid backup is found.
 *
 * First queries the opaque DPCS d-tag, then falls back to the legacy
 * `freedomid:cashu` d-tag so existing backups are not lost.
 */
export async function restoreCashuState(
  user: BackupUser,
  relayUrls: string[],
  dTag?: string,
): Promise<CashuBackupPayload | null> {
  if (!user?.signer?.nip44?.decrypt) {
    devLog.warn('Cashu restore: signer does not support NIP-44');
    return null;
  }
  if (relayUrls.length === 0) {
    devLog.warn('Cashu restore: no relays configured');
    return null;
  }

  const primaryDTag = dTag ?? getCashuBackupDTag(user.pubkey);

  const primary = await queryBackup(user, relayUrls, primaryDTag);
  if (primary) {
    return decryptBackup(user, primary);
  }

  devLog.log('Cashu restore: no opaque backup found, trying legacy d-tag');
  const legacy = await queryBackup(user, relayUrls, LEGACY_BACKUP_D_TAG);
  if (legacy) {
    return decryptBackup(user, legacy);
  }

  devLog.warn('Cashu restore: no valid backup event found');
  return null;
}
