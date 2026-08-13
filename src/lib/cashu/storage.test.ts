import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';

import { deriveEncryptionKey } from './cashu';
import {
  addTransaction,
  loadTransactionsSync,
  addProcessedNutzapId,
  isProcessedNutzapId,
  loadProcessedNutzapIds,
  savePendingNutzap,
  loadPendingNutzaps,
  removePendingNutzap,
  pendingNutzapCooldownRemaining,
  writePendingReceive,
  loadPendingReceive,
  clearPendingReceive,
  CrossTabLock,
  loadMintCounter,
  saveMintCounter,
  writePendingMint,
  loadPendingMint,
  clearPendingMint,
} from './storage';

describe('addTransaction', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const baseTx = {
    type: 'send' as const,
    amount: 100,
    memo: 'test',
    mintUrl: 'https://mint.example.com',
    status: 'completed' as const,
  };

  it('generates a crypto.randomUUID id by default', async () => {
    const id = await addTransaction(baseTx, undefined, undefined, { allowPlaintextFallback: true });
    expect(typeof id).toBe('string');
    expect(id).not.toContain('_');
    expect(id.length).toBeGreaterThan(10);

    const txs = loadTransactionsSync({ allowPlaintextFallback: true });
    expect(txs).toHaveLength(1);
    expect(txs[0].id).toBe(id);
  });

  it('falls back to Math.random when crypto.randomUUID throws', async () => {
    vi.spyOn(globalThis.crypto, 'randomUUID').mockImplementation(() => {
      throw new Error('Insecure context');
    });
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const id = await addTransaction(baseTx, undefined, undefined, { allowPlaintextFallback: true });
    expect(typeof id).toBe('string');
    expect(id).toContain('_');
    expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining('Math.random'));

    const txs = loadTransactionsSync({ allowPlaintextFallback: true });
    expect(txs).toHaveLength(1);
    expect(txs[0].id).toBe(id);

    warnSpy.mockRestore();
  });

  it('appends a timestamp when a generated id collides with an existing transaction', async () => {
    const existingId = 'collision-id';
    localStorage.setItem(
      'freedomid_transactions',
      JSON.stringify([
        { ...baseTx, id: existingId, createdAt: Date.now() - 1000 },
      ]),
    );
    vi.spyOn(globalThis.crypto, 'randomUUID').mockReturnValue(existingId as `${string}-${string}-${string}-${string}-${string}`);

    const id = await addTransaction(baseTx, undefined, undefined, { allowPlaintextFallback: true });
    expect(id).not.toBe(existingId);
    expect(id.startsWith(`${existingId}_`)).toBe(true);

    const txs = loadTransactionsSync({ allowPlaintextFallback: true });
    expect(txs).toHaveLength(2);
    expect(txs.map((t) => t.id)).toContain(existingId);
    expect(txs.map((t) => t.id)).toContain(id);
  });
});


describe('processed Nutzap ids', () => {
  let encKey: CryptoKey;

  beforeEach(async () => {
    const phrase = generateMnemonic(wordlist);
    encKey = await deriveEncryptionKey(phrase);
    localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('remembers a processed Nutzap id and evicts it on expiry', async () => {
    const id = 'nutzap-id'.padEnd(64, '0');
    await addProcessedNutzapId(id, encKey);
    expect(await isProcessedNutzapId(id, encKey)).toBe(true);
    expect(await loadProcessedNutzapIds(encKey)).toHaveLength(1);

    vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 8 * 24 * 60 * 60 * 1000);
    expect(await isProcessedNutzapId(id, encKey)).toBe(false);
    expect(await loadProcessedNutzapIds(encKey)).toHaveLength(0);
  });

  it('returns false for missing or empty ids', async () => {
    expect(await isProcessedNutzapId('', encKey)).toBe(false);
    expect(await isProcessedNutzapId('any-id', encKey)).toBe(false);
  });
});

describe('pending Nutzap journal', () => {
  let encKey: CryptoKey;

  beforeEach(async () => {
    const phrase = generateMnemonic(wordlist);
    encKey = await deriveEncryptionKey(phrase);
    localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const baseEntry = {
    id: 'pending-id',
    sendProofs: [{ amount: 21 }],
    recipientPubkey: 'recipient'.padEnd(64, '0'),
    mintUrl: 'https://mint.example.com',
    amount: 21,
    timestamp: Date.now(),
    attempts: 0,
  } satisfies Parameters<typeof savePendingNutzap>[0];

  it('saves and loads pending Nutzap entries', async () => {
    await savePendingNutzap(baseEntry, encKey);
    const loaded = await loadPendingNutzaps(encKey);
    expect(loaded).toHaveLength(1);
    expect(loaded[0]!.id).toBe(baseEntry.id);
    expect(loaded[0]!.amount).toBe(baseEntry.amount);
  });

  it('updates an existing entry by id', async () => {
    await savePendingNutzap(baseEntry, encKey);
    await savePendingNutzap({ ...baseEntry, attempts: 3 }, encKey);
    const loaded = await loadPendingNutzaps(encKey);
    expect(loaded).toHaveLength(1);
    expect(loaded[0]!.attempts).toBe(3);
  });

  it('removes a pending entry by id', async () => {
    await savePendingNutzap(baseEntry, encKey);
    await removePendingNutzap(baseEntry.id, encKey);
    expect(await loadPendingNutzaps(encKey)).toHaveLength(0);
  });

  it('enforces a retry cooldown between attempts', () => {
    const now = Date.now();
    const entry = { ...baseEntry, lastAttemptAt: now - 30_000 };
    expect(pendingNutzapCooldownRemaining(entry, now)).toBeGreaterThan(0);
    expect(pendingNutzapCooldownRemaining({ ...baseEntry, lastAttemptAt: now - 120_000 }, now)).toBe(0);
  });
});

describe('writePendingReceive attempts counter', () => {
  let encKey: CryptoKey;

  beforeEach(async () => {
    const phrase = generateMnemonic(wordlist);
    encKey = await deriveEncryptionKey(phrase);
    localStorage.clear();
  });

  it('preserves the stored attempts counter when no explicit value is passed', async () => {
    await writePendingReceive('cashuAtoken', 'hash-a', ['https://mint.example.com'], 10, encKey);
    await writePendingReceive('cashuAtoken', 'hash-a', ['https://mint.example.com'], 10, encKey, undefined, 3);
    // A later status update that does not pass attempts must NOT reset the
    // counter to 0 — otherwise the reconciler's max-attempts eviction never
    // trips and failed tokens are retried forever.
    await writePendingReceive('cashuAtoken', 'hash-a', ['https://mint.example.com'], 10, encKey, ['https://mint.example.com']);
    const entry = await loadPendingReceive('hash-a', encKey);
    expect(entry).not.toBeNull();
    expect(entry!.attempts).toBe(3);
  });

  it('starts at 0 for a fresh entry and applies explicit increments', async () => {
    await writePendingReceive('cashuAtoken', 'hash-b', ['https://mint.example.com'], 10, encKey);
    expect((await loadPendingReceive('hash-b', encKey))!.attempts).toBe(0);
    await writePendingReceive('cashuAtoken', 'hash-b', ['https://mint.example.com'], 10, encKey, undefined, 1);
    expect((await loadPendingReceive('hash-b', encKey))!.attempts).toBe(1);
    clearPendingReceive('hash-b');
    expect(await loadPendingReceive('hash-b', encKey)).toBeNull();
  });
});

describe('CrossTabLock.assertOwnership', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it('throws when the lock is not held', async () => {
    const lock = new CrossTabLock('freedomid_test_lock_a');
    await expect(lock.assertOwnership()).rejects.toThrow('not held');
  });

  it('resolves while held and throws again after release', async () => {
    const lock = new CrossTabLock('freedomid_test_lock_b');
    await lock.acquire();
    await expect(lock.assertOwnership()).resolves.toBeUndefined();
    lock.release();
    await expect(lock.assertOwnership()).rejects.toThrow('not held');
  });

  /** Overwrite the IDB lease record as if another tab took the lock while
   *  this tab was suspended past the lease expiry. */
  async function stealLease(key: string): Promise<void> {
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      const req = indexedDB.open('FreedomIDLocks', 1);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction('locks', 'readwrite');
      tx.objectStore('locks').put({ name: key, token: 'other-tab-token', expires: Date.now() + 60_000 });
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    db.close();
  }

  it('throws and invalidates when the lease was stolen while held (tab suspension)', async () => {
    const lock = new CrossTabLock('freedomid_test_lock_c');
    await lock.acquire();
    await expect(lock.assertOwnership()).resolves.toBeUndefined();

    await stealLease('freedomid_test_lock_c');

    await expect(lock.assertOwnership()).rejects.toThrow('lost while held');
    // Ownership state was invalidated — a later assert fails as 'not held',
    // so a stale writer can never commit over the other tab's state.
    await expect(lock.assertOwnership()).rejects.toThrow('not held');
  });

  it('re-entrant acquire after a lease theft fails loudly instead of running two writers', async () => {
    const lock = new CrossTabLock('freedomid_test_lock_d');
    await lock.acquire();

    await stealLease('freedomid_test_lock_d');

    await expect(lock.acquire()).rejects.toThrow('lost while held');
  });
});

describe('deterministic mint counter and pending-mint journal', () => {
  let encKey: CryptoKey;
  const mintUrl = 'https://mint.example.com';

  beforeEach(async () => {
    const phrase = generateMnemonic(wordlist);
    encKey = await deriveEncryptionKey(phrase);
    localStorage.clear();
  });

  it('defaults the counter to 0 and round-trips saved values', () => {
    expect(loadMintCounter(mintUrl)).toBe(0);
    saveMintCounter(mintUrl, 42);
    expect(loadMintCounter(mintUrl)).toBe(42);
  });

  it('round-trips and clears the pending-mint journal', async () => {
    await writePendingMint(mintUrl, { quoteId: 'q1', counterStart: 7, amount: 21, timestamp: Date.now() }, encKey);
    const entry = await loadPendingMint(mintUrl, encKey);
    expect(entry).toMatchObject({ quoteId: 'q1', counterStart: 7, amount: 21 });
    clearPendingMint(mintUrl);
    expect(await loadPendingMint(mintUrl, encKey)).toBeNull();
  });
});
