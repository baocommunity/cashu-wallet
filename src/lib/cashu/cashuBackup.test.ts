import { describe, expect, it, vi, beforeEach } from 'vitest';
import { generateSecretKey, getPublicKey, nip44, finalizeEvent, type Event } from 'nostr-tools';

import {
  BACKUP_KIND,
  getCashuBackupDTag,
  LEGACY_BACKUP_D_TAG,
  syncCashuState,
  restoreCashuState,
} from './cashuBackup';
import type { CashuBackupPayloadV2 } from './cashuBackup';

function createTestSigner() {
  const sk = generateSecretKey();
  const pk = getPublicKey(sk);
  const conversationKey = nip44.v2.utils.getConversationKey(sk, pk);
  return {
    pubkey: pk,
    signer: {
      getPublicKey: async () => pk,
      nip44: {
        encrypt: async (_pubkey: string, plaintext: string) =>
          nip44.v2.encrypt(plaintext, conversationKey),
        decrypt: async (_pubkey: string, ciphertext: string) =>
          nip44.v2.decrypt(ciphertext, conversationKey),
      },
      signEvent: async (template: unknown) =>
        finalizeEvent(template as Parameters<typeof finalizeEvent>[0], sk) as Event,
    },
  };
}

function makeV2Payload(): CashuBackupPayloadV2 {
  return {
    version: 2,
    timestamp: Date.now(),
    epoch: 0,
    mints: ['https://mint.example.com'],
    proofs: [{ mintUrl: 'https://mint.example.com', proofs: [{ amount: 1, C: 'abc', secret: 'secret', id: 'id' }] }],
    transactions: [
      { id: 'tx-1', type: 'receive', amount: 1, memo: '', mintUrl: 'https://mint.example.com', status: 'completed', createdAt: Date.now() },
    ],
    selectedMintUrl: 'https://mint.example.com',
    customMints: [{ name: 'Custom', url: 'https://custom.example.com' }],
    nutzapPubkey: '02' + 'a'.repeat(64),
    mintedQuoteIds: ['quote-1'],
    processedTokenHashes: [{ hash: 'hash-1', expiresAt: Date.now() + 86400000 }],
  };
}

const mocks = vi.hoisted(() => ({
  querySync: vi.fn(),
  publish: vi.fn(),
  close: vi.fn(),
}));

vi.mock('nostr-tools', async (importOriginal) => {
  const mod = await importOriginal<typeof import('nostr-tools')>();
  class SimplePoolMock {
    querySync = mocks.querySync;
    publish = mocks.publish;
    close = mocks.close;
  }
  return {
    ...mod,
    SimplePool: SimplePoolMock,
  };
});

describe('DPCS cashuBackup', () => {
  beforeEach(() => {
    mocks.querySync.mockReset();
    mocks.publish.mockReset();
    mocks.close.mockReset();
  });

  it('derives an opaque d-tag deterministically from a pubkey', () => {
    const pubkey = '0000000000000000000000000000000000000000000000000000000000000001';
    const a = getCashuBackupDTag(pubkey);
    const b = getCashuBackupDTag(pubkey);
    expect(a).toBe(b);
    expect(a).not.toBe(LEGACY_BACKUP_D_TAG);
    expect(a).toMatch(/^[0-9a-f]{16}$/);
  });

  it('produces different d-tags for different pubkeys', () => {
    const a = getCashuBackupDTag('0000000000000000000000000000000000000000000000000000000000000001');
    const b = getCashuBackupDTag('0000000000000000000000000000000000000000000000000000000000000002');
    expect(a).not.toBe(b);
  });

  it('publishes a v2 backup under the opaque d-tag', async () => {
    const user = createTestSigner();
    const payload = makeV2Payload();
    mocks.publish.mockResolvedValue(undefined);

    const id = await syncCashuState(payload, user, ['wss://relay.example.com']);

    expect(id).toBeTruthy();
    expect(mocks.publish).toHaveBeenCalledTimes(1);
    const event = mocks.publish.mock.calls[0]?.[1] as Event;
    expect(event.kind).toBe(BACKUP_KIND);
    expect(event.tags).toContainEqual(['d', getCashuBackupDTag(user.pubkey)]);
  });

  it('restores a v2 backup from the opaque d-tag', async () => {
    const user = createTestSigner();
    const payload = makeV2Payload();
    mocks.publish.mockResolvedValue(undefined);
    const id = await syncCashuState(payload, user, ['wss://relay.example.com']);
    expect(id).toBeTruthy();

    const publishedEvent = mocks.publish.mock.calls[0]?.[1] as Event;
    mocks.querySync.mockResolvedValue([publishedEvent]);

    const restored = await restoreCashuState(user, ['wss://relay.example.com']);

    expect(restored).not.toBeNull();
    expect(restored?.version).toBe(2);
    expect((restored as CashuBackupPayloadV2).nutzapPubkey).toBe(payload.nutzapPubkey);
    expect((restored as CashuBackupPayloadV2).mintedQuoteIds).toEqual(payload.mintedQuoteIds);
  });

  it('falls back to the legacy d-tag when no opaque backup exists', async () => {
    const user = createTestSigner();
    const payload = makeV2Payload();
    const event = await user.signer.signEvent({
      kind: BACKUP_KIND,
      content: await user.signer.nip44.encrypt(user.pubkey, JSON.stringify(payload)),
      tags: [['d', LEGACY_BACKUP_D_TAG]],
      created_at: Math.floor(Date.now() / 1000),
    });

    mocks.querySync.mockImplementation(async (_relays: string[], filter: { '#d'?: string[] }) => {
      if (filter['#d']?.includes(LEGACY_BACKUP_D_TAG)) return [event];
      return [];
    });

    const restored = await restoreCashuState(user, ['wss://relay.example.com']);

    expect(restored).not.toBeNull();
    expect(restored?.version).toBe(2);
  });

  it('prefers the opaque d-tag over the legacy d-tag', async () => {
    const user = createTestSigner();
    const opaquePayload = makeV2Payload();
    const legacyPayload: CashuBackupPayloadV2 = { ...makeV2Payload(), customMints: [{ name: 'Legacy', url: 'https://legacy.example.com' }] };

    const opaqueEvent = await user.signer.signEvent({
      kind: BACKUP_KIND,
      content: await user.signer.nip44.encrypt(user.pubkey, JSON.stringify(opaquePayload)),
      tags: [['d', getCashuBackupDTag(user.pubkey)], ['client', '2140']],
      created_at: Math.floor(Date.now() / 1000),
    });

    const legacyEvent = await user.signer.signEvent({
      kind: BACKUP_KIND,
      content: await user.signer.nip44.encrypt(user.pubkey, JSON.stringify(legacyPayload)),
      tags: [['d', LEGACY_BACKUP_D_TAG]],
      created_at: Math.floor(Date.now() / 1000) - 1,
    });

    mocks.querySync.mockImplementation(async (_relays: string[], filter: { '#d'?: string[] }) => {
      if (filter['#d']?.includes(getCashuBackupDTag(user.pubkey))) return [opaqueEvent];
      if (filter['#d']?.includes(LEGACY_BACKUP_D_TAG)) return [legacyEvent];
      return [];
    });

    const restored = await restoreCashuState(user, ['wss://relay.example.com']);

    expect(restored).not.toBeNull();
    expect((restored as CashuBackupPayloadV2).customMints).toEqual(opaquePayload.customMints);
  });
});
