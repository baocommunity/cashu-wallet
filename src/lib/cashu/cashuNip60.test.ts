import { describe, expect, it, beforeEach } from 'vitest';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { generateSecretKey, getPublicKey } from 'nostr-tools';

import { deriveEncryptionKey, deriveNip60WalletKey } from './cashu';
import {
  buildWalletConfigEvent,
  buildWalletConfigPayload,
  buildTokenEvent,
  buildDeletionEvent,
  buildHistoryEvent,
  buildMintQuoteEvent,
  buildNutzapInfoEvent,
  buildNutzapEvent,
  buildNutzapRedemptionHistoryEvent,
  parseWalletConfigEvent,
  parseWalletConfigEvents,
  parseTokenEvent,
  parseHistoryEvent,
  parseMintQuoteEvent,
  parseNutzapInfoEvent,
  parseNutzapEvent,
  createNip60Signer,
  restoreNip60Wallet,
  restoreMintQuoteEvents,
  restoreCrossAppNip60Wallet,
  resolveMintAlias,
  computeContentHash,
  loadLastTokenEventId,
  saveLastTokenEventId,
  loadLastTokenEventHash,
  saveLastTokenEventHash,
  WALLET_CONFIG_KIND,
  TOKEN_KIND,
  HISTORY_KIND,
  QUOTE_KIND,
  DELETE_KIND,
  NUTZAP_INFO_KIND,
  NUTZAP_KIND,
} from './cashuNip60';

describe('pending mint quote events', () => {
  it('round-trips Amethyst-compatible NUT-20 recovery state', async () => {
    const signer = createNip60Signer(generateSecretKey());
    const quotePrivateKey = 'ab'.repeat(32);
    const event = await buildMintQuoteEvent('quote-123', 'https://mint.example.com/', signer, {
      quotePrivateKey,
      createdAt: 100,
      expiration: 200,
    });

    expect(event).not.toBeNull();
    expect(event!.kind).toBe(QUOTE_KIND);
    expect(event!.tags).toContainEqual(['mint', 'https://mint.example.com']);
    const parsed = await parseMintQuoteEvent(event!, signer);
    expect(parsed).toEqual({
      eventId: event!.id,
      quoteId: 'quote-123',
      mint: 'https://mint.example.com',
      quotePrivateKey,
      createdAt: 100,
      expiresAt: 200_000,
    });
  });

  it('restores only live, undeleted quotes', async () => {
    const signer = createNip60Signer(generateSecretKey());
    const deleted = await buildMintQuoteEvent('deleted', 'https://mint.example.com', signer, { createdAt: 100, expiration: 500 });
    const live = await buildMintQuoteEvent('live', 'https://mint.example.com', signer, { createdAt: 200, expiration: 500 });
    const expired = await buildMintQuoteEvent('expired', 'https://mint.example.com', signer, { createdAt: 50, expiration: 99 });
    const deletion = await buildDeletionEvent([deleted!.id], signer, 'mint quote completed', [['k', String(QUOTE_KIND)]]);
    const queryFn = async (filter: { kinds: number[] }) => {
      if (filter.kinds.includes(QUOTE_KIND)) return [deleted!, live!, expired!];
      if (filter.kinds.includes(DELETE_KIND)) return [deletion!];
      return [];
    };

    const restored = await restoreMintQuoteEvents(signer, queryFn as never, 100_000);
    expect(restored.map((quote) => quote.quoteId)).toEqual(['live']);
  });
});

describe('createNip60Signer', () => {
  it('derives the expected x-only pubkey and can sign an event', async () => {
    const privkey = generateSecretKey();
    const signer = createNip60Signer(privkey);
    expect(signer.pubkey).toBe(getPublicKey(privkey));

    const event = await signer.signEvent({
      kind: 1,
      content: 'hello',
      tags: [],
      created_at: Math.floor(Date.now() / 1000),
    });
    expect(event).not.toBeNull();
    expect(event!.pubkey).toBe(signer.pubkey);
    expect(event!.sig).toHaveLength(128);
  });

  it('round-trips NIP-44 self-encryption', async () => {
    const signer = createNip60Signer(generateSecretKey());
    const plaintext = JSON.stringify({ mint: 'https://mint.example.com', proofs: [] });
    const ciphertext = await signer.nip44Encrypt(signer.pubkey, plaintext);
    expect(ciphertext).not.toBeNull();
    const decrypted = await signer.nip44Decrypt(signer.pubkey, ciphertext!);
    expect(decrypted).toBe(plaintext);
  });
});

describe('wallet config event', () => {
  it('round-trips a kind:17375 event', async () => {
    const walletKey = deriveNip60WalletKey(generateMnemonic(wordlist));
    const identityPrivkey = generateSecretKey();
    const identitySigner = createNip60Signer(identityPrivkey);
    const config = buildWalletConfigPayload(walletKey.privkey, [
      'https://mint.example.com',
      'https://mint.example.com/', // duplicate, should be normalized
    ]);

    const event = await buildWalletConfigEvent(config, identitySigner);
    expect(event).not.toBeNull();
    expect(event!.kind).toBe(WALLET_CONFIG_KIND);

    const parsed = await parseWalletConfigEvent(event!, identitySigner);
    expect(parsed).toEqual({
      id: 'default',
      privkey: config.privkey,
      mints: ['https://mint.example.com'],
    });
  });

  it('a malformed privkey entry never re-emits the previous config or steals its mints', async () => {
    const signer = createNip60Signer(generateSecretKey());
    const keyA = 'aa'.repeat(32);
    const keyC = 'cc'.repeat(32);
    // A three-field-plus privkey entry (garbage trailing element) sits between
    // two valid configs. The pre-fix parser left `current` pointing at the
    // ALREADY-PUSHED first config: the trailing mint attached to it and the
    // final push emitted it a second time.
    const entries = [
      ['privkey', keyA],
      ['mint', 'https://a.example.com'],
      ['privkey', 'id-x', 'bb'.repeat(32), 'garbage'],
      ['mint', 'https://b.example.com'],
      ['privkey', keyC],
      ['mint', 'https://c.example.com'],
    ];
    const content = await signer.nip44Encrypt(signer.pubkey, JSON.stringify(entries));
    const event = await signer.signEvent({
      kind: WALLET_CONFIG_KIND,
      content: content!,
      tags: [],
      created_at: Math.floor(Date.now() / 1000),
    });

    const configs = await parseWalletConfigEvents(event!, signer);
    expect(configs).toEqual([
      { id: 'default', privkey: keyA, mints: ['https://a.example.com'] },
      { id: 'default', privkey: keyC, mints: ['https://c.example.com'] },
    ]);
  });
});

describe('token event', () => {
  it('round-trips a kind:7375 event and preserves del ids', async () => {
    const signer = createNip60Signer(generateSecretKey());
    const proofs = [{ id: 'abc', amount: 1, secret: 's', C: 'c' }];
    const event = await buildTokenEvent(
      'https://mint.example.com',
      proofs,
      signer,
      ['deadbeef'.repeat(8), 'deadbeef'.repeat(8)],
      undefined,
      100,
    );
    expect(event).not.toBeNull();
    expect(event!.kind).toBe(TOKEN_KIND);

    const parsed = await parseTokenEvent(event!, signer);
    expect(parsed).toEqual({
      mint: 'https://mint.example.com',
      unit: 'sat',
      proofs,
      del: ['deadbeef'.repeat(8)],
    });
  });

  it('rejects a tampered token event', async () => {
    const signer = createNip60Signer(generateSecretKey());
    const event = await buildTokenEvent('https://mint.example.com', [], signer);
    expect(event).not.toBeNull();
    const tampered = JSON.parse(JSON.stringify(event)) as NonNullable<typeof event>;
    tampered.content = tampered.content + 'x';
    const parsed = await parseTokenEvent(tampered, signer);
    expect(parsed).toBeNull();
  });
});

describe('deletion event', () => {
  it('builds a kind:5 event referencing spent token ids', async () => {
    const signer = createNip60Signer(generateSecretKey());
    const ids = ['aabbccdd'.repeat(8), '11223344'.repeat(8), 'short'];
    const event = await buildDeletionEvent(ids, signer, 'spent');
    expect(event).not.toBeNull();
    expect(event!.kind).toBe(DELETE_KIND);
    expect(event!.content).toBe('spent');
    expect(event!.tags).toEqual([
      ['e', ids[0]],
      ['e', ids[1]],
    ]);
  });

  it('returns null when no valid ids are provided', async () => {
    const signer = createNip60Signer(generateSecretKey());
    const event = await buildDeletionEvent(['short', ''], signer);
    expect(event).toBeNull();
  });
});

describe('history event', () => {
  it('round-trips a kind:7376 event', async () => {
    const signer = createNip60Signer(generateSecretKey());
    const event = await buildHistoryEvent(
      'in',
      100,
      'https://mint.example.com',
      signer,
      [
        { id: 'aaa'.repeat(8), marker: 'created' },
        { id: 'bbb'.repeat(8), marker: 'destroyed' },
      ],
    );
    expect(event).not.toBeNull();
    expect(event!.kind).toBe(HISTORY_KIND);

    const parsed = await parseHistoryEvent(event!, signer);
    expect(parsed).toMatchObject({
      direction: 'in',
      amount: 100,
      unit: 'sat',
      mint: 'https://mint.example.com',
    });
    expect(parsed?.events).toEqual([
      { id: 'aaa'.repeat(8), marker: 'created' },
      { id: 'bbb'.repeat(8), marker: 'destroyed' },
    ]);
  });
});

describe('Nutzap info event', () => {
  it('round-trips a kind:10019 event', async () => {
    const identitySigner = createNip60Signer(generateSecretKey());
    const walletPubkey = getPublicKey(generateSecretKey());
    const event = await buildNutzapInfoEvent(
      ['https://mint.example.com', 'https://mint2.example.com'],
      ['wss://relay.example.com'],
      walletPubkey,
      identitySigner,
    );
    expect(event).not.toBeNull();
    expect(event!.kind).toBe(NUTZAP_INFO_KIND);
    expect(event!.tags).toContainEqual(['relay', 'wss://relay.example.com']);
    expect(event!.tags).toContainEqual(['mint', 'https://mint.example.com', 'sat']);
    expect(event!.tags).toContainEqual(['mint', 'https://mint2.example.com', 'sat']);
    expect(event!.tags).toContainEqual(['pubkey', walletPubkey]);

    const parsed = parseNutzapInfoEvent(event!);
    expect(parsed).toEqual({
      pubkey: walletPubkey,
      mints: ['https://mint.example.com', 'https://mint2.example.com'],
      relays: ['wss://relay.example.com'],
    });
  });

  it('rejects an unsigned or tampered kind:10019 event', async () => {
    const identitySigner = createNip60Signer(generateSecretKey());
    const walletPubkey = getPublicKey(generateSecretKey());
    const event = await buildNutzapInfoEvent(['https://mint.example.com'], [], walletPubkey, identitySigner);
    expect(event).not.toBeNull();
    const tampered = JSON.parse(JSON.stringify(event)) as NonNullable<typeof event>;
    tampered.content = 'tampered';
    expect(parseNutzapInfoEvent(tampered)).toBeNull();
  });

  it('rejects a kind:10019 event authored by someone other than the expected recipient', async () => {
    const identitySigner = createNip60Signer(generateSecretKey());
    const attackerSigner = createNip60Signer(generateSecretKey());
    const walletPubkey = getPublicKey(generateSecretKey());
    const event = await buildNutzapInfoEvent(['https://mint.example.com'], [], walletPubkey, attackerSigner);

    expect(parseNutzapInfoEvent(event!)).not.toBeNull();
    expect(parseNutzapInfoEvent(event!, identitySigner.pubkey)).toBeNull();
    expect(parseNutzapInfoEvent(event!, attackerSigner.pubkey)).not.toBeNull();
  });
});

describe('Nutzap event', () => {
  it('builds and parses a kind:9321 event', async () => {
    const identitySigner = createNip60Signer(generateSecretKey());
    const recipient = getPublicKey(generateSecretKey());
    const proofs = [
      { id: 'ks', amount: 21, secret: 's1', C: 'c1' },
      { id: 'ks', amount: 10, secret: 's2', C: 'c2' },
    ];
    const event = await buildNutzapEvent(
      recipient,
      'https://mint.example.com',
      proofs,
      identitySigner,
      { memo: 'hello', zappedEvent: { id: 'eventid'.repeat(2).padEnd(64, '0'), kind: 1, relay: 'wss://r' } },
    );
    expect(event).not.toBeNull();
    expect(event!.kind).toBe(NUTZAP_KIND);
    expect(event!.content).toBe('hello');

    const parsed = parseNutzapEvent(event!);
    expect(parsed).toMatchObject({
      mint: 'https://mint.example.com',
      recipient,
      sender: identitySigner.pubkey,
      amount: 31,
    });
    expect(parsed!.proofs).toHaveLength(2);
  });
});

describe('Nutzap redemption history event', () => {
  it('builds a kind:7376 redemption event', async () => {
    const walletSigner = createNip60Signer(generateSecretKey());
    const senderPubkey = getPublicKey(generateSecretKey());
    const event = await buildNutzapRedemptionHistoryEvent(
      42,
      'https://mint.example.com',
      'nutzapid'.repeat(4).padEnd(64, '0'),
      senderPubkey,
      'tokenid'.repeat(4).padEnd(64, '0'),
      walletSigner,
    );
    expect(event).not.toBeNull();
    expect(event!.kind).toBe(HISTORY_KIND);
    expect(event!.tags).toContainEqual(['e', 'nutzapid'.repeat(4).padEnd(64, '0'), '', 'redeemed']);
    expect(event!.tags).toContainEqual(['p', senderPubkey]);

    const parsed = await parseHistoryEvent(event!, walletSigner);
    expect(parsed).toMatchObject({ direction: 'in', amount: 42, mint: 'https://mint.example.com' });
  });

  it('rejects an empty or malformed created token event id', async () => {
    const walletSigner = createNip60Signer(generateSecretKey());
    const senderPubkey = getPublicKey(generateSecretKey());
    const baseArgs = [42, 'https://mint.example.com', 'nutzapid'.repeat(4).padEnd(64, '0'), senderPubkey] as const;

    expect(await buildNutzapRedemptionHistoryEvent(...baseArgs, '', walletSigner)).toBeNull();
    expect(await buildNutzapRedemptionHistoryEvent(...baseArgs, 'short', walletSigner)).toBeNull();
  });
});

describe('restoreNip60Wallet', () => {
  it('rebuilds unspent proofs from token events and respects deletions', async () => {
    const walletKey = deriveNip60WalletKey(generateMnemonic(wordlist));
    const identityPrivkey = generateSecretKey();
    const identitySigner = createNip60Signer(identityPrivkey);
    const walletSigner = createNip60Signer(walletKey.privkey);

    const config = buildWalletConfigPayload(walletKey.privkey, ['https://mint.example.com']);
    const configEvent = await buildWalletConfigEvent(config, identitySigner);

    const tokenA = await buildTokenEvent('https://mint.example.com', [{ amount: 1 }], walletSigner, undefined, undefined, 100);
    const tokenB = await buildTokenEvent(
      'https://mint.example.com',
      [{ amount: 2 }],
      walletSigner,
      [tokenA!.id],
      undefined,
      200,
    );
    const tokenC = await buildTokenEvent('https://mint.example.com', [{ amount: 3 }], walletSigner, undefined, undefined, 300);

    const deletion = await buildDeletionEvent([tokenC!.id], walletSigner);

    const queryFn = async (filter: { kinds: number[] }) => {
      if (filter.kinds.includes(WALLET_CONFIG_KIND)) return [configEvent!];
      if (filter.kinds.includes(TOKEN_KIND)) return [tokenA!, tokenB!, tokenC!];
      if (filter.kinds.includes(DELETE_KIND)) return [deletion!];
      if (filter.kinds.includes(HISTORY_KIND)) return [];
      return [];
    };

    const restored = await restoreNip60Wallet(walletSigner, identitySigner, queryFn as never);
    expect(restored.config).toEqual(config);
    expect(restored.proofsByMint['https://mint.example.com']).toHaveLength(1);
    expect(restored.proofsByMint['https://mint.example.com'].map((p) => (p as { amount: number }).amount)).toEqual([
      2,
    ]);
  });
});

describe('restoreCrossAppNip60Wallet', () => {
  it('recovers the wallet key from the identity config and restores foreign tokens', async () => {
    // Simulates bao.markets: wallet key unrelated to anything we can derive
    // locally; config published by the identity; tokens signed by the wallet key.
    const identityPrivkey = generateSecretKey();
    const identitySigner = createNip60Signer(identityPrivkey);
    const foreignWalletPrivkey = generateSecretKey();
    const foreignWalletSigner = createNip60Signer(foreignWalletPrivkey);

    const config = buildWalletConfigPayload(foreignWalletPrivkey, ['https://relay.bao.network/cashu']);
    const configEvent = await buildWalletConfigEvent(config, identitySigner);
    const token = await buildTokenEvent('https://relay.bao.network/cashu', [{ amount: 21 }], foreignWalletSigner);

    const queryFn = async (filter: { kinds: number[]; authors?: string[] }) => {
      if (filter.kinds.includes(WALLET_CONFIG_KIND)) return [configEvent!];
      if (filter.kinds.includes(TOKEN_KIND)) return filter.authors?.includes(foreignWalletSigner.pubkey) ? [token!] : [];
      if (filter.kinds.includes(DELETE_KIND)) return [];
      if (filter.kinds.includes(HISTORY_KIND)) return [];
      return [];
    };

    const { result, walletPrivkey, walletPubkey } = await restoreCrossAppNip60Wallet(identitySigner, queryFn as never);
    expect(walletPubkey).toBe(foreignWalletSigner.pubkey);
    expect(walletPrivkey).not.toBeNull();
    expect(result.config?.mints).toEqual(['https://relay.bao.network/cashu']);
    expect(result.proofsByMint['https://relay.bao.network/cashu']).toHaveLength(1);
  });

  it('returns nulls when the identity never published a config', async () => {
    const identitySigner = createNip60Signer(generateSecretKey());
    const { result, walletPrivkey, walletPubkey } = await restoreCrossAppNip60Wallet(identitySigner, async () => []);
    expect(result.config).toBeNull();
    expect(walletPrivkey).toBeNull();
    expect(walletPubkey).toBeNull();
  });

  it('ignores configs that are not signed by the identity', async () => {
    const identitySigner = createNip60Signer(generateSecretKey());
    const impostor = createNip60Signer(generateSecretKey());
    const config = buildWalletConfigPayload(generateSecretKey(), ['https://mint.example.com']);
    const forgedEvent = await buildWalletConfigEvent(config, impostor);

    const queryFn = async (filter: { kinds: number[] }) =>
      filter.kinds.includes(WALLET_CONFIG_KIND) ? [forgedEvent!] : [];

    // The forged event is well-formed but authored by the wrong key; the
    // caller's relay filter scopes authors, and verifyEvent re-checks the sig.
    // What matters here: decryption with the identity signer fails → no key.
    const { walletPrivkey, walletPubkey } = await restoreCrossAppNip60Wallet(identitySigner, queryFn as never);
    expect(walletPrivkey).toBeNull();
    expect(walletPubkey).toBeNull();
  });
});

describe('resolveMintAlias', () => {
  it('folds the bao.markets proxy path into the canonical mint URL', () => {
    expect(resolveMintAlias('https://relay.bao.network/bao-api/v1/proxy/cashu')).toBe('https://relay.bao.network/cashu');
  });

  it('leaves other mint URLs untouched', () => {
    expect(resolveMintAlias('https://mint.example.com')).toBe('https://mint.example.com');
    expect(resolveMintAlias('https://relay.bao.network/cashu')).toBe('https://relay.bao.network/cashu');
  });
});

describe('computeContentHash', () => {
  it('is deterministic for the same payload', () => {
    const payload = { mint: 'https://mint.example.com', unit: 'sat', proofs: [] };
    expect(computeContentHash(payload)).toBe(computeContentHash(payload));
  });

  it('changes when the payload changes', () => {
    const a = computeContentHash({ mint: 'a', unit: 'sat', proofs: [] });
    const b = computeContentHash({ mint: 'b', unit: 'sat', proofs: [] });
    expect(a).not.toBe(b);
  });
});

describe('token event localStorage helpers', () => {
  let encKey: CryptoKey;

  beforeEach(async () => {
    const phrase = generateMnemonic(wordlist);
    encKey = await deriveEncryptionKey(phrase);
    localStorage.clear();
  });

  it('save and load last token event id', async () => {
    await saveLastTokenEventId('https://mint.example.com', 'eventid'.repeat(4).padEnd(64, '0'), encKey);
    const loaded = await loadLastTokenEventId('https://mint.example.com', encKey);
    expect(loaded).toBe('eventid'.repeat(4).padEnd(64, '0'));
  });

  it('save and load last token event hash', async () => {
    await saveLastTokenEventHash('https://mint.example.com', 'hashvalue', encKey);
    const loaded = await loadLastTokenEventHash('https://mint.example.com', encKey);
    expect(loaded).toBe('hashvalue');
  });

  it('keeps last-token-event state separate for mints sharing a 16-byte URL prefix', async () => {
    // Regression: makeLocalMintKey used to keep only the first 16 URL bytes
    // (mostly the shared "https://" prefix), so these two mints shared one
    // localStorage key and clobbered each other's last-token-event state.
    const mintA = 'https://aaaaaaaa.one.example.com';
    const mintB = 'https://aaaaaaaa.two.example.com';
    expect(mintA.slice(0, 16)).toBe(mintB.slice(0, 16)); // collided under the old scheme
    await saveLastTokenEventId(mintA, 'a'.repeat(64), encKey);
    await saveLastTokenEventId(mintB, 'b'.repeat(64), encKey);
    expect(await loadLastTokenEventId(mintA, encKey)).toBe('a'.repeat(64));
    expect(await loadLastTokenEventId(mintB, encKey)).toBe('b'.repeat(64));
  });
});
