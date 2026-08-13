import { describe, expect, it, vi } from 'vitest';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { verifyEvent } from 'nostr-tools';

import { buildNut27MintListEvent, deriveNut27Key, NUT27_D_TAG, NUT27_KIND, restoreNut27MintList } from './nut27';
import { createNip60Signer, type Nip60SyncApi } from './cashuNip60';

describe('NUT-27 mint-list backup', () => {
  it('derives a stable domain-separated key and creates an interoperable event', async () => {
    const mnemonic = generateMnemonic(wordlist);
    expect(deriveNut27Key(mnemonic)).toEqual(deriveNut27Key(mnemonic));

    const event = await buildNut27MintListEvent(mnemonic, [
      'https://mint.example.com/',
      'https://mint.example.com',
      'http://unsafe.example.com',
    ]);

    expect(event.kind).toBe(NUT27_KIND);
    expect(event.tags).toContainEqual(['d', NUT27_D_TAG]);
    expect(verifyEvent(event)).toBe(true);
    expect(event.content).not.toContain('mint.example.com');
  });

  it('queries by derived author and restores only allowed deduplicated mints', async () => {
    const mnemonic = generateMnemonic(wordlist);
    const event = await buildNut27MintListEvent(mnemonic, [
      'https://mint.example.com/',
      'https://mint.example.com',
      'http://unsafe.example.com',
    ]);
    const sync = {
      signer: createNip60Signer(new Uint8Array(32).fill(1)),
      publish: vi.fn(),
      query: vi.fn().mockResolvedValue([event]),
      relays: [],
    } satisfies Nip60SyncApi;

    await expect(restoreNut27MintList(mnemonic, sync)).resolves.toEqual(['https://mint.example.com']);
    expect(sync.query).toHaveBeenCalledWith(expect.objectContaining({
      kinds: [NUT27_KIND],
      authors: [event.pubkey],
      '#d': [NUT27_D_TAG],
    }));
  });
});
