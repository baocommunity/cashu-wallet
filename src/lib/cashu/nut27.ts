import { mnemonicToSeedSync } from '@scure/bip39';
import { sha256 } from '@noble/hashes/sha2.js';
import { getPublicKey } from 'nostr-tools';
import type { NostrEvent, NostrFilter } from '@nostrify/nostrify';

import { createNip60Signer, type Nip60SyncApi } from './cashuNip60';
import { isAllowedMintUrl, safeNormalizeMintUrl } from './cashu';

export const NUT27_KIND = 30078;
export const NUT27_D_TAG = 'mint-list';
const DOMAIN = new TextEncoder().encode('cashu-mint-backup');
const MAX_MINTS = 100;

export function deriveNut27Key(seedPhrase: string): Uint8Array {
  const seed = mnemonicToSeedSync(seedPhrase);
  const input = new Uint8Array(seed.length + DOMAIN.length);
  input.set(seed);
  input.set(DOMAIN, seed.length);
  return sha256(input);
}

function cleanMints(mints: string[]): string[] {
  return [...new Set(mints.map(safeNormalizeMintUrl).filter((url) => url && isAllowedMintUrl(url)))].slice(0, MAX_MINTS);
}

export async function buildNut27MintListEvent(seedPhrase: string, mints: string[], client = '2140.wtf'): Promise<NostrEvent> {
  const privateKey = deriveNut27Key(seedPhrase);
  const signer = createNip60Signer(privateKey);
  const content = await signer.nip44Encrypt(signer.pubkey, JSON.stringify({
    mints: cleanMints(mints),
    timestamp: Math.floor(Date.now() / 1000),
  }));
  if (!content) throw new Error('Could not encrypt NUT-27 mint backup');
  const event = await signer.signEvent({
    kind: NUT27_KIND,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['d', NUT27_D_TAG], ['client', client]],
    content,
  });
  if (!event) throw new Error('Could not sign NUT-27 mint backup');
  return event;
}

export async function restoreNut27MintList(seedPhrase: string, sync: Nip60SyncApi): Promise<string[]> {
  const privateKey = deriveNut27Key(seedPhrase);
  const signer = createNip60Signer(privateKey);
  const filter: NostrFilter = { kinds: [NUT27_KIND], authors: [getPublicKey(privateKey)], '#d': [NUT27_D_TAG], limit: 5 };
  const events = (await sync.query(filter))
    .filter((event) => event.kind === NUT27_KIND && event.pubkey === signer.pubkey && event.tags.some(([name, value]) => name === 'd' && value === NUT27_D_TAG))
    .sort((a, b) => b.created_at - a.created_at);
  for (const event of events) {
    const plaintext = await signer.nip44Decrypt(signer.pubkey, event.content);
    if (!plaintext) continue;
    try {
      const parsed = JSON.parse(plaintext) as { mints?: unknown };
      if (Array.isArray(parsed.mints) && parsed.mints.every((mint) => typeof mint === 'string')) {
        return cleanMints(parsed.mints);
      }
    } catch {
      // Try an older valid event if the newest relay result is malformed.
    }
  }
  return [];
}
