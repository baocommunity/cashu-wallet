import { describe, it, expect } from 'vitest';

import {
  CASHU_MINT_ANNOUNCEMENT_KIND,
  CASHU_MINT_RECOMMENDATION_KIND,
  parseMintAnnouncement,
  parseMintRecommendation,
  groupRecommendationsByUrl,
  buildMintRecommendationEvent,
  type CashuMintRecommendation,
} from './nip87';
import type { NostrEvent } from '@nostrify/nostrify';

function makeEvent(overrides: Partial<NostrEvent>): NostrEvent {
  return {
    id: 'id',
    pubkey: 'pubkey',
    created_at: 1,
    sig: 'sig',
    ...overrides,
  } as NostrEvent;
}

describe('parseMintAnnouncement', () => {
  it('returns null for wrong kind', () => {
    const event = makeEvent({ kind: 1, tags: [['d', 'mpubkey'], ['u', 'https://mint.example.com']], content: '' });
    expect(parseMintAnnouncement(event)).toBeNull();
  });

  it('returns null when d-tag is missing', () => {
    const event = makeEvent({ kind: CASHU_MINT_ANNOUNCEMENT_KIND, tags: [['u', 'https://mint.example.com']], content: '' });
    expect(parseMintAnnouncement(event)).toBeNull();
  });

  it('returns null for non-https URL', () => {
    const event = makeEvent({
      kind: CASHU_MINT_ANNOUNCEMENT_KIND,
      tags: [['d', 'mpubkey'], ['u', 'ftp://mint.example.com']],
      content: '',
    });
    expect(parseMintAnnouncement(event)).toBeNull();
  });

  it('parses a valid announcement', () => {
    const event = makeEvent({
      kind: CASHU_MINT_ANNOUNCEMENT_KIND,
      tags: [
        ['d', 'mpubkey'],
        ['u', 'https://mint.example.com/'],
        ['nuts', '1,2,3,4,5'],
        ['n', 'mainnet'],
      ],
      content: JSON.stringify({ name: 'Test Mint' }),
    });
    const parsed = parseMintAnnouncement(event);
    expect(parsed).not.toBeNull();
    expect(parsed!.mintId).toBe('mpubkey');
    expect(parsed!.mintUrl).toBe('https://mint.example.com');
    expect(parsed!.network).toBe('mainnet');
    expect(parsed!.nuts).toEqual([1, 2, 3, 4, 5]);
    expect(parsed!.metadata).toEqual({ name: 'Test Mint' });
  });

  it('normalizes URL and defaults network to unknown', () => {
    const event = makeEvent({
      kind: CASHU_MINT_ANNOUNCEMENT_KIND,
      tags: [['d', 'mpubkey'], ['u', 'https://MINT.EXAMPLE.COM:443/']],
      content: '',
    });
    const parsed = parseMintAnnouncement(event);
    expect(parsed!.mintUrl).toBe('https://mint.example.com');
    expect(parsed!.network).toBe('unknown');
  });
});

describe('parseMintRecommendation', () => {
  it('returns null for wrong kind', () => {
    const event = makeEvent({ kind: 1, tags: [['k', '38172'], ['d', 'mpubkey'], ['u', 'https://mint.example.com']], content: 'great' });
    expect(parseMintRecommendation(event)).toBeNull();
  });

  it('returns null when k-tag is not 38172', () => {
    const event = makeEvent({
      kind: CASHU_MINT_RECOMMENDATION_KIND,
      tags: [['k', '38173'], ['d', 'mpubkey'], ['u', 'https://mint.example.com']],
      content: '',
    });
    expect(parseMintRecommendation(event)).toBeNull();
  });

  it('parses a valid recommendation with rating and address pointer', () => {
    const event = makeEvent({
      kind: CASHU_MINT_RECOMMENDATION_KIND,
      tags: [
        ['k', '38172'],
        ['d', 'mpubkey'],
        ['u', 'https://mint.example.com'],
        ['a', '38172:mpubkey:', 'wss://relay'],
        ['rating', '5'],
      ],
      content: 'Reliable mint.',
    });
    const parsed = parseMintRecommendation(event);
    expect(parsed).not.toBeNull();
    expect(parsed!.mintId).toBe('mpubkey');
    expect(parsed!.mintUrls).toEqual(['https://mint.example.com']);
    expect(parsed!.addressPointers).toEqual([{ coordinate: '38172:mpubkey:', relayHint: 'wss://relay' }]);
    expect(parsed!.rating).toBe(5);
    expect(parsed!.content).toBe('Reliable mint.');
  });

  it('deduplicates and normalizes mint URLs', () => {
    const event = makeEvent({
      kind: CASHU_MINT_RECOMMENDATION_KIND,
      tags: [
        ['k', '38172'],
        ['d', 'mpubkey'],
        ['u', 'https://mint.example.com/'],
        ['u', 'https://mint.example.com'],
      ],
      content: '',
    });
    const parsed = parseMintRecommendation(event);
    expect(parsed!.mintUrls).toEqual(['https://mint.example.com']);
  });
});

describe('groupRecommendationsByUrl', () => {
  it('groups recommendations by URL', () => {
    const r1: CashuMintRecommendation = {
      event: makeEvent({ kind: CASHU_MINT_RECOMMENDATION_KIND }),
      author: 'a1',
      mintId: 'm1',
      mintUrls: ['https://mint.one'],
      addressPointers: [],
      rating: undefined,
      content: '',
    };
    const r2: CashuMintRecommendation = {
      event: makeEvent({ kind: CASHU_MINT_RECOMMENDATION_KIND }),
      author: 'a2',
      mintId: 'm2',
      mintUrls: ['https://mint.one', 'https://mint.two'],
      addressPointers: [],
      rating: undefined,
      content: '',
    };
    const grouped = groupRecommendationsByUrl([r1, r2]);
    expect(grouped['https://mint.one']).toHaveLength(2);
    expect(grouped['https://mint.two']).toHaveLength(1);
  });
});

describe('buildMintRecommendationEvent', () => {
  it('builds a minimal recommendation event', () => {
    const event = buildMintRecommendationEvent({
      mintId: 'mpubkey',
      mintUrl: 'https://mint.example.com',
    });
    expect(event.kind).toBe(CASHU_MINT_RECOMMENDATION_KIND);
    expect(event.content).toBe('');
    expect(event.tags).toEqual([
      ['d', 'mpubkey'],
      ['k', '38172'],
      ['u', 'https://mint.example.com'],
    ]);
  });

  it('includes rating and address coordinate when provided', () => {
    const event = buildMintRecommendationEvent({
      mintId: 'mpubkey',
      mintUrl: 'https://mint.example.com',
      announcementCoordinate: '38172:operator:mpubkey',
      rating: 4,
      content: 'Solid mint.',
    });
    expect(event.tags).toEqual([
      ['d', 'mpubkey'],
      ['k', '38172'],
      ['u', 'https://mint.example.com'],
      ['a', '38172:operator:mpubkey'],
      ['rating', '4'],
    ]);
    expect(event.content).toBe('Solid mint.');
  });

  it('rejects invalid ratings', () => {
    expect(() => buildMintRecommendationEvent({ mintId: 'mpubkey', mintUrl: 'https://mint.example.com', rating: 0 })).toThrow();
    expect(() => buildMintRecommendationEvent({ mintId: 'mpubkey', mintUrl: 'https://mint.example.com', rating: 6 })).toThrow();
    expect(() => buildMintRecommendationEvent({ mintId: 'mpubkey', mintUrl: 'https://mint.example.com', rating: 3.5 })).toThrow();
  });

  it('rejects missing mint id or url', () => {
    expect(() => buildMintRecommendationEvent({ mintId: '', mintUrl: 'https://mint.example.com' })).toThrow();
    expect(() => buildMintRecommendationEvent({ mintId: 'mpubkey', mintUrl: '' })).toThrow();
  });
});
