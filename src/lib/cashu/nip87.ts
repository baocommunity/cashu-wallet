import type { NostrEvent } from '@nostrify/nostrify';

import { normalizeMintUrl } from '@/lib/cashu/cashu';
import { sanitizeUrl } from '@/lib/sanitizeUrl';

/** Cashu mint announcement event kind (NIP-87). */
export const CASHU_MINT_ANNOUNCEMENT_KIND = 38172;

/** Cashu mint recommendation/review event kind (NIP-87). */
export const CASHU_MINT_RECOMMENDATION_KIND = 38000;

/** Fedimint announcement event kind (NIP-87) — not supported yet, but reserved. */
export const FEDIMINT_MINT_ANNOUNCEMENT_KIND = 38173;

export interface CashuMintAnnouncement {
  /** Original Nostr event. */
  event: NostrEvent;
  /** Mint pubkey / identifier (d-tag). */
  mintId: string;
  /** Normalized mint URL. */
  mintUrl: string;
  /** Network the mint runs on. */
  network: 'mainnet' | 'testnet' | 'signet' | 'regtest' | 'unknown';
  /** Supported Cashu NUTs as numbers. */
  nuts: number[];
  /** Optional kind-0-style metadata from content. */
  metadata: Record<string, unknown>;
}

export interface CashuMintRecommendation {
  /** Original Nostr event. */
  event: NostrEvent;
  /** Author pubkey (hex). */
  author: string;
  /** Mint identifier (d-tag of the recommended kind 38172). */
  mintId: string;
  /** Optional mint URL(s) from u-tags. */
  mintUrls: string[];
  /** Address pointer(s) to the kind 38172 event, with optional relay hint. */
  addressPointers: Array<{ coordinate: string; relayHint?: string }>;
  /** Optional numeric rating, if a `rating` tag is present. */
  rating: number | undefined;
  /** Review text from content. */
  content: string;
}

const VALID_NETWORKS = new Set(['mainnet', 'testnet', 'signet', 'regtest']);

function parseNutsTag(value: string | undefined): number[] {
  if (!value) return [];
  return value
    .split(',')
    .map((s) => Number(s.trim()))
    .filter((n) => Number.isInteger(n) && n > 0);
}

function parseMetadata(content: string): Record<string, unknown> {
  if (!content.trim()) return {};
  try {
    const parsed = JSON.parse(content) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  } catch {
    // ignore invalid JSON
  }
  return {};
}

/**
 * Parse a kind 38172 Cashu mint announcement event.
 *
 * Returns null if the event is missing a valid mint URL or d-tag.
 */
export function parseMintAnnouncement(event: NostrEvent): CashuMintAnnouncement | null {
  if (event.kind !== CASHU_MINT_ANNOUNCEMENT_KIND) return null;

  const mintId = event.tags.find((t) => t[0] === 'd')?.[1]?.trim();
  if (!mintId) return null;

  const rawUrl = event.tags.find((t) => t[0] === 'u')?.[1];
  const sanitized = sanitizeUrl(rawUrl);
  if (!sanitized) return null;

  const normalized = normalizeMintUrl(sanitized);
  if (!normalized) return null;

  const rawNetwork = event.tags.find((t) => t[0] === 'n')?.[1]?.toLowerCase() ?? 'unknown';
  const network = VALID_NETWORKS.has(rawNetwork)
    ? (rawNetwork as 'mainnet' | 'testnet' | 'signet' | 'regtest')
    : 'unknown';

  const nutsTag = event.tags.find((t) => t[0] === 'nuts')?.[1];
  const nuts = parseNutsTag(nutsTag);

  return {
    event,
    mintId,
    mintUrl: normalized,
    network,
    nuts,
    metadata: parseMetadata(event.content),
  };
}

function parseRating(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const n = Number(value);
  if (Number.isNaN(n)) return undefined;
  return n;
}

/**
 * Parse a kind 38000 Cashu mint recommendation/review event.
 *
 * Only accepts recommendations that target Cashu mints (`k:38172`).
 * Returns null if the event is missing a mint identifier or is not for Cashu.
 */
export function parseMintRecommendation(event: NostrEvent): CashuMintRecommendation | null {
  if (event.kind !== CASHU_MINT_RECOMMENDATION_KIND) return null;

  const kindTag = event.tags.find((t) => t[0] === 'k')?.[1];
  if (kindTag !== String(CASHU_MINT_ANNOUNCEMENT_KIND)) return null;

  const mintId = event.tags.find((t) => t[0] === 'd')?.[1]?.trim();
  if (!mintId) return null;

  const mintUrls: string[] = [];
  for (const t of event.tags) {
    if (t[0] === 'u' && t[1]) {
      const sanitized = sanitizeUrl(t[1]);
      if (sanitized) {
        const normalized = normalizeMintUrl(sanitized);
        if (normalized && !mintUrls.includes(normalized)) {
          mintUrls.push(normalized);
        }
      }
    }
  }

  const addressPointers = event.tags
    .filter((t): t is [string, string, ...string[]] => t[0] === 'a' && typeof t[1] === 'string')
    .map((t) => ({ coordinate: t[1], relayHint: t[2] }));

  const ratingTag = event.tags.find((t) => t[0] === 'rating')?.[1];
  const rating = parseRating(ratingTag);

  return {
    event,
    author: event.pubkey,
    mintId,
    mintUrls,
    addressPointers,
    rating,
    content: event.content.trim(),
  };
}

export interface MintRecommendationInput {
  /** Mint identifier (d-tag of the referenced kind 38172 event). */
  mintId: string;
  /** Normalized mint URL. */
  mintUrl: string;
  /** Optional NIP-33 address coordinate of the kind 38172 announcement. */
  announcementCoordinate?: string;
  /** Optional 1–5 star rating. */
  rating?: number;
  /** Review text. */
  content?: string;
}

/**
 * Build the event template for a kind 38000 Cashu mint recommendation/review.
 *
 * Does not sign or publish — use with `useNostrPublish`.
 */
export function buildMintRecommendationEvent(input: MintRecommendationInput): {
  kind: typeof CASHU_MINT_RECOMMENDATION_KIND;
  content: string;
  tags: string[][];
} {
  const { mintId, mintUrl, announcementCoordinate, rating, content = '' } = input;

  if (!mintId.trim()) throw new Error('Mint identifier is required');
  if (!mintUrl.trim()) throw new Error('Mint URL is required');
  if (rating !== undefined && (!Number.isInteger(rating) || rating < 1 || rating > 5)) {
    throw new Error('Rating must be an integer between 1 and 5');
  }

  const tags: string[][] = [
    ['d', mintId.trim()],
    ['k', String(CASHU_MINT_ANNOUNCEMENT_KIND)],
    ['u', mintUrl.trim()],
  ];

  if (announcementCoordinate) {
    tags.push(['a', announcementCoordinate.trim()]);
  }

  if (rating !== undefined) {
    tags.push(['rating', String(rating)]);
  }

  return {
    kind: CASHU_MINT_RECOMMENDATION_KIND,
    content: content.trim(),
    tags,
  };
}

/**
 * Group recommendations by normalized mint URL.
 *
 * Recommendations without a u-tag are skipped (they can't be tied to a concrete
 * mint endpoint without also fetching the referenced announcement).
 */
export function groupRecommendationsByUrl(
  recommendations: CashuMintRecommendation[],
): Record<string, CashuMintRecommendation[]> {
  const groups: Record<string, CashuMintRecommendation[]> = {};
  for (const r of recommendations) {
    for (const url of r.mintUrls) {
      if (!groups[url]) groups[url] = [];
      groups[url].push(r);
    }
  }
  return groups;
}
