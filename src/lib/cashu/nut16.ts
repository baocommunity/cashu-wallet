import { Buffer } from 'buffer';
import { UR, URDecoder, UREncoder } from '@ngraveio/bc-ur';

import { decodeCashuToken } from './cashu';

export const CASHU_UR_PREFIX = 'ur:bytes/';
export const CASHU_UR_FRAGMENT_LENGTH = 200;
export const CASHU_UR_MAX_TOKEN_BYTES = 100_000;
export const CASHU_UR_MAX_PARTS = 512;
export const CASHU_UR_MAX_SCANNED_FRAMES = 2_048;
export const CASHU_UR_SCAN_TIMEOUT_MS = 2 * 60_000;

/** NUT-16 recommends animation once a token has more than two proofs. The
 * byte cap also catches long scripts, memos, and mint URLs. */
export function shouldAnimateCashuToken(token: string): boolean {
  if (new TextEncoder().encode(token).byteLength > 900) return true;
  const entries = decodeCashuToken(token);
  return (entries?.reduce((count, entry) => count + entry.proofs.length, 0) ?? 0) > 2;
}

export class CashuUrEncoder {
  private readonly encoder: UREncoder;

  constructor(token: string) {
    const bytes = new TextEncoder().encode(token);
    if (!token.startsWith('cashu') || !decodeCashuToken(token)) {
      throw new Error('Only valid serialized Cashu tokens can be encoded.');
    }
    if (bytes.byteLength > CASHU_UR_MAX_TOKEN_BYTES) {
      throw new Error('Cashu token is too large for animated QR transfer.');
    }
    this.encoder = new UREncoder(UR.fromBuffer(Buffer.from(bytes)), CASHU_UR_FRAGMENT_LENGTH, 0);
    if (this.encoder.fragmentsLength > CASHU_UR_MAX_PARTS) {
      throw new Error('Cashu token requires too many animated QR fragments.');
    }
  }

  get partCount(): number {
    return this.encoder.fragmentsLength;
  }

  nextPart(): string {
    return this.encoder.nextPart();
  }
}

export interface CashuUrScanProgress {
  complete: boolean;
  progress: number;
  token?: string;
}

/** Stateful, bounded NUT-16 decoder. Use one instance per scanner dialog so
 * fragments from separate transfers can never mix. */
export class CashuUrDecoder {
  private readonly decoder = new URDecoder();
  private readonly startedAt = Date.now();
  private frames = 0;

  receive(part: string): CashuUrScanProgress {
    if (Date.now() - this.startedAt > CASHU_UR_SCAN_TIMEOUT_MS) {
      throw new Error('Animated QR scan timed out. Start again.');
    }
    if (++this.frames > CASHU_UR_MAX_SCANNED_FRAMES) {
      throw new Error('Animated QR scan exceeded the safe frame limit.');
    }
    if (part.length > 4_096 || !part.toLowerCase().startsWith(CASHU_UR_PREFIX)) {
      throw new Error('This is not a Cashu NUT-16 QR fragment.');
    }

    this.decoder.receivePart(part);
    if (!this.decoder.isComplete()) {
      const estimated = Number(this.decoder.estimatedPercentComplete());
      return {
        complete: false,
        progress: Number.isFinite(estimated) ? Math.max(0, Math.min(99, Math.round(estimated * 100))) : 0,
      };
    }
    if (!this.decoder.isSuccess()) {
      throw new Error(this.decoder.resultError() || 'Animated QR could not be decoded.');
    }

    const bytes = this.decoder.resultUR().decodeCBOR();
    if (bytes.byteLength > CASHU_UR_MAX_TOKEN_BYTES) {
      throw new Error('Decoded Cashu token exceeds the safe size limit.');
    }
    const token = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    if (!token.startsWith('cashu') || !decodeCashuToken(token)) {
      throw new Error('Animated QR did not contain a valid Cashu token.');
    }
    return { complete: true, progress: 100, token };
  }
}
