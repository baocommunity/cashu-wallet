// NUT-16 (UR animated-QR encoding) — node-only module (bc-ur + Buffer),
// imported via the './nut16' subpath; kept out of the browser barrel.
import { describe, expect, it } from 'vitest';
import { getEncodedToken } from '@cashu/cashu-ts';
import { CashuUrDecoder, CashuUrEncoder, CASHU_UR_PREFIX } from './nut16';

const TOKEN = getEncodedToken({
  mint: 'https://mint.example.com',
  proofs: [{ id: '00' + '0'.repeat(62), amount: 10, secret: 's', C: '02' + '0'.repeat(64) }],
  unit: 'sat',
});

describe('CashuUrEncoder/Decoder (NUT-16, node-only)', () => {
  it('round-trips a token through UR fragments', () => {
    const enc = new CashuUrEncoder(TOKEN);
    expect(enc.partCount).toBeGreaterThanOrEqual(1);
    const dec = new CashuUrDecoder();
    let result = null;
    for (let i = 0; i < enc.partCount; i += 1) {
      result = dec.receive(enc.nextPart());
    }
    expect(result?.complete).toBe(true);
    expect(result?.token).toBe(TOKEN);
  });
  it('fragments carry the ur:bytes/ prefix', () => {
    const enc = new CashuUrEncoder(TOKEN);
    const part = enc.nextPart();
    expect(part.toLowerCase().startsWith(CASHU_UR_PREFIX)).toBe(true);
  });
  it('rejects non-cashu tokens at encode time', () => {
    expect(() => new CashuUrEncoder('nonsense')).toThrow(/valid serialized/);
  });
});
