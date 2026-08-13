import { afterEach, describe, expect, it, vi } from 'vitest';

import { createMintFetch } from './cashuFetch';

const mint = 'https://mint.example.com';
const info = {
  name: 'Mint',
  nuts: {
    '19': {
      ttl: 60,
      cached_endpoints: [{ method: 'POST', path: '/v1/swap' }],
    },
  },
};

describe('createMintFetch NUT-19 replay', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('replays an advertised endpoint once with a byte-identical request', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(info), { status: 200 }))
      .mockRejectedValueOnce(new TypeError('connection reset'))
      .mockResolvedValueOnce(new Response(JSON.stringify({ signatures: [] }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const request = createMintFetch([mint]);
    await request({ endpoint: `${mint}/v1/info` });

    await expect(request({
      endpoint: `${mint}/v1/swap`,
      method: 'POST',
      requestBody: { inputs: [{ amount: 21 }], outputs: [] },
      headers: { 'X-Test': 'same' },
    })).resolves.toEqual({ signatures: [] });

    const first = fetchMock.mock.calls[1] as [string, RequestInit];
    const replay = fetchMock.mock.calls[2] as [string, RequestInit];
    expect(replay[0]).toBe(first[0]);
    expect(replay[1].method).toBe(first[1].method);
    expect(replay[1].body).toBe(first[1].body);
    expect(replay[1].headers).toEqual(first[1].headers);
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('does not replay endpoints the mint did not advertise', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(info), { status: 200 }))
      .mockRejectedValueOnce(new TypeError('connection reset'));
    vi.stubGlobal('fetch', fetchMock);
    const request = createMintFetch([mint]);
    await request({ endpoint: `${mint}/v1/info` });

    await expect(request({ endpoint: `${mint}/v1/mint/bolt11`, method: 'POST', requestBody: { quote: 'q' } }))
      .rejects.toThrow('connection reset');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('replays once when a successful cached response body is unreadable', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(info), { status: 200 }))
      .mockResolvedValueOnce(new Response('{broken', { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ signatures: ['ok'] }), { status: 200 }));
    vi.stubGlobal('fetch', fetchMock);
    const request = createMintFetch([mint]);
    await request({ endpoint: `${mint}/v1/info` });

    await expect(request({ endpoint: `${mint}/v1/swap`, method: 'POST', requestBody: { inputs: [], outputs: [] } }))
      .resolves.toEqual({ signatures: ['ok'] });
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('never replays HTTP errors', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(info), { status: 200 }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ detail: 'bad request' }), { status: 400 }));
    vi.stubGlobal('fetch', fetchMock);
    const request = createMintFetch([mint]);
    await request({ endpoint: `${mint}/v1/info` });

    await expect(request({ endpoint: `${mint}/v1/swap`, method: 'POST', requestBody: { inputs: [], outputs: [] } }))
      .rejects.toThrow('bad request');
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
