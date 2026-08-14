/**
 * SSRF-hardened fetch wrapper for Cashu mint communication.
 *
 * cashu-ts exposes a pluggable `request` function to CashuMint/CashuWallet.
 * This module provides a factory that returns a request function which:
 *   - re-validates every request URL against the allowed-mint list,
 *   - forces `redirect: 'manual'` so mints cannot redirect us elsewhere,
 *   - rejects 3xx responses before any response body is read,
 *   - attaches a per-request abort timeout so network calls cannot hang forever.
 */
import { isAllowedMintUrl } from './cashu';
import { devLog } from './devLog';

export type MintRequestOptions = {
  endpoint: string;
  requestBody?: Record<string, unknown>;
  headers?: Record<string, string>;
} & Omit<RequestInit, 'body' | 'headers'>;

const DEFAULT_REQUEST_TIMEOUT_MS = 120_000;

interface Nut19Policy {
  ttl: number;
  endpoints: Set<string>;
}

function readNut19Policy(value: unknown): Nut19Policy | null {
  if (!value || typeof value !== 'object') return null;
  const nuts = (value as { nuts?: unknown }).nuts;
  if (!nuts || typeof nuts !== 'object') return null;
  const nut19 = (nuts as Record<string, unknown>)['19'];
  if (!nut19 || typeof nut19 !== 'object') return null;
  const { ttl, cached_endpoints: cachedEndpoints } = nut19 as {
    ttl?: unknown;
    cached_endpoints?: unknown;
  };
  if (!Number.isSafeInteger(ttl) || (ttl as number) <= 0 || !Array.isArray(cachedEndpoints)) return null;
  const endpoints = new Set<string>();
  for (const entry of cachedEndpoints) {
    if (!entry || typeof entry !== 'object') continue;
    const method = (entry as { method?: unknown }).method;
    const path = (entry as { path?: unknown }).path;
    if (typeof method === 'string' && typeof path === 'string' && path.startsWith('/')) {
      endpoints.add(`${method.toUpperCase()} ${path}`);
    }
  }
  return endpoints.size > 0 ? { ttl: ttl as number, endpoints } : null;
}

function isAllowedMintEndpoint(endpoint: string, allowedUrls: string[]): boolean {
  if (!isAllowedMintUrl(endpoint)) return false;
  if (allowedUrls.length === 0) return true;
  try {
    const u = new URL(endpoint);
    return allowedUrls.some((allowed) => {
      try {
        const a = new URL(allowed);
        const basePath = a.pathname.replace(/\/+$/, '');
        const endpointPath = u.pathname;
        const endpointPathLower = endpointPath.toLowerCase();
        const basePathLower = basePath.toLowerCase();
        const isPathMatch =
          endpointPathLower === basePathLower ||
          endpointPathLower.startsWith(basePathLower + '/');
        return (
          u.protocol === a.protocol &&
          u.host.toLowerCase() === a.host.toLowerCase() &&
          isPathMatch
        );
      } catch {
        return false;
      }
    });
  } catch {
    return false;
  }
}

/**
 * Create a Cashu-compatible request function hardened against SSRF and
 * unwanted redirects.
 *
 * @param allowedUrls Known mint base URLs that requests are allowed to target.
 */
export function createMintFetch(allowedUrls: string[]) {
  let nut19Policy: Nut19Policy | null = null;

  return async function mintFetch<T>(options: MintRequestOptions): Promise<T> {
    const { endpoint, requestBody, headers, ...rest } = options;

    if (!isAllowedMintEndpoint(endpoint, allowedUrls)) {
      throw new Error(`Mint URL is not allowed: ${endpoint}`);
    }

    const body = requestBody ? JSON.stringify(requestBody) : undefined;
    const method = (rest.method ?? 'GET').toUpperCase();
    const endpointPath = new URL(endpoint).pathname;
    const canReplay = () => nut19Policy !== null && [...nut19Policy.endpoints].some((cached) => {
      const separator = cached.indexOf(' ');
      const cachedMethod = cached.slice(0, separator);
      const cachedPath = cached.slice(separator + 1);
      return cachedMethod === method && (endpointPath === cachedPath || endpointPath.endsWith(cachedPath));
    });
    const requestHeaders = {
      Accept: 'application/json, text/plain, */*',
      ...(body ? { 'Content-Type': 'application/json' } : undefined),
      ...headers,
    };

    const requestOnce = async (): Promise<Response> => fetch(endpoint, {
        ...rest,
        method,
        headers: requestHeaders,
        body,
        // A fresh timeout is required for the one allowed replay; a timed-out
        // AbortSignal cannot be reused. Explicit caller signals stay singular.
        signal: rest.signal ?? AbortSignal.timeout(DEFAULT_REQUEST_TIMEOUT_MS),
        redirect: 'manual',
      });

    let replayed = false;
    let response: Response;
    for (;;) {
      try {
        response = await requestOnce();
        break;
      } catch (err: unknown) {
        if (!replayed && !rest.signal && canReplay()) {
          replayed = true;
          continue;
        }
        if (err && typeof err === 'object' && (err as { name?: string }).name === 'AbortError') {
          throw new Error('Mint request was aborted');
        }
        devLog.warn('Mint network request failed:', endpoint, err);
        throw new Error(err instanceof Error ? err.message : 'Network request failed');
      }
    }

    if (response.status >= 300 && response.status < 400) {
      throw new Error(`Mint redirect blocked (${response.status})`);
    }

    if (!response.ok) {
      let detail: string;
      try {
        const json = await response.json();
        detail =
          (json && typeof json.detail === 'string' && json.detail) ||
          (json && typeof json.error === 'string' && json.error) ||
          `HTTP ${response.status}`;
      } catch {
        detail = `HTTP ${response.status}`;
      }
      throw new Error(detail);
    }

    for (;;) {
      try {
        const result = (await response.json()) as T;
        const discovered = readNut19Policy(result);
        if (discovered) nut19Policy = discovered;
        return result;
      } catch (err: unknown) {
        if (!replayed && !rest.signal && canReplay()) {
          replayed = true;
          try {
            response = await requestOnce();
          } catch (retryErr: unknown) {
            devLog.warn('Mint NUT-19 replay failed:', endpoint, retryErr);
            throw new Error(retryErr instanceof Error ? retryErr.message : 'Network request failed');
          }
          if (!response.ok) throw new Error(`HTTP ${response.status}`);
          continue;
        }
        devLog.warn('Mint returned non-JSON response:', endpoint, err);
        throw new Error('Mint returned an invalid response');
      }
    }
  };
}
