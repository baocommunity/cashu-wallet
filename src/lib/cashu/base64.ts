/**
 * Small, typed base64 utilities that do not rely on the legacy DOM helpers.
 *
 * These helpers avoid the Latin1-only limitation of the legacy DOM base64
 * functions and work in all JavaScript runtimes (browser, Node, test).
 */

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const BASE64_REVERSE: Record<string, number> = (() => {
  const map: Record<string, number> = {};
  for (let i = 0; i < BASE64_ALPHABET.length; i++) {
    map[BASE64_ALPHABET[i]] = i;
  }
  return map;
})();

/** Encode raw bytes as standard base64 (with padding). */
export function bytesToBase64(bytes: Uint8Array): string {
  const len = bytes.length;
  let result = '';
  for (let i = 0; i < len; i += 3) {
    const b1 = bytes[i];
    const b2 = i + 1 < len ? bytes[i + 1] : 0;
    const b3 = i + 2 < len ? bytes[i + 2] : 0;
    const bitmap = (b1 << 16) | (b2 << 8) | b3;
    result += BASE64_ALPHABET[(bitmap >> 18) & 63];
    result += BASE64_ALPHABET[(bitmap >> 12) & 63];
    result += i + 1 < len ? BASE64_ALPHABET[(bitmap >> 6) & 63] : '=';
    result += i + 2 < len ? BASE64_ALPHABET[bitmap & 63] : '=';
  }
  return result;
}

/** Decode a standard base64 string (with or without padding) to raw bytes. */
export function base64ToBytes(b64: string): Uint8Array<ArrayBuffer> {
  // Strip whitespace/newlines — tolerates the same inputs as the legacy decoder.
  const clean = b64.replace(/[^A-Za-z0-9+/=]/g, '');
  const len = clean.length;
  if (len % 4 !== 0) {
    throw new Error('Invalid base64 string');
  }
  let padding = 0;
  if (clean.endsWith('==')) {
    padding = 2;
  } else if (clean.endsWith('=')) {
    padding = 1;
  }
  const outLen = (len * 3) / 4 - padding;
  const out = new Uint8Array(new ArrayBuffer(outLen)) as Uint8Array<ArrayBuffer>;
  let j = 0;
  for (let i = 0; i < len; i += 4) {
    const c1 = BASE64_REVERSE[clean[i]] ?? 0;
    const c2 = BASE64_REVERSE[clean[i + 1]] ?? 0;
    const c3 = BASE64_REVERSE[clean[i + 2]] ?? 0;
    const c4 = BASE64_REVERSE[clean[i + 3]] ?? 0;
    const bitmap = (c1 << 18) | (c2 << 12) | (c3 << 6) | c4;
    if (j < outLen) out[j++] = (bitmap >> 16) & 255;
    if (j < outLen) out[j++] = (bitmap >> 8) & 255;
    if (j < outLen) out[j++] = bitmap & 255;
  }
  return out;
}

/** Encode raw bytes as URL-safe base64 (no `+`, no `/`, no padding `=`). */
export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/** Decode a URL-safe base64 string to raw bytes. */
export function base64UrlToBytes(b64url: string): Uint8Array {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padLength = (4 - (b64.length % 4)) % 4;
  b64 = b64.padEnd(b64.length + padLength, '=');
  return base64ToBytes(b64);
}

/**
 * Encode a Unicode string the same way the legacy DOM helpers did
 * (encodeURIComponent, then base64).
 *
 * This preserves backward compatibility with existing stored keys that were
 * created with the old DOM helpers.
 */
export function stringToBase64(str: string): string {
  return bytesToBase64(new TextEncoder().encode(encodeURIComponent(str)));
}

/**
 * Decode a base64 string to a Unicode string the same way the legacy DOM helpers did
 * (base64, then decodeURIComponent).
 *
 * This preserves backward compatibility with existing stored keys that were
 * created with the old DOM helpers.
 */
export function base64ToString(b64: string): string {
  return decodeURIComponent(new TextDecoder().decode(base64ToBytes(b64)));
}
