/**
 * Development-only logger.
 * All logging is stripped in production builds to avoid leaking
 * internal state or errors to the browser console.
 */

const isDev = typeof import.meta !== 'undefined' && !!import.meta.env?.DEV;
const con = isDev ? globalThis.console : null;

export const devLog = {
  log: (...args: unknown[]): void => {
    if (isDev) con?.log(...args);
  },
  warn: (...args: unknown[]): void => {
    if (isDev) con?.warn(...args);
  },
  error: (...args: unknown[]): void => {
    if (isDev) con?.error(...args);
  },
};
