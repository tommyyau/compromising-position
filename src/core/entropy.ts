import type { SecureBuffer } from "./secure-buffer.js";
import type { Encoding, EntropyResult } from "../types/index.js";

/**
 * Calculate Shannon entropy (bits per character) from a Buffer.
 * Operates on raw bytes to avoid creating an immutable string.
 */
export function shannonEntropyFromBuffer(buf: Buffer): number {
  if (buf.length === 0) return 0;

  const freq = new Map<number, number>();
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i]!;
    freq.set(byte, (freq.get(byte) ?? 0) + 1);
  }

  let entropy = 0;
  const len = buf.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/** Calculate Shannon entropy (bits per character) from a string. */
export function shannonEntropy(data: string): number {
  if (data.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of data) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }

  let entropy = 0;
  const len = data.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Detect the likely encoding of a buffer by examining byte values.
 */
export function detectEncodingFromBuffer(buf: Buffer): Encoding {
  let hasPlus = false;
  let hasSlash = false;
  let hasEquals = false;
  let hasUnderscore = false;
  let hasHyphen = false;
  let allHex = true;
  let allAlnum = true;
  let allBase64 = true;

  for (let i = 0; i < buf.length; i++) {
    const b = buf[i]!;
    const isDigit = b >= 0x30 && b <= 0x39;
    const isUpper = b >= 0x41 && b <= 0x5a;
    const isLower = b >= 0x61 && b <= 0x7a;
    const isHexLower = b >= 0x61 && b <= 0x66;
    const isHexUpper = b >= 0x41 && b <= 0x46;
    const isB64Special = b === 0x2b || b === 0x2f || b === 0x3d; // + / =

    if (b === 0x2b) hasPlus = true;
    else if (b === 0x2f) hasSlash = true;
    else if (b === 0x3d) hasEquals = true;
    else if (b === 0x5f) hasUnderscore = true;
    else if (b === 0x2d) hasHyphen = true;

    if (!(isDigit || isHexLower || isHexUpper)) allHex = false;
    if (!(isDigit || isUpper || isLower)) allAlnum = false;
    if (!(isDigit || isUpper || isLower || isB64Special)) allBase64 = false;
  }

  if (allHex && !hasPlus && !hasSlash && !hasEquals && !hasUnderscore && !hasHyphen) return "hex";
  if (allBase64 && (hasPlus || hasSlash || hasEquals)) return "base64";
  if (allAlnum && !hasUnderscore && !hasHyphen) return "base62";
  if (allAlnum || (!hasPlus && !hasSlash && !hasEquals)) {
    if (hasUnderscore || hasHyphen) return "alphanumeric";
  }
  return "mixed";
}

/** Detect the likely encoding of a string. */
export function detectEncoding(data: string): Encoding {
  if (/^[0-9a-fA-F]+$/.test(data)) return "hex";
  // base64 must contain +, /, or trailing = to distinguish from base62
  if (/^[A-Za-z0-9+/]+=+$/.test(data) || (/^[A-Za-z0-9+/=]+$/.test(data) && /[+/=]/.test(data)))
    return "base64";
  if (/^[A-Za-z0-9]+$/.test(data)) return "base62";
  if (/^[A-Za-z0-9_-]+$/.test(data)) return "alphanumeric";
  return "mixed";
}

/** Maximum possible Shannon entropy for a given alphabet size. */
function maxEntropy(alphabetSize: number): number {
  return alphabetSize > 0 ? Math.log2(alphabetSize) : 0;
}

function alphabetSizeForEncoding(encoding: Encoding): number {
  switch (encoding) {
    case "hex":
      return 16;
    case "base62":
      return 62;
    case "base64":
      return 64;
    case "alphanumeric":
      return 64; // includes _ and -
    case "mixed":
      return 95; // printable ASCII
  }
}

/**
 * Analyze entropy of a secret held in a SecureBuffer.
 * Uses Buffer-based operations to avoid creating long-lived strings.
 */
export function analyzeEntropyFromBuffer(secret: SecureBuffer): EntropyResult {
  const buf = secret.unsafeGetBuffer();
  // Trim whitespace bytes from the buffer for analysis
  let start = 0;
  let end = buf.length;
  while (start < end && (buf[start] === 0x20 || buf[start] === 0x09 || buf[start] === 0x0a || buf[start] === 0x0d)) start++;
  while (end > start && (buf[end - 1] === 0x20 || buf[end - 1] === 0x09 || buf[end - 1] === 0x0a || buf[end - 1] === 0x0d)) end--;

  const trimmed = buf.subarray(start, end);
  const len = trimmed.length;
  const entropy = shannonEntropyFromBuffer(trimmed);
  const encoding = detectEncodingFromBuffer(trimmed);
  const maxEnt = maxEntropy(alphabetSizeForEncoding(encoding));
  const normalized = maxEnt > 0 ? entropy / maxEnt : 0;

  let warning: string | null = null;
  if (len < 8) {
    warning = "Very short — likely not a real API key";
  } else if (entropy < 2.5) {
    warning = "Very low entropy — may be a placeholder or test value";
  } else if (entropy < 3.5 && len < 20) {
    warning = "Low entropy — consider whether this is a real secret";
  }

  return {
    shannonEntropy: Math.round(entropy * 1000) / 1000,
    maxPossibleEntropy: Math.round(maxEnt * 1000) / 1000,
    normalizedEntropy: Math.round(normalized * 1000) / 1000,
    encoding,
    length: len,
    warning,
  };
}

/** Analyze entropy of a string. */
export function analyzeEntropy(data: string): EntropyResult {
  const entropy = shannonEntropy(data);
  const encoding = detectEncoding(data);
  const maxEnt = maxEntropy(alphabetSizeForEncoding(encoding));
  const normalized = maxEnt > 0 ? entropy / maxEnt : 0;

  let warning: string | null = null;
  if (data.length < 8) {
    warning = "Very short — likely not a real API key";
  } else if (entropy < 2.5) {
    warning = "Very low entropy — may be a placeholder or test value";
  } else if (entropy < 3.5 && data.length < 20) {
    warning = "Low entropy — consider whether this is a real secret";
  }

  return {
    shannonEntropy: Math.round(entropy * 1000) / 1000,
    maxPossibleEntropy: Math.round(maxEnt * 1000) / 1000,
    normalizedEntropy: Math.round(normalized * 1000) / 1000,
    encoding,
    length: data.length,
    warning,
  };
}
