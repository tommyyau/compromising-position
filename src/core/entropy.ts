import type { Encoding, EntropyResult } from "../types/index.js";

/** Calculate Shannon entropy (bits per character). */
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

/** Detect the likely encoding of a string. */
export function detectEncoding(data: string): Encoding {
  if (/^[0-9a-fA-F]+$/.test(data)) return "hex";
  // base64 must contain +, /, or trailing = to distinguish from base62
  if (/^[A-Za-z0-9+/]+=+$/.test(data) || /^[A-Za-z0-9+/]*[+/][A-Za-z0-9+/=]*$/.test(data))
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

/** Analyze entropy of a secret and produce warnings. */
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
