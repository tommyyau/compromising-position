import { timingSafeEqual } from "node:crypto";
import type { SecureBuffer } from "../core/secure-buffer.js";
import { sanitizeForTerminal } from "../core/sanitize.js";
import type { HibpPasswordResult } from "../types/index.js";

const HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/";
const USER_AGENT = "compromising-position/1.0.0";

/**
 * Number of hex chars for the prefix (5 = 2.5 bytes of SHA-1).
 * This is the only portion transmitted to the HIBP server.
 */
const PREFIX_HEX_LENGTH = 5;

/** Number of hex chars for the suffix (35 = remaining SHA-1). */
const SUFFIX_HEX_LENGTH = 35;

/**
 * Check a secret against the HIBP Pwned Passwords API using k-anonymity.
 *
 * Only the first 5 characters of the SHA-1 hash are sent to the server.
 * The remaining 35 characters are compared locally using constant-time comparison.
 *
 * Uses Buffer-based SHA-1 computation to avoid leaving the full hash
 * as an immutable string on the V8 heap.
 */
export async function checkHibpPassword(
  secret: SecureBuffer,
): Promise<HibpPasswordResult> {
  // Compute SHA-1 as raw bytes (20 bytes), not a hex string.
  // This avoids leaving the full 40-char hex hash as an un-zeroable string.
  const sha1Buf = secret.sha1Buffer();

  // Extract prefix as hex for the API call (first 2.5 bytes = 5 hex chars).
  // We need to read 3 bytes and take the first 5 hex chars.
  const prefixBytes = sha1Buf.subarray(0, 3);
  const prefix = prefixBytes.toString("hex").toUpperCase().slice(0, PREFIX_HEX_LENGTH);

  // Build the suffix as a fixed-size uppercase hex Buffer for constant-time comparison.
  const suffixHex = sha1Buf.subarray(2).toString("hex").toUpperCase().slice(1); // skip first nibble (already in prefix)
  const suffixBuffer = Buffer.from(suffixHex, "utf-8");

  // Zero the raw SHA-1 buffer now that we've extracted what we need
  sha1Buf.fill(0);

  try {
    const response = await fetch(`${HIBP_RANGE_URL}${prefix}`, {
      headers: {
        "User-Agent": USER_AGENT,
        "Add-Padding": "true",
      },
    });

    if (!response.ok) {
      return {
        checked: true,
        found: false,
        occurrences: 0,
        hashPrefix: prefix,
        error: `HIBP API returned ${response.status}: ${sanitizeForTerminal(response.statusText)}`,
      };
    }

    const body = await response.text();
    const match = findMatchConstantTime(suffixBuffer, body);

    return {
      checked: true,
      found: match.found,
      occurrences: match.occurrences,
      hashPrefix: prefix,
      error: null,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      checked: true,
      found: false,
      occurrences: 0,
      hashPrefix: prefix,
      error: `Network error: ${sanitizeForTerminal(message)}`,
    };
  } finally {
    // Zero the suffix buffer
    suffixBuffer.fill(0);
  }
}

interface MatchResult {
  found: boolean;
  occurrences: number;
}

/**
 * Compare our suffix against all returned suffixes using constant-time comparison.
 *
 * Every entry is compared with timingSafeEqual regardless of length match.
 * Entries that don't match the expected length are padded to avoid skipping
 * the comparison (which would create a timing side-channel).
 *
 * The loop never breaks early. Result variables are updated using the same
 * code path on every iteration to minimize data-dependent timing variance.
 */
function findMatchConstantTime(
  targetSuffix: Buffer,
  responseBody: string,
): MatchResult {
  const targetLen = targetSuffix.length;
  let found = false;
  let occurrences = 0;

  const lines = responseBody.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;

    const colonIndex = trimmed.indexOf(":");
    if (colonIndex === -1) continue;

    const entrySuffix = trimmed.slice(0, colonIndex);
    const countStr = trimmed.slice(colonIndex + 1);
    const count = parseInt(countStr, 10);

    // Skip entries with invalid count (NaN, negative)
    if (Number.isNaN(count) || count < 0) continue;

    // Pad or truncate entry to target length so we always call timingSafeEqual.
    // This avoids a length-dependent branch that skips the comparison.
    const entryBuf = Buffer.alloc(targetLen);
    const entryRaw = Buffer.from(entrySuffix.toUpperCase(), "utf-8");
    entryRaw.copy(entryBuf, 0, 0, Math.min(entryRaw.length, targetLen));

    const lengthMatch = entryRaw.length === targetLen;
    const bytesMatch = timingSafeEqual(entryBuf, targetSuffix);

    // Both length and content must match. Use branchless-style update:
    // always evaluate both conditions, never break early.
    if (lengthMatch && bytesMatch) {
      found = true;
      occurrences = count;
    }
  }

  return { found, occurrences };
}
