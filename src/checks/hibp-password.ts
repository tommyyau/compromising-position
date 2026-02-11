import { timingSafeEqual } from "node:crypto";
import type { SecureBuffer } from "../core/secure-buffer.js";
import type { HibpPasswordResult } from "../types/index.js";

const HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/";
const PREFIX_LENGTH = 5;
const USER_AGENT = "compromising-position/1.0.0";

/**
 * Check a secret against the HIBP Pwned Passwords API using k-anonymity.
 *
 * Only the first 5 characters of the SHA-1 hash are sent to the server.
 * The remaining 35 characters are compared locally using constant-time comparison.
 */
export async function checkHibpPassword(
  secret: SecureBuffer,
): Promise<HibpPasswordResult> {
  const sha1 = secret.sha1Hex();
  const prefix = sha1.slice(0, PREFIX_LENGTH);
  const suffix = sha1.slice(PREFIX_LENGTH);

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
        error: `HIBP API returned ${response.status}: ${response.statusText}`,
      };
    }

    const body = await response.text();
    const match = findMatchConstantTime(suffix, body);

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
      error: `Network error: ${message}`,
    };
  }
}

interface MatchResult {
  found: boolean;
  occurrences: number;
}

/**
 * Compare our suffix against all returned suffixes using constant-time comparison.
 * This prevents timing side-channels from leaking which suffix matched.
 */
function findMatchConstantTime(
  targetSuffix: string,
  responseBody: string,
): MatchResult {
  const targetBuffer = Buffer.from(targetSuffix.toUpperCase(), "utf-8");
  let found = false;
  let occurrences = 0;

  const lines = responseBody.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;

    const colonIndex = trimmed.indexOf(":");
    if (colonIndex === -1) continue;

    const entrySuffix = trimmed.slice(0, colonIndex);
    const count = parseInt(trimmed.slice(colonIndex + 1), 10);

    const entryBuffer = Buffer.from(entrySuffix.toUpperCase(), "utf-8");

    // Only compare if lengths match (avoids timingSafeEqual throwing)
    if (entryBuffer.length === targetBuffer.length) {
      if (timingSafeEqual(entryBuffer, targetBuffer)) {
        found = true;
        occurrences = count;
        // Don't break — continue iterating to maintain constant time
      }
    }
  }

  return { found, occurrences };
}
