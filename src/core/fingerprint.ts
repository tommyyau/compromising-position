import type { SecureBuffer } from "./secure-buffer.js";

/** Number of hex characters to keep from SHA-256 for audit fingerprint. */
const FINGERPRINT_LENGTH = 16;

/**
 * Generate a truncated SHA-256 fingerprint for audit logging.
 * Returns first 16 hex chars — enough for identification, not enough to reverse.
 */
export function fingerprint(secret: SecureBuffer): string {
  return secret.sha256Hex().slice(0, FINGERPRINT_LENGTH);
}
