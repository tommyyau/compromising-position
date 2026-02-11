import type { SecureBuffer } from "../core/secure-buffer.js";
import type { KeyProvider, VerificationResult } from "../types/index.js";

/**
 * Interface for active key verifiers.
 * Each verifier checks if a key is still active by making a
 * minimal read-only API call to the provider.
 *
 * IMPORTANT: Verifiers must only use read-only endpoints.
 * Never make write operations with user keys.
 */
export interface KeyVerifier {
  /** Which provider this verifier handles. */
  readonly provider: KeyProvider;

  /** The endpoint that will be called. Shown to the user for consent. */
  readonly endpoint: string;

  /** Human-readable description of what this verification does. */
  readonly description: string;

  /**
   * Verify if the key is currently active.
   * @param secret - The API key to verify.
   */
  verify(secret: SecureBuffer): Promise<VerificationResult>;
}
