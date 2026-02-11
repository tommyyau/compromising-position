import { sanitizeForTerminal } from "../core/sanitize.js";
import type { SecureBuffer } from "../core/secure-buffer.js";
import { KeyProvider, type VerificationResult } from "../types/index.js";
import type { KeyVerifier } from "./verifier.js";

export const anthropicVerifier: KeyVerifier = {
  provider: KeyProvider.Anthropic,
  endpoint: "https://api.anthropic.com/v1/models",
  description: "Lists available models (read-only)",

  async verify(secret: SecureBuffer): Promise<VerificationResult> {
    const key = secret.unsafeGetString();
    try {
      const response = await fetch("https://api.anthropic.com/v1/models", {
        method: "GET",
        headers: {
          "x-api-key": key,
          "anthropic-version": "2023-06-01",
          "User-Agent": "compromising-position/1.0.0",
        },
      });

      if (response.status === 200) {
        return {
          provider: KeyProvider.Anthropic,
          active: true,
          details: "Key is active — authenticated to Anthropic API",
          error: null,
          endpoint: "https://api.anthropic.com/v1/models",
        };
      }

      if (response.status === 401) {
        return {
          provider: KeyProvider.Anthropic,
          active: false,
          details: "Key is invalid or revoked",
          error: null,
          endpoint: "https://api.anthropic.com/v1/models",
        };
      }

      return {
        provider: KeyProvider.Anthropic,
        active: false,
        details: `Unexpected status: ${response.status}`,
        error: `Anthropic API returned ${response.status}: ${sanitizeForTerminal(response.statusText)}`,
        endpoint: "https://api.anthropic.com/v1/models",
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        provider: KeyProvider.Anthropic,
        active: false,
        details: "Verification failed",
        error: `Network error: ${sanitizeForTerminal(message)}`,
        endpoint: "https://api.anthropic.com/v1/models",
      };
    }
  },
};
