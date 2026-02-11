import { sanitizeForTerminal } from "../core/sanitize.js";
import type { SecureBuffer } from "../core/secure-buffer.js";
import { KeyProvider, type VerificationResult } from "../types/index.js";
import type { KeyVerifier } from "./verifier.js";

function makeOpenAIVerifier(provider: KeyProvider): KeyVerifier {
  return {
    provider,
    endpoint: "https://api.openai.com/v1/models",
    description: "Lists available models (read-only)",

    async verify(secret: SecureBuffer): Promise<VerificationResult> {
      const key = secret.unsafeGetString();
      try {
        const response = await fetch("https://api.openai.com/v1/models", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${key}`,
            "User-Agent": "compromising-position/1.0.0",
          },
        });

        if (response.status === 200) {
          return {
            provider,
            active: true,
            details: "Key is active — authenticated to OpenAI API",
            error: null,
            endpoint: "https://api.openai.com/v1/models",
          };
        }

        if (response.status === 401) {
          return {
            provider,
            active: false,
            details: "Key is invalid or revoked",
            error: null,
            endpoint: "https://api.openai.com/v1/models",
          };
        }

        return {
          provider,
          active: false,
          details: `Unexpected status: ${response.status}`,
          error: `OpenAI API returned ${response.status}: ${sanitizeForTerminal(response.statusText)}`,
          endpoint: "https://api.openai.com/v1/models",
        };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          provider,
          active: false,
          details: "Verification failed",
          error: `Network error: ${sanitizeForTerminal(message)}`,
          endpoint: "https://api.openai.com/v1/models",
        };
      }
    },
  };
}

export const openaiVerifier = makeOpenAIVerifier(KeyProvider.OpenAI);
export const openaiServiceVerifier = makeOpenAIVerifier(KeyProvider.OpenAIService);
