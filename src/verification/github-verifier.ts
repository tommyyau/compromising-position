import { sanitizeForTerminal } from "../core/sanitize.js";
import type { SecureBuffer } from "../core/secure-buffer.js";
import { KeyProvider, type VerificationResult } from "../types/index.js";
import type { KeyVerifier } from "./verifier.js";

/** Handles both classic PATs (ghp_) and fine-grained tokens (github_pat_). */
function makeGitHubVerifier(provider: KeyProvider): KeyVerifier {
  return {
    provider,
    endpoint: "https://api.github.com/user",
    description: "Gets authenticated user info and scopes (read-only)",

    async verify(secret: SecureBuffer): Promise<VerificationResult> {
      const key = secret.unsafeGetString();
      try {
        const response = await fetch("https://api.github.com/user", {
          method: "GET",
          headers: {
            Authorization: `Bearer ${key}`,
            "User-Agent": "compromising-position/1.0.0",
            Accept: "application/vnd.github+json",
          },
        });

        if (response.status === 200) {
          const scopes = response.headers.get("x-oauth-scopes") ?? "none";
          return {
            provider,
            active: true,
            details: `Key is active — scopes: ${sanitizeForTerminal(scopes)}`,
            error: null,
            endpoint: "https://api.github.com/user",
          };
        }

        if (response.status === 401) {
          return {
            provider,
            active: false,
            details: "Key is invalid or revoked",
            error: null,
            endpoint: "https://api.github.com/user",
          };
        }

        return {
          provider,
          active: false,
          details: `Unexpected status: ${response.status}`,
          error: `GitHub API returned ${response.status}: ${sanitizeForTerminal(response.statusText)}`,
          endpoint: "https://api.github.com/user",
        };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          provider,
          active: false,
          details: "Verification failed",
          error: `Network error: ${sanitizeForTerminal(message)}`,
          endpoint: "https://api.github.com/user",
        };
      }
    },
  };
}

export const githubPatVerifier = makeGitHubVerifier(KeyProvider.GitHubPAT);
export const githubFineGrainedVerifier = makeGitHubVerifier(KeyProvider.GitHubFineGrained);
