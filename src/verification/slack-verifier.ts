import { sanitizeForTerminal } from "../core/sanitize.js";
import type { SecureBuffer } from "../core/secure-buffer.js";
import { KeyProvider, type VerificationResult } from "../types/index.js";
import type { KeyVerifier } from "./verifier.js";

function makeSlackVerifier(provider: KeyProvider): KeyVerifier {
  return {
    provider,
    endpoint: "https://slack.com/api/auth.test",
    description: "Calls auth.test to check if token is active (read-only)",

    async verify(secret: SecureBuffer): Promise<VerificationResult> {
      const key = secret.unsafeGetString();
      try {
        const response = await fetch("https://slack.com/api/auth.test", {
          method: "POST",
          headers: {
            Authorization: `Bearer ${key}`,
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "compromising-position/1.0.0",
          },
        });

        if (!response.ok) {
          return {
            provider,
            active: false,
            details: `Unexpected HTTP status: ${response.status}`,
            error: `Slack API returned ${response.status}: ${sanitizeForTerminal(response.statusText)}`,
            endpoint: "https://slack.com/api/auth.test",
          };
        }

        const data = (await response.json()) as {
          ok: boolean;
          team?: string;
          user?: string;
          error?: string;
        };

        if (data.ok) {
          const info = [
            data.team ? `team: ${sanitizeForTerminal(data.team)}` : null,
            data.user ? `user: ${sanitizeForTerminal(data.user)}` : null,
          ]
            .filter(Boolean)
            .join(", ");

          return {
            provider,
            active: true,
            details: `Key is active — ${info || "authenticated to Slack"}`,
            error: null,
            endpoint: "https://slack.com/api/auth.test",
          };
        }

        return {
          provider,
          active: false,
          details: `Key is invalid: ${sanitizeForTerminal(data.error ?? "unknown error")}`,
          error: null,
          endpoint: "https://slack.com/api/auth.test",
        };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return {
          provider,
          active: false,
          details: "Verification failed",
          error: `Network error: ${sanitizeForTerminal(message)}`,
          endpoint: "https://slack.com/api/auth.test",
        };
      }
    },
  };
}

export const slackBotVerifier = makeSlackVerifier(KeyProvider.SlackBot);
export const slackUserVerifier = makeSlackVerifier(KeyProvider.SlackUser);
