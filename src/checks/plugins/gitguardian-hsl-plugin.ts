import { sanitizeForTerminal } from "../../core/sanitize.js";
import type { CheckPlugin } from "../plugin.js";
import type { SecureBuffer } from "../../core/secure-buffer.js";
import type { AppConfig, PluginCheckResult } from "../../types/index.js";

const GITGUARDIAN_BASE = "https://api.gitguardian.com/v1";
const USER_AGENT = "compromising-position/1.0.0";

interface HasMySecretLeakedResponse {
  /** Whether the secret was found in public GitHub repos. */
  matches: number;
}

export const gitGuardianHslPlugin: CheckPlugin = {
  id: "gitguardian-hsl",
  name: "GitGuardian HasMySecretLeaked",
  inputKind: "secret",
  requiresNetwork: true,
  requiredConfigKeys: ["GITGUARDIAN_API_TOKEN"],
  isFree: false,
  privacySummary: "SHA-256 hash -> api.gitguardian.com (requires API token)",

  async check(
    input: SecureBuffer | string,
    config: AppConfig,
  ): Promise<PluginCheckResult> {
    const secret = input as SecureBuffer;
    const apiToken = config.pluginApiKeys["GITGUARDIAN_API_TOKEN"];

    if (!apiToken) {
      return {
        pluginId: "gitguardian-hsl",
        pluginName: "GitGuardian HasMySecretLeaked",
        found: false,
        details: "GitGuardian API token not configured",
        severity: "info",
        error: "Missing GITGUARDIAN_API_TOKEN",
      };
    }

    // Only send the SHA-256 hash, not the actual secret
    const hash = secret.sha256Hex();

    try {
      const response = await fetch(
        `${GITGUARDIAN_BASE}/secret/has_secret_leaked`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Token ${apiToken}`,
            "User-Agent": USER_AGENT,
          },
          body: JSON.stringify({ hash }),
        },
      );

      if (!response.ok) {
        const statusText = sanitizeForTerminal(response.statusText);
        return {
          pluginId: "gitguardian-hsl",
          pluginName: "GitGuardian HasMySecretLeaked",
          found: false,
          details: `API error: ${response.status} ${statusText}`,
          severity: "info",
          error: `GitGuardian API returned ${response.status}: ${statusText}`,
        };
      }

      const data = (await response.json()) as HasMySecretLeakedResponse;
      const found = data.matches > 0;

      return {
        pluginId: "gitguardian-hsl",
        pluginName: "GitGuardian HasMySecretLeaked",
        found,
        details: found
          ? `Found in ${data.matches} public GitHub repo(s)`
          : "Not found in public GitHub repos",
        severity: found ? "critical" : "low",
        error: null,
        metadata: { matches: data.matches },
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        pluginId: "gitguardian-hsl",
        pluginName: "GitGuardian HasMySecretLeaked",
        found: false,
        details: `Network error: ${sanitizeForTerminal(message)}`,
        severity: "info",
        error: sanitizeForTerminal(message),
      };
    }
  },
};
