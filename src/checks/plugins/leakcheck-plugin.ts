import { sanitizeForTerminal } from "../../core/sanitize.js";
import type { CheckPlugin } from "../plugin.js";
import type { AppConfig, PluginCheckResult } from "../../types/index.js";

const LEAKCHECK_BASE = "https://leakcheck.io/api/v2/query";
const USER_AGENT = "compromising-position/1.0.0";

interface LeakCheckSource {
  name: string;
  date: string;
}

interface LeakCheckResponse {
  success: boolean;
  found: number;
  sources: LeakCheckSource[];
}

export const leakCheckPlugin: CheckPlugin = {
  id: "leakcheck",
  name: "LeakCheck",
  inputKind: "email",
  requiresNetwork: true,
  requiredConfigKeys: ["LEAKCHECK_API_KEY"],
  isFree: false,
  privacySummary: "Full email -> leakcheck.io (requires paid API key)",

  async check(
    input: unknown,
    config: AppConfig,
  ): Promise<PluginCheckResult> {
    const email = input as string;
    const apiKey = config.pluginApiKeys["LEAKCHECK_API_KEY"];

    if (!apiKey) {
      return {
        pluginId: "leakcheck",
        pluginName: "LeakCheck",
        found: false,
        details: "LeakCheck API key not configured",
        severity: "info",
        error: "Missing LEAKCHECK_API_KEY",
      };
    }

    try {
      const response = await fetch(
        `${LEAKCHECK_BASE}/${encodeURIComponent(email)}`,
        {
          headers: {
            Accept: "application/json",
            "X-API-Key": apiKey,
            "User-Agent": USER_AGENT,
          },
        },
      );

      if (!response.ok) {
        const statusText = sanitizeForTerminal(response.statusText);
        return {
          pluginId: "leakcheck",
          pluginName: "LeakCheck",
          found: false,
          details: `API error: ${response.status} ${statusText}`,
          severity: "info",
          error: `LeakCheck API returned ${response.status}: ${statusText}`,
        };
      }

      const data = (await response.json()) as LeakCheckResponse;
      const found = data.found > 0;

      let severity: PluginCheckResult["severity"] = "low";
      if (data.found > 10) {
        severity = "critical";
      } else if (data.found > 0) {
        severity = "high";
      }

      return {
        pluginId: "leakcheck",
        pluginName: "LeakCheck",
        found,
        details: found
          ? `Found in ${data.found} leak(s) from ${data.sources.length} source(s)`
          : "Not found in LeakCheck database",
        severity,
        error: null,
        metadata: {
          found: data.found,
          sourceCount: data.sources.length,
          sources: data.sources.map((s) => s.name),
        },
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        pluginId: "leakcheck",
        pluginName: "LeakCheck",
        found: false,
        details: `Network error: ${sanitizeForTerminal(message)}`,
        severity: "info",
        error: sanitizeForTerminal(message),
      };
    }
  },
};
