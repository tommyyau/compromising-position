import { sanitizeForTerminal } from "../../core/sanitize.js";
import type { CheckPlugin } from "../plugin.js";
import type { AppConfig, PluginCheckResult } from "../../types/index.js";

const INTELX_BASE = "https://2.intelx.io";
const USER_AGENT = "compromising-position/1.0.0";

interface IntelXSearchResponse {
  id: string;
  status: number;
}

interface IntelXResultRecord {
  systemid: string;
  name: string;
  date: string;
  bucket: string;
  mediah: string;
  type: number;
}

interface IntelXResultResponse {
  records: IntelXResultRecord[];
  status: number;
}

export const intelXPlugin: CheckPlugin = {
  id: "intelx",
  name: "Intelligence X",
  inputKind: "email",
  requiresNetwork: true,
  requiredConfigKeys: ["INTELX_API_KEY"],
  isFree: false,
  privacySummary: "Full email -> 2.intelx.io (requires paid API key)",

  async check(
    input: unknown,
    config: AppConfig,
  ): Promise<PluginCheckResult> {
    const email = input as string;
    const apiKey = config.pluginApiKeys["INTELX_API_KEY"];

    if (!apiKey) {
      return {
        pluginId: "intelx",
        pluginName: "Intelligence X",
        found: false,
        details: "Intelligence X API key not configured",
        severity: "info",
        error: "Missing INTELX_API_KEY",
      };
    }

    try {
      // Step 1: Initiate search
      const searchResponse = await fetch(
        `${INTELX_BASE}/intelligent/search`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-key": apiKey,
            "User-Agent": USER_AGENT,
          },
          body: JSON.stringify({
            term: email,
            maxresults: 10,
            media: 0,
            sort: 2,
            terminate: [],
          }),
        },
      );

      if (!searchResponse.ok) {
        const statusText = sanitizeForTerminal(searchResponse.statusText);
        return {
          pluginId: "intelx",
          pluginName: "Intelligence X",
          found: false,
          details: `Search API error: ${searchResponse.status} ${statusText}`,
          severity: "info",
          error: `IntelX API returned ${searchResponse.status}: ${statusText}`,
        };
      }

      const searchData = (await searchResponse.json()) as IntelXSearchResponse;

      // Step 2: Fetch results
      const resultResponse = await fetch(
        `${INTELX_BASE}/intelligent/search/result?id=${encodeURIComponent(searchData.id)}&limit=10`,
        {
          headers: {
            "x-key": apiKey,
            "User-Agent": USER_AGENT,
          },
        },
      );

      if (!resultResponse.ok) {
        const statusText = sanitizeForTerminal(resultResponse.statusText);
        return {
          pluginId: "intelx",
          pluginName: "Intelligence X",
          found: false,
          details: `Result API error: ${resultResponse.status} ${statusText}`,
          severity: "info",
          error: `IntelX API returned ${resultResponse.status}: ${statusText}`,
        };
      }

      const resultData = (await resultResponse.json()) as IntelXResultResponse;
      const records = resultData.records ?? [];
      const found = records.length > 0;

      // Categorize sources
      const buckets = new Set(records.map((r) => r.bucket).filter(Boolean));

      let severity: PluginCheckResult["severity"] = "low";
      if (records.length > 5) {
        severity = "critical";
      } else if (records.length > 0) {
        severity = "high";
      }

      return {
        pluginId: "intelx",
        pluginName: "Intelligence X",
        found,
        details: found
          ? `Found ${records.length} result(s) across ${buckets.size} source(s) (Tor, I2P, pastes, leaks)`
          : "Not found in Intelligence X",
        severity,
        error: null,
        metadata: {
          resultCount: records.length,
          buckets: Array.from(buckets),
          searchId: searchData.id,
        },
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        pluginId: "intelx",
        pluginName: "Intelligence X",
        found: false,
        details: `Network error: ${sanitizeForTerminal(message)}`,
        severity: "info",
        error: sanitizeForTerminal(message),
      };
    }
  },
};
