import { sanitizeForTerminal } from "../../core/sanitize.js";
import type { CheckPlugin } from "../plugin.js";
import type { AppConfig, PluginCheckResult } from "../../types/index.js";

const DEHASHED_BASE = "https://api.dehashed.com/search";
const USER_AGENT = "compromising-position/1.0.0";

interface DehashedEntry {
  id: string;
  email: string;
  ip_address: string;
  username: string;
  password: string;
  hashed_password: string;
  name: string;
  vin: string;
  address: string;
  phone: string;
  database_name: string;
}

interface DehashedResponse {
  balance: number;
  entries: DehashedEntry[] | null;
  success: boolean;
  took: string;
  total: number;
}

export const dehashedPlugin: CheckPlugin = {
  id: "dehashed",
  name: "DeHashed",
  inputKind: "email",
  requiresNetwork: true,
  requiredConfigKeys: ["DEHASHED_EMAIL", "DEHASHED_API_KEY"],
  isFree: false,
  privacySummary: "Full email -> api.dehashed.com (requires paid API key)",

  async check(
    input: unknown,
    config: AppConfig,
  ): Promise<PluginCheckResult> {
    const email = input as string;
    const dehashedEmail = config.pluginApiKeys["DEHASHED_EMAIL"];
    const apiKey = config.pluginApiKeys["DEHASHED_API_KEY"];

    if (!dehashedEmail || !apiKey) {
      return {
        pluginId: "dehashed",
        pluginName: "DeHashed",
        found: false,
        details: "DeHashed credentials not configured",
        severity: "info",
        error: "Missing DEHASHED_EMAIL and/or DEHASHED_API_KEY",
      };
    }

    try {
      const credentials = Buffer.from(`${dehashedEmail}:${apiKey}`).toString("base64");
      const response = await fetch(
        `${DEHASHED_BASE}?query=email:${encodeURIComponent(email)}&size=10`,
        {
          headers: {
            Accept: "application/json",
            Authorization: `Basic ${credentials}`,
            "User-Agent": USER_AGENT,
          },
        },
      );

      if (!response.ok) {
        const statusText = sanitizeForTerminal(response.statusText);
        return {
          pluginId: "dehashed",
          pluginName: "DeHashed",
          found: false,
          details: `API error: ${response.status} ${statusText}`,
          severity: "info",
          error: `DeHashed API returned ${response.status}: ${statusText}`,
        };
      }

      const data = (await response.json()) as DehashedResponse;
      const found = data.total > 0;

      // Count unique databases
      const databases = new Set(
        (data.entries ?? []).map((e) => e.database_name).filter(Boolean),
      );

      let severity: PluginCheckResult["severity"] = "low";
      if (data.total > 10) {
        severity = "critical";
      } else if (data.total > 0) {
        severity = "high";
      }

      return {
        pluginId: "dehashed",
        pluginName: "DeHashed",
        found,
        details: found
          ? `Found ${data.total} record(s) across ${databases.size} database(s)`
          : "Not found in DeHashed database",
        severity,
        error: null,
        metadata: {
          total: data.total,
          uniqueDatabases: databases.size,
          balance: data.balance,
        },
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        pluginId: "dehashed",
        pluginName: "DeHashed",
        found: false,
        details: `Network error: ${sanitizeForTerminal(message)}`,
        severity: "info",
        error: sanitizeForTerminal(message),
      };
    }
  },
};
