import { sanitizeForTerminal } from "../../core/sanitize.js";
import type { CheckPlugin } from "../plugin.js";
import type { AppConfig, PluginCheckResult } from "../../types/index.js";

const EMAILREP_BASE = "https://emailrep.io";
const USER_AGENT = "compromising-position/1.0.0";

interface EmailRepResponse {
  email: string;
  reputation: "high" | "medium" | "low" | "none";
  suspicious: boolean;
  references: number;
  details: {
    blacklisted: boolean;
    malicious_activity: boolean;
    malicious_activity_recent: boolean;
    credentials_leaked: boolean;
    credentials_leaked_recent: boolean;
    data_breach: boolean;
    dark_web_appearance: boolean;
    last_seen: string;
    domain_exists: boolean;
    domain_reputation: string;
    new_domain: boolean;
    days_since_domain_creation: number;
    suspicious_tld: boolean;
    spam: boolean;
    free_provider: boolean;
    disposable: boolean;
    deliverable: boolean;
    accept_all: boolean;
    valid_mx: boolean;
    spoofable: boolean;
    spf_strict: boolean;
    dmarc_enforced: boolean;
    profiles: string[];
  };
}

export const emailRepPlugin: CheckPlugin = {
  id: "emailrep",
  name: "EmailRep.io",
  inputKind: "email",
  requiresNetwork: true,
  requiredConfigKeys: [],
  isFree: true,
  privacySummary: "Full email -> emailrep.io (free, 100/day)",

  async check(
    input: unknown,
    config: AppConfig,
  ): Promise<PluginCheckResult> {
    const email = input as string;
    const apiKey = config.pluginApiKeys["EMAILREP_API_KEY"];

    try {
      const headers: Record<string, string> = {
        "User-Agent": USER_AGENT,
        Accept: "application/json",
      };

      if (apiKey) {
        headers["Key"] = apiKey;
      }

      const response = await fetch(`${EMAILREP_BASE}/${encodeURIComponent(email)}`, {
        headers,
      });

      if (!response.ok) {
        const statusText = sanitizeForTerminal(response.statusText);
        return {
          pluginId: "emailrep",
          pluginName: "EmailRep.io",
          found: false,
          details: `API error: ${response.status} ${statusText}`,
          severity: "info",
          error: `EmailRep API returned ${response.status}: ${statusText}`,
        };
      }

      const data = (await response.json()) as EmailRepResponse;
      const findings: string[] = [];

      if (data.details.credentials_leaked) {
        findings.push("credentials leaked");
      }
      if (data.details.data_breach) {
        findings.push("found in data breach");
      }
      if (data.details.dark_web_appearance) {
        findings.push("dark web appearance");
      }
      if (data.details.malicious_activity) {
        findings.push("malicious activity detected");
      }

      const found = findings.length > 0;

      let severity: PluginCheckResult["severity"] = "low";
      if (data.details.credentials_leaked_recent || data.details.malicious_activity_recent) {
        severity = "critical";
      } else if (data.details.credentials_leaked || data.details.dark_web_appearance) {
        severity = "high";
      } else if (data.details.data_breach || data.suspicious) {
        severity = "medium";
      }

      return {
        pluginId: "emailrep",
        pluginName: "EmailRep.io",
        found,
        details: found
          ? `Reputation: ${data.reputation} — ${findings.join(", ")}`
          : `Reputation: ${data.reputation} — no exposure found`,
        severity,
        error: null,
        metadata: {
          reputation: data.reputation,
          suspicious: data.suspicious,
          references: data.references,
          credentialsLeaked: data.details.credentials_leaked,
          darkWebAppearance: data.details.dark_web_appearance,
          dataBreach: data.details.data_breach,
          profiles: data.details.profiles,
        },
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        pluginId: "emailrep",
        pluginName: "EmailRep.io",
        found: false,
        details: `Network error: ${sanitizeForTerminal(message)}`,
        severity: "info",
        error: sanitizeForTerminal(message),
      };
    }
  },
};
