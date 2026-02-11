import type { CheckPlugin } from "../plugin.js";
import type { AppConfig, PluginCheckResult } from "../../types/index.js";
import { checkHibpEmail } from "../hibp-email.js";

export const hibpEmailPlugin: CheckPlugin = {
  id: "hibp-email",
  name: "HIBP Email Breach Check",
  inputKind: "email",
  requiresNetwork: true,
  requiredConfigKeys: ["HIBP_API_KEY"],
  isFree: false,
  privacySummary: "Full email -> haveibeenpwned.com (requires paid API key)",

  async check(
    input: unknown,
    config: AppConfig,
  ): Promise<PluginCheckResult> {
    const email = input as string;
    const apiKey = config.pluginApiKeys["HIBP_API_KEY"] ?? config.hibpApiKey;

    if (!apiKey) {
      return {
        pluginId: "hibp-email",
        pluginName: "HIBP Email Breach Check",
        found: false,
        details: "HIBP API key not configured",
        severity: "info",
        error: "Missing HIBP_API_KEY",
      };
    }

    const result = await checkHibpEmail(email, apiKey);

    if (result.error) {
      return {
        pluginId: "hibp-email",
        pluginName: "HIBP Email Breach Check",
        found: false,
        details: result.error,
        severity: "info",
        error: result.error,
      };
    }

    const totalFindings =
      result.breaches.length +
      result.stealerLogs.length +
      result.pastes.length;
    const found = totalFindings > 0;

    const parts: string[] = [];
    if (result.breaches.length > 0) {
      parts.push(`${result.breaches.length} breach(es)`);
    }
    if (result.stealerLogs.length > 0) {
      parts.push(`${result.stealerLogs.length} stealer log(s)`);
    }
    if (result.pastes.length > 0) {
      parts.push(`${result.pastes.length} paste(s)`);
    }

    let severity: PluginCheckResult["severity"] = "low";
    if (result.stealerLogs.length > 0 || result.breaches.length > 10) {
      severity = "critical";
    } else if (result.breaches.length > 0) {
      severity = "high";
    } else if (result.pastes.length > 0) {
      severity = "medium";
    }

    return {
      pluginId: "hibp-email",
      pluginName: "HIBP Email Breach Check",
      found,
      details: found ? `Found in: ${parts.join(", ")}` : "No breaches found",
      severity,
      error: null,
      metadata: {
        breachCount: result.breaches.length,
        stealerLogCount: result.stealerLogs.length,
        pasteCount: result.pastes.length,
      },
    };
  },
};
