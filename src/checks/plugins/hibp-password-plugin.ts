import type { CheckPlugin } from "../plugin.js";
import type { SecureBuffer } from "../../core/secure-buffer.js";
import type { AppConfig, PluginCheckResult } from "../../types/index.js";
import { checkHibpPassword } from "../hibp-password.js";

export const hibpPasswordPlugin: CheckPlugin = {
  id: "hibp-password",
  name: "HIBP Password Check",
  inputKind: "secret",
  requiresNetwork: true,
  requiredConfigKeys: [],
  isFree: true,
  privacySummary: "SHA-1 prefix (5 hex chars) -> api.pwnedpasswords.com",

  async check(
    input: SecureBuffer | string,
    _config: AppConfig,
  ): Promise<PluginCheckResult> {
    const secret = input as SecureBuffer;
    const result = await checkHibpPassword(secret);

    if (result.error) {
      return {
        pluginId: "hibp-password",
        pluginName: "HIBP Password Check",
        found: false,
        details: result.error,
        severity: "info",
        error: result.error,
      };
    }

    return {
      pluginId: "hibp-password",
      pluginName: "HIBP Password Check",
      found: result.found,
      details: result.found
        ? `Found in ${result.occurrences.toLocaleString()} breach(es)`
        : "Not found in breach data",
      severity: result.found ? "critical" : "low",
      error: null,
      metadata: {
        occurrences: result.occurrences,
        hashPrefix: result.hashPrefix,
      },
    };
  },
};
