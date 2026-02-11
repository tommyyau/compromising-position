import type { CheckPlugin } from "../plugin.js";
import type { SecureBuffer } from "../../core/secure-buffer.js";
import type { AppConfig, PluginCheckResult } from "../../types/index.js";
import { performLocalCheck } from "../local-check.js";

export const localAnalysisPlugin: CheckPlugin = {
  id: "local-analysis",
  name: "Local Analysis",
  inputKind: "secret",
  requiresNetwork: false,
  requiredConfigKeys: [],
  isFree: true,
  privacySummary: "No data sent (local only)",

  async check(
    input: SecureBuffer | string,
    _config: AppConfig,
  ): Promise<PluginCheckResult> {
    const secret = input as SecureBuffer;
    const result = performLocalCheck(secret);

    const details = [
      `Provider: ${result.identification.provider} (${result.identification.confidence})`,
      `Entropy: ${result.entropy.shannonEntropy} bits/char`,
    ];

    if (result.warnings.length > 0) {
      details.push(`Warnings: ${result.warnings.join("; ")}`);
    }

    return {
      pluginId: "local-analysis",
      pluginName: "Local Analysis",
      found: false,
      details: details.join(", "),
      severity: result.looksLikeSecret ? "info" : "low",
      error: null,
      metadata: {
        provider: result.identification.provider,
        confidence: result.identification.confidence,
        entropy: result.entropy.shannonEntropy,
        looksLikeSecret: result.looksLikeSecret,
      },
    };
  },
};
