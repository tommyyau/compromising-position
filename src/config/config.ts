import { config as dotenvConfig } from "dotenv";
import type { AppConfig } from "../types/index.js";

/** Load configuration from env vars and CLI options. */
export function loadConfig(cliOptions: Partial<AppConfig> = {}): AppConfig {
  dotenvConfig();

  return {
    hibpApiKey: cliOptions.hibpApiKey ?? process.env["HIBP_API_KEY"] ?? null,
    auditLogPath:
      cliOptions.auditLogPath ?? process.env["CP_AUDIT_LOG"] ?? null,
    offline: cliOptions.offline ?? false,
    json: cliOptions.json ?? false,
    verbose: cliOptions.verbose ?? false,
  };
}
