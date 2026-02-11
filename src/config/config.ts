import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { config as dotenvConfig } from "dotenv";
import type { AppConfig } from "../types/index.js";

/** Known plugin API key env var names. */
const PLUGIN_API_KEY_VARS = [
  "HIBP_API_KEY",
  "EMAILREP_API_KEY",
  "GITGUARDIAN_API_TOKEN",
  "DEHASHED_EMAIL",
  "DEHASHED_API_KEY",
  "LEAKCHECK_API_KEY",
  "INTELX_API_KEY",
] as const;

/**
 * Load configuration from env vars and CLI options.
 *
 * Only loads .env if --env-file is explicitly provided or the .env file
 * is in the current working directory (with a warning). This prevents
 * a malicious .env in a cloned repo from silently overriding config.
 */
export function loadConfig(cliOptions: Partial<AppConfig> = {}): AppConfig {
  if (cliOptions.envFile) {
    // Explicit --env-file: load it
    dotenvConfig({ path: resolve(cliOptions.envFile) });
  } else {
    // Only auto-load .env from cwd if it exists, with a warning
    const defaultEnv = resolve(".env");
    if (existsSync(defaultEnv)) {
      process.stderr.write(
        `Note: Loading .env from ${defaultEnv}\n`,
      );
      dotenvConfig({ path: defaultEnv });
    }
  }

  // Collect plugin API keys from environment
  const pluginApiKeys: Record<string, string> = {
    ...cliOptions.pluginApiKeys,
  };
  for (const varName of PLUGIN_API_KEY_VARS) {
    const val = process.env[varName];
    if (val && !pluginApiKeys[varName]) {
      pluginApiKeys[varName] = val;
    }
  }

  return {
    hibpApiKey: cliOptions.hibpApiKey ?? process.env["HIBP_API_KEY"] ?? null,
    auditLogPath:
      cliOptions.auditLogPath ?? process.env["CP_AUDIT_LOG"] ?? null,
    offline: cliOptions.offline ?? false,
    json: cliOptions.json ?? false,
    verbose: cliOptions.verbose ?? false,
    verify: cliOptions.verify ?? false,
    enabledPlugins: cliOptions.enabledPlugins ?? [],
    disabledPlugins: cliOptions.disabledPlugins ?? [],
    pluginApiKeys,
  };
}
