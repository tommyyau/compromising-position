import type { SecureBuffer } from "../core/secure-buffer.js";
import type {
  AppConfig,
  PluginCheckResult,
  PluginInputKind,
} from "../types/index.js";

/**
 * Interface for check plugins. Each plugin checks a secret or email
 * against a specific data source and returns a standardized result.
 */
export interface CheckPlugin {
  /** Unique identifier for this plugin. */
  readonly id: string;

  /** Human-readable name for display. */
  readonly name: string;

  /** What kind of input this plugin operates on. */
  readonly inputKind: PluginInputKind;

  /** Whether this plugin makes network requests. */
  readonly requiresNetwork: boolean;

  /** Config keys (env var names) that must be set for this plugin to run. */
  readonly requiredConfigKeys: string[];

  /** Whether this plugin is free (no API key purchase needed). */
  readonly isFree: boolean;

  /** Short description of what data is sent and where, for --privacy output. */
  readonly privacySummary: string;

  /**
   * Run the check.
   * @param input - The secret (SecureBuffer) or email (string), depending on inputKind.
   * @param config - App configuration including API keys.
   */
  check(
    input: SecureBuffer | string,
    config: AppConfig,
  ): Promise<PluginCheckResult>;
}
