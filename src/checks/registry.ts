import type { CheckPlugin } from "./plugin.js";
import type { AppConfig, PluginInputKind } from "../types/index.js";

/**
 * Registry for check plugins. Manages plugin registration and
 * filtering by input kind, network requirements, and config availability.
 */
export class CheckRegistry {
  readonly #plugins: CheckPlugin[] = [];

  register(plugin: CheckPlugin): void {
    if (this.#plugins.some((p) => p.id === plugin.id)) {
      throw new Error(`Plugin already registered: ${plugin.id}`);
    }
    this.#plugins.push(plugin);
  }

  /** Get all registered plugins. */
  getAll(): readonly CheckPlugin[] {
    return this.#plugins;
  }

  /** Get plugins filtered by input kind. */
  getByKind(kind: PluginInputKind): CheckPlugin[] {
    return this.#plugins.filter(
      (p) => p.inputKind === kind || p.inputKind === "both",
    );
  }

  /**
   * Get plugins that are runnable given the current config.
   * Filters out:
   * - Network plugins when offline
   * - Plugins missing required API keys
   * - Explicitly disabled plugins
   * - Plugins not in the enabled list (if an enabled list is provided)
   */
  getRunnable(kind: PluginInputKind, config: AppConfig): CheckPlugin[] {
    return this.getByKind(kind).filter((p) => {
      // Respect disable list
      if (config.disabledPlugins.length > 0 && config.disabledPlugins.includes(p.id)) {
        return false;
      }

      // If an explicit enable list is provided, only include those
      if (config.enabledPlugins.length > 0 && !config.enabledPlugins.includes(p.id)) {
        return false;
      }

      // Skip network plugins in offline mode
      if (config.offline && p.requiresNetwork) {
        return false;
      }

      // Skip plugins missing required config keys
      for (const key of p.requiredConfigKeys) {
        if (!config.pluginApiKeys[key]) {
          return false;
        }
      }

      return true;
    });
  }
}
