import { describe, it, expect } from "vitest";
import { CheckRegistry } from "../src/checks/registry.js";
import type { CheckPlugin } from "../src/checks/plugin.js";
import type { AppConfig, PluginCheckResult } from "../src/types/index.js";

function makePlugin(overrides: Partial<CheckPlugin> = {}): CheckPlugin {
  return {
    id: overrides.id ?? "test-plugin",
    name: overrides.name ?? "Test Plugin",
    inputKind: overrides.inputKind ?? "secret",
    requiresNetwork: overrides.requiresNetwork ?? false,
    requiredConfigKeys: overrides.requiredConfigKeys ?? [],
    isFree: overrides.isFree ?? true,
    privacySummary: overrides.privacySummary ?? "No data sent",
    check: overrides.check ?? (async (): Promise<PluginCheckResult> => ({
      pluginId: "test-plugin",
      pluginName: "Test Plugin",
      found: false,
      details: "test",
      severity: "info",
      error: null,
    })),
  };
}

function makeConfig(overrides: Partial<AppConfig> = {}): AppConfig {
  return {
    hibpApiKey: null,
    auditLogPath: null,
    offline: false,
    json: false,
    verbose: false,
    verify: false,
    enabledPlugins: [],
    disabledPlugins: [],
    pluginApiKeys: {},
    ...overrides,
  };
}

describe("CheckRegistry", () => {
  it("should register and retrieve plugins", () => {
    const registry = new CheckRegistry();
    const plugin = makePlugin({ id: "p1" });
    registry.register(plugin);
    expect(registry.getAll()).toHaveLength(1);
    expect(registry.getAll()[0]!.id).toBe("p1");
  });

  it("should reject duplicate plugin IDs", () => {
    const registry = new CheckRegistry();
    registry.register(makePlugin({ id: "dup" }));
    expect(() => registry.register(makePlugin({ id: "dup" }))).toThrow(
      "Plugin already registered: dup",
    );
  });

  it("should filter by input kind", () => {
    const registry = new CheckRegistry();
    registry.register(makePlugin({ id: "secret-p", inputKind: "secret" }));
    registry.register(makePlugin({ id: "email-p", inputKind: "email" }));
    registry.register(makePlugin({ id: "both-p", inputKind: "both" }));

    const secretPlugins = registry.getByKind("secret");
    expect(secretPlugins.map((p) => p.id)).toEqual(["secret-p", "both-p"]);

    const emailPlugins = registry.getByKind("email");
    expect(emailPlugins.map((p) => p.id)).toEqual(["email-p", "both-p"]);
  });

  it("should filter out network plugins in offline mode", () => {
    const registry = new CheckRegistry();
    registry.register(makePlugin({ id: "local", requiresNetwork: false }));
    registry.register(makePlugin({ id: "remote", requiresNetwork: true }));

    const config = makeConfig({ offline: true });
    const runnable = registry.getRunnable("secret", config);
    expect(runnable.map((p) => p.id)).toEqual(["local"]);
  });

  it("should filter out plugins missing required API keys", () => {
    const registry = new CheckRegistry();
    registry.register(makePlugin({ id: "free", requiredConfigKeys: [] }));
    registry.register(
      makePlugin({ id: "paid", requiredConfigKeys: ["SOME_API_KEY"] }),
    );

    const configNoKey = makeConfig();
    expect(registry.getRunnable("secret", configNoKey).map((p) => p.id)).toEqual(["free"]);

    const configWithKey = makeConfig({
      pluginApiKeys: { SOME_API_KEY: "sk-123" },
    });
    expect(registry.getRunnable("secret", configWithKey).map((p) => p.id)).toEqual([
      "free",
      "paid",
    ]);
  });

  it("should respect disable list", () => {
    const registry = new CheckRegistry();
    registry.register(makePlugin({ id: "a" }));
    registry.register(makePlugin({ id: "b" }));

    const config = makeConfig({ disabledPlugins: ["a"] });
    expect(registry.getRunnable("secret", config).map((p) => p.id)).toEqual(["b"]);
  });

  it("should respect enable list (allow-list mode)", () => {
    const registry = new CheckRegistry();
    registry.register(makePlugin({ id: "a" }));
    registry.register(makePlugin({ id: "b" }));
    registry.register(makePlugin({ id: "c" }));

    const config = makeConfig({ enabledPlugins: ["a", "c"] });
    expect(registry.getRunnable("secret", config).map((p) => p.id)).toEqual(["a", "c"]);
  });

  it("should return all plugins when no enable/disable lists", () => {
    const registry = new CheckRegistry();
    registry.register(makePlugin({ id: "a" }));
    registry.register(makePlugin({ id: "b" }));

    const config = makeConfig();
    expect(registry.getRunnable("secret", config).map((p) => p.id)).toEqual(["a", "b"]);
  });
});
