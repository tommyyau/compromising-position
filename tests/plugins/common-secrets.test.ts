import { describe, it, expect } from "vitest";
import { commonSecretsPlugin } from "../../src/checks/plugins/common-secrets-plugin.js";
import { SecureBuffer } from "../../src/core/secure-buffer.js";
import type { AppConfig } from "../../src/types/index.js";

const config: AppConfig = {
  hibpApiKey: null,
  auditLogPath: null,
  offline: false,
  json: false,
  verbose: false,
  verify: false,
  enabledPlugins: [],
  disabledPlugins: [],
  pluginApiKeys: {},
};

describe("commonSecretsPlugin", () => {
  it("should detect 'password' as a common secret", async () => {
    const sb = SecureBuffer.fromString("password");
    const result = await commonSecretsPlugin.check(sb, config);
    sb.dispose();

    expect(result.found).toBe(true);
    expect(result.severity).toBe("critical");
    expect(result.metadata?.matchType).toBe("blocklist");
  });

  it("should detect '123456' as a common secret", async () => {
    const sb = SecureBuffer.fromString("123456");
    const result = await commonSecretsPlugin.check(sb, config);
    sb.dispose();

    expect(result.found).toBe(true);
    expect(result.severity).toBe("critical");
  });

  it("should detect 'changeme' as a common secret", async () => {
    const sb = SecureBuffer.fromString("changeme");
    const result = await commonSecretsPlugin.check(sb, config);
    sb.dispose();

    expect(result.found).toBe(true);
    expect(result.severity).toBe("critical");
  });

  it("should detect placeholder patterns like 'your-api-key-here'", async () => {
    const sb = SecureBuffer.fromString("your-api-key-here");
    const result = await commonSecretsPlugin.check(sb, config);
    sb.dispose();

    expect(result.found).toBe(true);
    expect(result.severity).toBe("medium");
    expect(result.metadata?.matchType).toBe("placeholder");
  });

  it("should detect 'TODO' as a placeholder", async () => {
    const sb = SecureBuffer.fromString("TODO");
    const result = await commonSecretsPlugin.check(sb, config);
    sb.dispose();

    expect(result.found).toBe(true);
    expect(result.severity).toBe("medium");
  });

  it("should detect sequential patterns like 'aaaaaaaaaa'", async () => {
    const sb = SecureBuffer.fromString("aaaaaaaaaa");
    const result = await commonSecretsPlugin.check(sb, config);
    sb.dispose();

    expect(result.found).toBe(true);
    expect(result.severity).toBe("high");
    expect(result.metadata?.matchType).toBe("sequential");
  });

  it("should detect keyboard pattern 'qwerty'", async () => {
    // 'qwerty' is also in the blocklist, so it matches there first
    const sb = SecureBuffer.fromString("qwerty");
    const result = await commonSecretsPlugin.check(sb, config);
    sb.dispose();

    expect(result.found).toBe(true);
  });

  it("should not match a strong random secret", async () => {
    const sb = SecureBuffer.fromString("sk-proj-a8f3k2j4n6m1p9q7r5t0w3x2y8v6u4s");
    const result = await commonSecretsPlugin.check(sb, config);
    sb.dispose();

    expect(result.found).toBe(false);
    expect(result.severity).toBe("low");
  });

  it("should have correct plugin metadata", () => {
    expect(commonSecretsPlugin.id).toBe("common-secrets");
    expect(commonSecretsPlugin.requiresNetwork).toBe(false);
    expect(commonSecretsPlugin.isFree).toBe(true);
    expect(commonSecretsPlugin.inputKind).toBe("secret");
  });
});
