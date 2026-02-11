import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { gitGuardianHslPlugin } from "../../src/checks/plugins/gitguardian-hsl-plugin.js";
import { SecureBuffer } from "../../src/core/secure-buffer.js";
import type { AppConfig } from "../../src/types/index.js";

const configWithKey: AppConfig = {
  hibpApiKey: null,
  auditLogPath: null,
  offline: false,
  json: false,
  verbose: false,
  verify: false,
  enabledPlugins: [],
  disabledPlugins: [],
  pluginApiKeys: { GITGUARDIAN_API_TOKEN: "test-token-123" },
};

const configNoKey: AppConfig = {
  ...configWithKey,
  pluginApiKeys: {},
};

const server = setupServer(
  http.post("https://api.gitguardian.com/v1/secret/has_secret_leaked", async ({ request }) => {
    const body = (await request.json()) as { hash: string };

    // Simulate a "found" response for a specific hash
    if (body.hash === SecureBuffer.fromString("leaked-secret-abc").sha256Hex()) {
      return HttpResponse.json({ matches: 3 });
    }

    // Default: not found
    return HttpResponse.json({ matches: 0 });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("gitGuardianHslPlugin", () => {
  it("should detect a leaked secret", async () => {
    const sb = SecureBuffer.fromString("leaked-secret-abc");
    const result = await gitGuardianHslPlugin.check(sb, configWithKey);
    sb.dispose();

    expect(result.found).toBe(true);
    expect(result.severity).toBe("critical");
    expect(result.details).toContain("3 public GitHub repo(s)");
    expect(result.error).toBeNull();
  });

  it("should report clean for unknown secret", async () => {
    const sb = SecureBuffer.fromString("unique-secret-xyz-789");
    const result = await gitGuardianHslPlugin.check(sb, configWithKey);
    sb.dispose();

    expect(result.found).toBe(false);
    expect(result.severity).toBe("low");
    expect(result.details).toContain("Not found in public GitHub repos");
    expect(result.error).toBeNull();
  });

  it("should return error when API token is missing", async () => {
    const sb = SecureBuffer.fromString("test-secret");
    const result = await gitGuardianHslPlugin.check(sb, configNoKey);
    sb.dispose();

    expect(result.found).toBe(false);
    expect(result.error).toContain("Missing GITGUARDIAN_API_TOKEN");
  });

  it("should handle API errors gracefully", async () => {
    server.use(
      http.post("https://api.gitguardian.com/v1/secret/has_secret_leaked", () => {
        return new HttpResponse(null, { status: 500 });
      }),
    );

    const sb = SecureBuffer.fromString("test-secret");
    const result = await gitGuardianHslPlugin.check(sb, configWithKey);
    sb.dispose();

    expect(result.found).toBe(false);
    expect(result.error).toContain("500");
  });

  it("should handle rate limiting", async () => {
    server.use(
      http.post("https://api.gitguardian.com/v1/secret/has_secret_leaked", () => {
        return new HttpResponse(null, { status: 429 });
      }),
    );

    const sb = SecureBuffer.fromString("test-secret");
    const result = await gitGuardianHslPlugin.check(sb, configWithKey);
    sb.dispose();

    expect(result.found).toBe(false);
    expect(result.error).toContain("429");
  });

  it("should handle network errors", async () => {
    server.use(
      http.post("https://api.gitguardian.com/v1/secret/has_secret_leaked", () => {
        return HttpResponse.error();
      }),
    );

    const sb = SecureBuffer.fromString("test-secret");
    const result = await gitGuardianHslPlugin.check(sb, configWithKey);
    sb.dispose();

    expect(result.found).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it("should have correct plugin metadata", () => {
    expect(gitGuardianHslPlugin.id).toBe("gitguardian-hsl");
    expect(gitGuardianHslPlugin.requiresNetwork).toBe(true);
    expect(gitGuardianHslPlugin.requiredConfigKeys).toEqual(["GITGUARDIAN_API_TOKEN"]);
    expect(gitGuardianHslPlugin.inputKind).toBe("secret");
  });
});
