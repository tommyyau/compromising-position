import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { leakCheckPlugin } from "../../src/checks/plugins/leakcheck-plugin.js";
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
  pluginApiKeys: { LEAKCHECK_API_KEY: "test-key" },
};

const configNoKey: AppConfig = { ...configWithKey, pluginApiKeys: {} };

const server = setupServer(
  http.get("https://leakcheck.io/api/v2/query/:email", ({ params }) => {
    if (params["email"] === "compromised@example.com") {
      return HttpResponse.json({
        success: true,
        found: 3,
        sources: [
          { name: "Collection1", date: "2019-01-01" },
          { name: "LinkedIn2021", date: "2021-06-01" },
        ],
      });
    }

    return HttpResponse.json({
      success: true,
      found: 0,
      sources: [],
    });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("leakCheckPlugin", () => {
  it("should detect a compromised email", async () => {
    const result = await leakCheckPlugin.check("compromised@example.com", configWithKey);

    expect(result.found).toBe(true);
    expect(result.severity).toBe("high");
    expect(result.details).toContain("3 leak(s)");
    expect(result.details).toContain("2 source(s)");
  });

  it("should report clean for unknown email", async () => {
    const result = await leakCheckPlugin.check("clean@example.com", configWithKey);

    expect(result.found).toBe(false);
    expect(result.severity).toBe("low");
  });

  it("should return error when API key missing", async () => {
    const result = await leakCheckPlugin.check("test@example.com", configNoKey);

    expect(result.found).toBe(false);
    expect(result.error).toContain("Missing LEAKCHECK_API_KEY");
  });

  it("should handle API errors", async () => {
    server.use(
      http.get("https://leakcheck.io/api/v2/query/:email", () => {
        return new HttpResponse(null, { status: 401 });
      }),
    );

    const result = await leakCheckPlugin.check("test@example.com", configWithKey);

    expect(result.found).toBe(false);
    expect(result.error).toContain("401");
  });
});
