import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { dehashedPlugin } from "../../src/checks/plugins/dehashed-plugin.js";
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
  pluginApiKeys: {
    DEHASHED_EMAIL: "user@example.com",
    DEHASHED_API_KEY: "test-api-key",
  },
};

const configNoKey: AppConfig = { ...configWithKey, pluginApiKeys: {} };

const server = setupServer(
  http.get("https://api.dehashed.com/search", ({ request }) => {
    const url = new URL(request.url);
    const query = url.searchParams.get("query");

    if (query?.includes("compromised@example.com")) {
      return HttpResponse.json({
        balance: 95,
        entries: [
          {
            id: "1",
            email: "compromised@example.com",
            database_name: "Collection1",
            ip_address: "",
            username: "",
            password: "",
            hashed_password: "",
            name: "",
            vin: "",
            address: "",
            phone: "",
          },
          {
            id: "2",
            email: "compromised@example.com",
            database_name: "LinkedIn2021",
            ip_address: "",
            username: "",
            password: "",
            hashed_password: "",
            name: "",
            vin: "",
            address: "",
            phone: "",
          },
        ],
        success: true,
        took: "0.1s",
        total: 2,
      });
    }

    return HttpResponse.json({
      balance: 95,
      entries: null,
      success: true,
      took: "0.1s",
      total: 0,
    });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("dehashedPlugin", () => {
  it("should detect a compromised email", async () => {
    const result = await dehashedPlugin.check("compromised@example.com", configWithKey);

    expect(result.found).toBe(true);
    expect(result.severity).toBe("high");
    expect(result.details).toContain("2 record(s)");
    expect(result.details).toContain("2 database(s)");
  });

  it("should report clean for unknown email", async () => {
    const result = await dehashedPlugin.check("clean@example.com", configWithKey);

    expect(result.found).toBe(false);
    expect(result.severity).toBe("low");
  });

  it("should return error when API keys missing", async () => {
    const result = await dehashedPlugin.check("test@example.com", configNoKey);

    expect(result.found).toBe(false);
    expect(result.error).toContain("Missing DEHASHED_EMAIL");
  });

  it("should handle API errors", async () => {
    server.use(
      http.get("https://api.dehashed.com/search", () => {
        return new HttpResponse(null, { status: 403 });
      }),
    );

    const result = await dehashedPlugin.check("test@example.com", configWithKey);

    expect(result.found).toBe(false);
    expect(result.error).toContain("403");
  });
});
