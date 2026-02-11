import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { intelXPlugin } from "../../src/checks/plugins/intelx-plugin.js";
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
  pluginApiKeys: { INTELX_API_KEY: "test-key" },
};

const configNoKey: AppConfig = { ...configWithKey, pluginApiKeys: {} };

const server = setupServer(
  // Search initiation
  http.post("https://2.intelx.io/intelligent/search", async ({ request }) => {
    const body = (await request.json()) as { term: string };
    return HttpResponse.json({
      id: "search-id-123",
      status: 0,
    });
  }),

  // Search results
  http.get("https://2.intelx.io/intelligent/search/result", ({ request }) => {
    const url = new URL(request.url);
    const id = url.searchParams.get("id");

    if (id === "search-id-123") {
      return HttpResponse.json({
        records: [
          {
            systemid: "1",
            name: "paste-leak.txt",
            date: "2023-01-15",
            bucket: "pastes",
            mediah: "",
            type: 0,
          },
          {
            systemid: "2",
            name: "darkweb-dump.csv",
            date: "2022-11-01",
            bucket: "darknet",
            mediah: "",
            type: 0,
          },
        ],
        status: 0,
      });
    }

    return HttpResponse.json({ records: [], status: 0 });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("intelXPlugin", () => {
  it("should find results for a compromised email", async () => {
    const result = await intelXPlugin.check("compromised@example.com", configWithKey);

    expect(result.found).toBe(true);
    expect(result.severity).toBe("high");
    expect(result.details).toContain("2 result(s)");
    expect(result.details).toContain("2 source(s)");
  });

  it("should return error when API key missing", async () => {
    const result = await intelXPlugin.check("test@example.com", configNoKey);

    expect(result.found).toBe(false);
    expect(result.error).toContain("Missing INTELX_API_KEY");
  });

  it("should handle search API errors", async () => {
    server.use(
      http.post("https://2.intelx.io/intelligent/search", () => {
        return new HttpResponse(null, { status: 401 });
      }),
    );

    const result = await intelXPlugin.check("test@example.com", configWithKey);

    expect(result.found).toBe(false);
    expect(result.error).toContain("401");
  });

  it("should handle network errors", async () => {
    server.use(
      http.post("https://2.intelx.io/intelligent/search", () => {
        return HttpResponse.error();
      }),
    );

    const result = await intelXPlugin.check("test@example.com", configWithKey);

    expect(result.found).toBe(false);
    expect(result.error).toBeTruthy();
  });
});
