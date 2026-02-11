import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { emailRepPlugin } from "../../src/checks/plugins/emailrep-plugin.js";
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

const server = setupServer(
  // Compromised email
  http.get("https://emailrep.io/compromised%40example.com", () => {
    return HttpResponse.json({
      email: "compromised@example.com",
      reputation: "low",
      suspicious: true,
      references: 15,
      details: {
        blacklisted: false,
        malicious_activity: false,
        malicious_activity_recent: false,
        credentials_leaked: true,
        credentials_leaked_recent: false,
        data_breach: true,
        dark_web_appearance: true,
        last_seen: "2024-01-15",
        domain_exists: true,
        domain_reputation: "high",
        new_domain: false,
        days_since_domain_creation: 5000,
        suspicious_tld: false,
        spam: false,
        free_provider: false,
        disposable: false,
        deliverable: true,
        accept_all: false,
        valid_mx: true,
        spoofable: false,
        spf_strict: true,
        dmarc_enforced: true,
        profiles: ["linkedin", "github"],
      },
    });
  }),

  // Clean email
  http.get("https://emailrep.io/clean%40example.com", () => {
    return HttpResponse.json({
      email: "clean@example.com",
      reputation: "high",
      suspicious: false,
      references: 25,
      details: {
        blacklisted: false,
        malicious_activity: false,
        malicious_activity_recent: false,
        credentials_leaked: false,
        credentials_leaked_recent: false,
        data_breach: false,
        dark_web_appearance: false,
        last_seen: "2024-06-01",
        domain_exists: true,
        domain_reputation: "high",
        new_domain: false,
        days_since_domain_creation: 8000,
        suspicious_tld: false,
        spam: false,
        free_provider: false,
        disposable: false,
        deliverable: true,
        accept_all: false,
        valid_mx: true,
        spoofable: false,
        spf_strict: true,
        dmarc_enforced: true,
        profiles: ["linkedin", "twitter"],
      },
    });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("emailRepPlugin", () => {
  it("should detect a compromised email", async () => {
    const result = await emailRepPlugin.check("compromised@example.com", config);

    expect(result.found).toBe(true);
    expect(result.severity).toBe("high");
    expect(result.details).toContain("credentials leaked");
    expect(result.details).toContain("dark web appearance");
    expect(result.error).toBeNull();
  });

  it("should report clean for a safe email", async () => {
    const result = await emailRepPlugin.check("clean@example.com", config);

    expect(result.found).toBe(false);
    expect(result.severity).toBe("low");
    expect(result.details).toContain("no exposure found");
    expect(result.error).toBeNull();
  });

  it("should handle API errors gracefully", async () => {
    server.use(
      http.get("https://emailrep.io/:email", () => {
        return new HttpResponse(null, { status: 429 });
      }),
    );

    const result = await emailRepPlugin.check("test@example.com", config);

    expect(result.found).toBe(false);
    expect(result.error).toContain("429");
  });

  it("should handle network errors gracefully", async () => {
    server.use(
      http.get("https://emailrep.io/:email", () => {
        return HttpResponse.error();
      }),
    );

    const result = await emailRepPlugin.check("test@example.com", config);

    expect(result.found).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it("should have correct plugin metadata", () => {
    expect(emailRepPlugin.id).toBe("emailrep");
    expect(emailRepPlugin.requiresNetwork).toBe(true);
    expect(emailRepPlugin.isFree).toBe(true);
    expect(emailRepPlugin.inputKind).toBe("email");
  });
});
