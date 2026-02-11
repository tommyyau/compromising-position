import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { checkHibpEmail } from "../src/checks/hibp-email.js";

const MOCK_BREACHES = [
  {
    Name: "ExampleBreach",
    BreachDate: "2023-01-15",
    DataClasses: ["Email addresses", "Passwords"],
  },
];

const MOCK_STEALER_LOGS = [
  {
    Name: "InfoStealer2024",
    Date: "2024-03-20",
  },
];

const MOCK_PASTES = [
  {
    Source: "Pastebin",
    Id: "abc123",
    Title: "Leaked credentials",
    Date: "2023-06-01",
  },
];

const server = setupServer(
  http.get("https://haveibeenpwned.com/api/v3/breachedaccount/:email", () => {
    return HttpResponse.json(MOCK_BREACHES);
  }),
  http.get("https://haveibeenpwned.com/api/v3/stealerlogsbyemail/:email", () => {
    return HttpResponse.json(MOCK_STEALER_LOGS);
  }),
  http.get("https://haveibeenpwned.com/api/v3/pasteaccount/:email", () => {
    return HttpResponse.json(MOCK_PASTES);
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("checkHibpEmail", () => {
  it("should return breaches, stealer logs, and pastes", async () => {
    const result = await checkHibpEmail("test@example.com", "fake-api-key");

    expect(result.checked).toBe(true);
    expect(result.error).toBeNull();
    expect(result.breaches).toHaveLength(1);
    expect(result.breaches[0]?.Name).toBe("ExampleBreach");
    expect(result.stealerLogs).toHaveLength(1);
    expect(result.stealerLogs[0]?.Name).toBe("InfoStealer2024");
    expect(result.pastes).toHaveLength(1);
    expect(result.pastes[0]?.Source).toBe("Pastebin");
  }, 10000);

  it("should handle 404 (no breaches found)", async () => {
    server.use(
      http.get("https://haveibeenpwned.com/api/v3/breachedaccount/:email", () => {
        return new HttpResponse(null, { status: 404 });
      }),
      http.get("https://haveibeenpwned.com/api/v3/stealerlogsbyemail/:email", () => {
        return new HttpResponse(null, { status: 404 });
      }),
      http.get("https://haveibeenpwned.com/api/v3/pasteaccount/:email", () => {
        return new HttpResponse(null, { status: 404 });
      }),
    );

    const result = await checkHibpEmail("clean@example.com", "fake-api-key");

    expect(result.checked).toBe(true);
    expect(result.error).toBeNull();
    expect(result.breaches).toHaveLength(0);
    expect(result.stealerLogs).toHaveLength(0);
    expect(result.pastes).toHaveLength(0);
  }, 10000);

  it("should handle API errors gracefully", async () => {
    server.use(
      http.get("https://haveibeenpwned.com/api/v3/breachedaccount/:email", () => {
        return new HttpResponse(null, { status: 401 });
      }),
    );

    const result = await checkHibpEmail("test@example.com", "bad-key");

    expect(result.checked).toBe(true);
    expect(result.error).toContain("401");
  });
});
