import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { checkHibpPassword } from "../src/checks/hibp-password.js";
import { SecureBuffer } from "../src/core/secure-buffer.js";

// SHA-1 of "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
// Prefix: 5BAA6, Suffix: 1E4C9B93F3F0682250B6CF8331B7EE68FD8

const MOCK_RANGE_RESPONSE = [
  "0018A45C4D1DEF81644B54AB7F969B88D65:1",
  "1E4C9B93F3F0682250B6CF8331B7EE68FD8:9545824", // <-- "password" suffix with count
  "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2",
  "011053FD0102E94D6AE2F8B83D76FAF94F6:1",
  "012A7CA357541F0AC487871FEEC1891C49C:2",
].join("\n");

const server = setupServer(
  http.get("https://api.pwnedpasswords.com/range/5BAA6", () => {
    return new HttpResponse(MOCK_RANGE_RESPONSE, {
      status: 200,
      headers: { "Content-Type": "text/plain" },
    });
  }),
  // For a "not found" test case - SHA1 of "this-is-not-in-breach-data-xyz123"
  http.get("https://api.pwnedpasswords.com/range/:prefix", () => {
    return new HttpResponse(
      "0018A45C4D1DEF81644B54AB7F969B88D65:1\n00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\n",
      {
        status: 200,
        headers: { "Content-Type": "text/plain" },
      },
    );
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("checkHibpPassword", () => {
  it("should find 'password' in breach data", async () => {
    const sb = SecureBuffer.fromString("password");
    const result = await checkHibpPassword(sb);

    expect(result.checked).toBe(true);
    expect(result.found).toBe(true);
    expect(result.occurrences).toBe(9545824);
    expect(result.hashPrefix).toBe("5BAA6");
    expect(result.error).toBeNull();
    sb.dispose();
  });

  it("should not find a unique secret in breach data", async () => {
    const sb = SecureBuffer.fromString("this-is-not-in-breach-data-xyz123");
    const result = await checkHibpPassword(sb);

    expect(result.checked).toBe(true);
    expect(result.found).toBe(false);
    expect(result.occurrences).toBe(0);
    expect(result.error).toBeNull();
    sb.dispose();
  });

  it("should only send 5-char prefix", async () => {
    const sb = SecureBuffer.fromString("password");
    const result = await checkHibpPassword(sb);
    expect(result.hashPrefix).toHaveLength(5);
    sb.dispose();
  });

  it("should handle API errors gracefully", async () => {
    server.use(
      http.get("https://api.pwnedpasswords.com/range/:prefix", () => {
        return new HttpResponse(null, { status: 503 });
      }),
    );

    const sb = SecureBuffer.fromString("test-key");
    const result = await checkHibpPassword(sb);

    expect(result.checked).toBe(true);
    expect(result.found).toBe(false);
    expect(result.error).toContain("503");
    sb.dispose();
  });
});
