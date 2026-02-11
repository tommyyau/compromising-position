import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { anthropicVerifier } from "../../src/verification/anthropic-verifier.js";
import { SecureBuffer } from "../../src/core/secure-buffer.js";

const server = setupServer(
  http.get("https://api.anthropic.com/v1/models", ({ request }) => {
    const apiKey = request.headers.get("x-api-key");
    if (apiKey === "sk-ant-valid") {
      return HttpResponse.json({ data: [{ id: "claude-3" }] });
    }
    return new HttpResponse(null, { status: 401 });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("anthropicVerifier", () => {
  it("should detect an active key", async () => {
    const sb = SecureBuffer.fromString("sk-ant-valid");
    const result = await anthropicVerifier.verify(sb);
    sb.dispose();

    expect(result.active).toBe(true);
    expect(result.details).toContain("active");
  });

  it("should detect an invalid key", async () => {
    const sb = SecureBuffer.fromString("sk-ant-invalid");
    const result = await anthropicVerifier.verify(sb);
    sb.dispose();

    expect(result.active).toBe(false);
    expect(result.details).toContain("invalid or revoked");
  });

  it("should handle network errors", async () => {
    server.use(
      http.get("https://api.anthropic.com/v1/models", () => {
        return HttpResponse.error();
      }),
    );

    const sb = SecureBuffer.fromString("sk-ant-test");
    const result = await anthropicVerifier.verify(sb);
    sb.dispose();

    expect(result.active).toBe(false);
    expect(result.error).toContain("Network error");
  });
});
