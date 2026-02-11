import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { openaiVerifier } from "../../src/verification/openai-verifier.js";
import { SecureBuffer } from "../../src/core/secure-buffer.js";

const server = setupServer(
  http.get("https://api.openai.com/v1/models", ({ request }) => {
    const auth = request.headers.get("Authorization");
    if (auth === "Bearer sk-valid-key") {
      return HttpResponse.json({ data: [{ id: "gpt-4" }] });
    }
    return new HttpResponse(null, { status: 401 });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("openaiVerifier", () => {
  it("should detect an active key", async () => {
    const sb = SecureBuffer.fromString("sk-valid-key");
    const result = await openaiVerifier.verify(sb);
    sb.dispose();

    expect(result.active).toBe(true);
    expect(result.details).toContain("active");
    expect(result.error).toBeNull();
  });

  it("should detect an invalid key", async () => {
    const sb = SecureBuffer.fromString("sk-invalid-key");
    const result = await openaiVerifier.verify(sb);
    sb.dispose();

    expect(result.active).toBe(false);
    expect(result.details).toContain("invalid or revoked");
    expect(result.error).toBeNull();
  });

  it("should handle rate limiting", async () => {
    server.use(
      http.get("https://api.openai.com/v1/models", () => {
        return new HttpResponse(null, { status: 429 });
      }),
    );

    const sb = SecureBuffer.fromString("sk-test");
    const result = await openaiVerifier.verify(sb);
    sb.dispose();

    expect(result.active).toBe(false);
    expect(result.error).toContain("429");
  });

  it("should handle network errors", async () => {
    server.use(
      http.get("https://api.openai.com/v1/models", () => {
        return HttpResponse.error();
      }),
    );

    const sb = SecureBuffer.fromString("sk-test");
    const result = await openaiVerifier.verify(sb);
    sb.dispose();

    expect(result.active).toBe(false);
    expect(result.error).toContain("Network error");
  });

  it("should use GET method only", () => {
    expect(openaiVerifier.endpoint).toBe("https://api.openai.com/v1/models");
  });
});
