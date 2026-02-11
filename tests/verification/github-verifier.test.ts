import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { githubPatVerifier } from "../../src/verification/github-verifier.js";
import { SecureBuffer } from "../../src/core/secure-buffer.js";

const server = setupServer(
  http.get("https://api.github.com/user", ({ request }) => {
    const auth = request.headers.get("Authorization");
    if (auth === "Bearer ghp_valid_token") {
      return new HttpResponse(JSON.stringify({ login: "testuser" }), {
        status: 200,
        headers: {
          "x-oauth-scopes": "repo, user",
        },
      });
    }
    return new HttpResponse(null, { status: 401 });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("githubPatVerifier", () => {
  it("should detect an active key with scopes", async () => {
    const sb = SecureBuffer.fromString("ghp_valid_token");
    const result = await githubPatVerifier.verify(sb);
    sb.dispose();

    expect(result.active).toBe(true);
    expect(result.details).toContain("scopes: repo, user");
  });

  it("should detect an invalid key", async () => {
    const sb = SecureBuffer.fromString("ghp_invalid_token");
    const result = await githubPatVerifier.verify(sb);
    sb.dispose();

    expect(result.active).toBe(false);
    expect(result.details).toContain("invalid or revoked");
  });

  it("should handle network errors", async () => {
    server.use(
      http.get("https://api.github.com/user", () => {
        return HttpResponse.error();
      }),
    );

    const sb = SecureBuffer.fromString("ghp_test");
    const result = await githubPatVerifier.verify(sb);
    sb.dispose();

    expect(result.active).toBe(false);
    expect(result.error).toContain("Network error");
  });
});
