import { describe, it, expect, beforeAll, afterAll, afterEach } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { slackBotVerifier } from "../../src/verification/slack-verifier.js";
import { SecureBuffer } from "../../src/core/secure-buffer.js";

const server = setupServer(
  http.post("https://slack.com/api/auth.test", ({ request }) => {
    const auth = request.headers.get("Authorization");
    if (auth === "Bearer xoxb-valid-token") {
      return HttpResponse.json({
        ok: true,
        team: "TestTeam",
        user: "testbot",
      });
    }
    return HttpResponse.json({
      ok: false,
      error: "invalid_auth",
    });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: "bypass" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("slackBotVerifier", () => {
  it("should detect an active token", async () => {
    const sb = SecureBuffer.fromString("xoxb-valid-token");
    const result = await slackBotVerifier.verify(sb);
    sb.dispose();

    expect(result.active).toBe(true);
    expect(result.details).toContain("team: TestTeam");
    expect(result.details).toContain("user: testbot");
  });

  it("should detect an invalid token", async () => {
    const sb = SecureBuffer.fromString("xoxb-invalid-token");
    const result = await slackBotVerifier.verify(sb);
    sb.dispose();

    expect(result.active).toBe(false);
    expect(result.details).toContain("invalid_auth");
  });

  it("should handle network errors", async () => {
    server.use(
      http.post("https://slack.com/api/auth.test", () => {
        return HttpResponse.error();
      }),
    );

    const sb = SecureBuffer.fromString("xoxb-test");
    const result = await slackBotVerifier.verify(sb);
    sb.dispose();

    expect(result.active).toBe(false);
    expect(result.error).toContain("Network error");
  });
});
