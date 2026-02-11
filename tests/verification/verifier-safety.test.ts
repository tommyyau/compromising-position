import { describe, it, expect } from "vitest";
import { openaiVerifier, openaiServiceVerifier } from "../../src/verification/openai-verifier.js";
import { anthropicVerifier } from "../../src/verification/anthropic-verifier.js";
import { githubPatVerifier, githubFineGrainedVerifier } from "../../src/verification/github-verifier.js";
import { awsVerifier } from "../../src/verification/aws-verifier.js";
import { slackBotVerifier, slackUserVerifier } from "../../src/verification/slack-verifier.js";

const allVerifiers = [
  openaiVerifier,
  openaiServiceVerifier,
  anthropicVerifier,
  githubPatVerifier,
  githubFineGrainedVerifier,
  awsVerifier,
  slackBotVerifier,
  slackUserVerifier,
];

describe("verifier safety", () => {
  it("all verifiers should have an endpoint defined", () => {
    for (const v of allVerifiers) {
      expect(v.endpoint).toBeTruthy();
      expect(v.endpoint.length).toBeGreaterThan(0);
    }
  });

  it("all verifiers should have a description", () => {
    for (const v of allVerifiers) {
      expect(v.description).toBeTruthy();
      expect(v.description).toContain("read-only");
    }
  });

  it("all verifier endpoints should be HTTPS", () => {
    for (const v of allVerifiers) {
      expect(v.endpoint).toMatch(/^https:\/\//);
    }
  });

  it("all verifiers should have a provider set", () => {
    for (const v of allVerifiers) {
      expect(v.provider).toBeTruthy();
    }
  });
});
