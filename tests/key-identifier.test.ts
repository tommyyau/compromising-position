import { describe, it, expect } from "vitest";
import { identifyKey } from "../src/core/key-identifier.js";
import { KeyProvider } from "../src/types/index.js";

describe("identifyKey", () => {
  it("should identify OpenAI project keys", () => {
    const key = "sk-proj-" + "a".repeat(100);
    const result = identifyKey(key);
    expect(result.provider).toBe(KeyProvider.OpenAI);
    expect(result.confidence).toBe("high");
  });

  it("should identify OpenAI service account keys", () => {
    const key = "sk-svcacct-" + "b".repeat(100);
    const result = identifyKey(key);
    expect(result.provider).toBe(KeyProvider.OpenAIService);
    expect(result.confidence).toBe("high");
  });

  it("should identify Anthropic keys", () => {
    const key = "sk-ant-api03-" + "c".repeat(95);
    const result = identifyKey(key);
    expect(result.provider).toBe(KeyProvider.Anthropic);
    expect(result.confidence).toBe("high");
  });

  it("should identify AWS access key IDs", () => {
    const result = identifyKey("AKIAIOSFODNN7EXAMPLE");
    expect(result.provider).toBe(KeyProvider.AWS);
    expect(result.confidence).toBe("high");
  });

  it("should identify GitHub PATs", () => {
    const key = "ghp_" + "a".repeat(36);
    const result = identifyKey(key);
    expect(result.provider).toBe(KeyProvider.GitHubPAT);
    expect(result.confidence).toBe("high");
  });

  it("should identify GitHub fine-grained tokens", () => {
    const key = "github_pat_" + "a".repeat(22) + "_" + "b".repeat(59);
    const result = identifyKey(key);
    expect(result.provider).toBe(KeyProvider.GitHubFineGrained);
    expect(result.confidence).toBe("high");
  });

  it("should identify Stripe live keys", () => {
    const key = "sk_live_" + "a".repeat(24);
    const result = identifyKey(key);
    expect(result.provider).toBe(KeyProvider.StripeLive);
    expect(result.confidence).toBe("high");
  });

  it("should identify Stripe test keys", () => {
    const key = "sk_test_" + "a".repeat(24);
    const result = identifyKey(key);
    expect(result.provider).toBe(KeyProvider.StripeTest);
    expect(result.confidence).toBe("high");
  });

  it("should identify Google API keys", () => {
    const result = identifyKey("AIzaSyA1234567890abcdefghijklmnopqrstuv");
    expect(result.provider).toBe(KeyProvider.GoogleAPI);
    expect(result.confidence).toBe("high");
  });

  it("should identify SendGrid keys", () => {
    const key = "SG." + "a".repeat(22) + "." + "b".repeat(43);
    const result = identifyKey(key);
    expect(result.provider).toBe(KeyProvider.SendGrid);
    expect(result.confidence).toBe("high");
  });

  it("should identify Twilio keys", () => {
    const result = identifyKey("SK" + "a".repeat(32));
    expect(result.provider).toBe(KeyProvider.Twilio);
    expect(result.confidence).toBe("high");
  });

  it("should identify Mailgun keys", () => {
    const result = identifyKey("key-" + "a".repeat(32));
    expect(result.provider).toBe(KeyProvider.Mailgun);
    expect(result.confidence).toBe("high");
  });

  it("should identify Telegram bot tokens", () => {
    const result = identifyKey("123456789:" + "A".repeat(35));
    expect(result.provider).toBe(KeyProvider.TelegramBot);
    expect(result.confidence).toBe("high");
  });

  it("should return Unknown for unrecognized formats", () => {
    const result = identifyKey("some-random-string");
    expect(result.provider).toBe(KeyProvider.Unknown);
    expect(result.confidence).toBe("low");
  });

  it("should handle whitespace trimming", () => {
    const key = "  AKIAIOSFODNN7EXAMPLE  ";
    const result = identifyKey(key);
    expect(result.provider).toBe(KeyProvider.AWS);
  });
});
