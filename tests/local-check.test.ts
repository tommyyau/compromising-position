import { describe, it, expect } from "vitest";
import { performLocalCheck } from "../src/checks/local-check.js";
import { SecureBuffer } from "../src/core/secure-buffer.js";
import { KeyProvider } from "../src/types/index.js";

describe("performLocalCheck", () => {
  it("should identify a known provider key", () => {
    const sb = SecureBuffer.fromString("AKIAIOSFODNN7EXAMPLE");
    const result = performLocalCheck(sb);
    expect(result.identification.provider).toBe(KeyProvider.AWS);
    expect(result.looksLikeSecret).toBe(true);
    sb.dispose();
  });

  it("should flag short inputs", () => {
    const sb = SecureBuffer.fromString("abc");
    const result = performLocalCheck(sb);
    expect(result.warnings.some((w) => w.includes("short"))).toBe(true);
    expect(result.looksLikeSecret).toBe(false);
    sb.dispose();
  });

  it("should flag low entropy unknown strings", () => {
    const sb = SecureBuffer.fromString("aaaaaaaaaaaaaaaa");
    const result = performLocalCheck(sb);
    expect(result.identification.provider).toBe(KeyProvider.Unknown);
    expect(
      result.warnings.some((w) => w.includes("low entropy") || w.includes("Low entropy")),
    ).toBe(true);
    sb.dispose();
  });

  it("should consider high-entropy unknown strings as possible secrets", () => {
    const sb = SecureBuffer.fromString(
      "xK9mP2qR7sT4uV8wZ1aB3cD6eF0gH5iJ",
    );
    const result = performLocalCheck(sb);
    expect(result.looksLikeSecret).toBe(true);
    sb.dispose();
  });

  it("should add warning for Stripe test keys", () => {
    const sb = SecureBuffer.fromString("sk_test_" + "a".repeat(24));
    const result = performLocalCheck(sb);
    expect(result.identification.provider).toBe(KeyProvider.StripeTest);
    expect(result.warnings.some((w) => w.includes("TEST"))).toBe(true);
    sb.dispose();
  });
});
