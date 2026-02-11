import { describe, it, expect } from "vitest";
import { fingerprint } from "../src/core/fingerprint.js";
import { SecureBuffer } from "../src/core/secure-buffer.js";

describe("fingerprint", () => {
  it("should return first 16 hex characters of SHA-256", () => {
    const sb = SecureBuffer.fromString("test-key");
    const fp = fingerprint(sb);
    expect(fp).toHaveLength(16);
    expect(fp).toMatch(/^[0-9a-f]{16}$/);
    // Verify it matches actual SHA-256 prefix
    expect(sb.sha256Hex().startsWith(fp)).toBe(true);
    sb.dispose();
  });

  it("should produce different fingerprints for different inputs", () => {
    const sb1 = SecureBuffer.fromString("key-one");
    const sb2 = SecureBuffer.fromString("key-two");
    expect(fingerprint(sb1)).not.toBe(fingerprint(sb2));
    sb1.dispose();
    sb2.dispose();
  });

  it("should produce consistent fingerprints", () => {
    const sb1 = SecureBuffer.fromString("consistent-key");
    const sb2 = SecureBuffer.fromString("consistent-key");
    expect(fingerprint(sb1)).toBe(fingerprint(sb2));
    sb1.dispose();
    sb2.dispose();
  });
});
