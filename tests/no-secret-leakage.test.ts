import { describe, it, expect } from "vitest";
import { SecureBuffer } from "../src/core/secure-buffer.js";
import { fingerprint } from "../src/core/fingerprint.js";

describe("no secret leakage", () => {
  const SECRET = "sk-proj-THIS_IS_A_FAKE_TEST_SECRET_DO_NOT_USE_" + "x".repeat(60);

  it("should not leak secret through toString", () => {
    const sb = SecureBuffer.fromString(SECRET);
    const str = String(sb);
    expect(str).not.toContain("sk-proj");
    expect(str).not.toContain("FAKE_TEST_SECRET");
    expect(str).toBe("[SecureBuffer: REDACTED]");
    sb.dispose();
  });

  it("should not leak secret through JSON.stringify", () => {
    const sb = SecureBuffer.fromString(SECRET);
    const json = JSON.stringify({ key: sb, other: "data" });
    expect(json).not.toContain("sk-proj");
    expect(json).not.toContain("FAKE_TEST_SECRET");
    sb.dispose();
  });

  it("should not leak secret through template literals", () => {
    const sb = SecureBuffer.fromString(SECRET);
    const output = `The key is: ${sb}`;
    expect(output).not.toContain("sk-proj");
    expect(output).toContain("REDACTED");
    sb.dispose();
  });

  it("should not leak secret through fingerprint", () => {
    const sb = SecureBuffer.fromString(SECRET);
    const fp = fingerprint(sb);
    // Fingerprint is only 16 hex chars — cannot reconstruct the secret
    expect(fp).toHaveLength(16);
    expect(fp).not.toContain("sk-proj");
    sb.dispose();
  });

  it("should zero memory after dispose", () => {
    const sb = SecureBuffer.fromString(SECRET);
    const buf = sb.unsafeGetBuffer();

    // Before dispose: buffer should contain the secret
    expect(buf.toString("utf-8")).toContain("sk-proj");

    sb.dispose();

    // After dispose: all bytes should be zero
    const allZero = buf.every((byte) => byte === 0);
    expect(allZero).toBe(true);
  });
});
