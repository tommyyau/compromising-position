import { describe, it, expect } from "vitest";
import { SecureBuffer } from "../src/core/secure-buffer.js";

describe("SecureBuffer", () => {
  it("should create from string and return content", () => {
    const sb = SecureBuffer.fromString("test-secret");
    expect(sb.unsafeGetString()).toBe("test-secret");
    expect(sb.length).toBe(11);
    sb.dispose();
  });

  it("should create from buffer and return content", () => {
    const buf = Buffer.from("hello");
    const sb = SecureBuffer.fromBuffer(buf);
    expect(sb.unsafeGetString()).toBe("hello");
    // Mutating original buffer should not affect SecureBuffer
    buf.fill(0);
    expect(sb.unsafeGetString()).toBe("hello");
    sb.dispose();
  });

  it("should produce correct SHA-1 hex", () => {
    const sb = SecureBuffer.fromString("password");
    // SHA-1 of "password" is well-known
    expect(sb.sha1Hex()).toBe("5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    sb.dispose();
  });

  it("should produce correct SHA-256 hex", () => {
    const sb = SecureBuffer.fromString("password");
    expect(sb.sha256Hex()).toBe(
      "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    );
    sb.dispose();
  });

  it("should zero buffer on dispose", () => {
    const sb = SecureBuffer.fromString("secret-key");
    const buf = sb.unsafeGetBuffer();
    sb.dispose();
    // All bytes should be zero
    for (let i = 0; i < buf.length; i++) {
      expect(buf[i]).toBe(0);
    }
  });

  it("should throw after dispose", () => {
    const sb = SecureBuffer.fromString("test");
    sb.dispose();
    expect(sb.isDisposed).toBe(true);
    expect(() => sb.unsafeGetString()).toThrow("SecureBuffer has been disposed");
    expect(() => sb.unsafeGetBuffer()).toThrow("SecureBuffer has been disposed");
    expect(() => sb.sha1Hex()).toThrow("SecureBuffer has been disposed");
    expect(() => sb.sha256Hex()).toThrow("SecureBuffer has been disposed");
    expect(() => sb.length).toThrow("SecureBuffer has been disposed");
  });

  it("should never leak secrets in toString/toJSON", () => {
    const sb = SecureBuffer.fromString("super-secret-key");
    expect(sb.toString()).toBe("[SecureBuffer: REDACTED]");
    expect(sb.toJSON()).toBe("[SecureBuffer: REDACTED]");
    expect(JSON.stringify({ key: sb })).toBe('{"key":"[SecureBuffer: REDACTED]"}');
    sb.dispose();
  });

  it("should be idempotent on multiple dispose calls", () => {
    const sb = SecureBuffer.fromString("test");
    sb.dispose();
    sb.dispose(); // should not throw
    expect(sb.isDisposed).toBe(true);
  });
});
