import { describe, it, expect } from "vitest";
import {
  shannonEntropy,
  shannonEntropyFromBuffer,
  detectEncoding,
  detectEncodingFromBuffer,
  analyzeEntropy,
  analyzeEntropyFromBuffer,
} from "../src/core/entropy.js";
import { SecureBuffer } from "../src/core/secure-buffer.js";

describe("shannonEntropy", () => {
  it("should return 0 for empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("should return 0 for single repeated character", () => {
    expect(shannonEntropy("aaaaaaa")).toBe(0);
  });

  it("should return 1.0 for two equally frequent characters", () => {
    expect(shannonEntropy("abababab")).toBeCloseTo(1.0, 5);
  });

  it("should produce high entropy for random-looking strings", () => {
    const entropy = shannonEntropy("aB3$xY7!mK9@pL2&");
    expect(entropy).toBeGreaterThan(3.5);
  });

  it("should produce moderate entropy for hex strings", () => {
    const entropy = shannonEntropy("a94b1c2d3e4f5a6b");
    expect(entropy).toBeGreaterThan(3.0);
  });
});

describe("shannonEntropyFromBuffer", () => {
  it("should return 0 for empty buffer", () => {
    expect(shannonEntropyFromBuffer(Buffer.alloc(0))).toBe(0);
  });

  it("should return 0 for single repeated byte", () => {
    expect(shannonEntropyFromBuffer(Buffer.from("aaaaaaa"))).toBe(0);
  });

  it("should match string-based entropy for ASCII input", () => {
    const data = "aB3xY7mK9pL2";
    const fromString = shannonEntropy(data);
    const fromBuffer = shannonEntropyFromBuffer(Buffer.from(data));
    expect(fromBuffer).toBeCloseTo(fromString, 10);
  });
});

describe("detectEncoding", () => {
  it("should detect hex", () => {
    expect(detectEncoding("a94b1c2d3e4f")).toBe("hex");
  });

  it("should detect base64", () => {
    expect(detectEncoding("SGVsbG8gV29ybGQ=")).toBe("base64");
  });

  it("should detect base62", () => {
    expect(detectEncoding("abc123XYZ")).toBe("base62");
  });

  it("should detect alphanumeric with underscores/hyphens", () => {
    expect(detectEncoding("abc_123-XYZ")).toBe("alphanumeric");
  });

  it("should detect mixed for special characters", () => {
    expect(detectEncoding("hello world!@#")).toBe("mixed");
  });
});

describe("detectEncodingFromBuffer", () => {
  it("should detect hex", () => {
    expect(detectEncodingFromBuffer(Buffer.from("a94b1c2d3e4f"))).toBe("hex");
  });

  it("should detect base64", () => {
    expect(detectEncodingFromBuffer(Buffer.from("SGVsbG8gV29ybGQ="))).toBe("base64");
  });

  it("should detect base62", () => {
    expect(detectEncodingFromBuffer(Buffer.from("abc123XYZ"))).toBe("base62");
  });

  it("should detect alphanumeric", () => {
    expect(detectEncodingFromBuffer(Buffer.from("abc_123-XYZ"))).toBe("alphanumeric");
  });
});

describe("analyzeEntropy", () => {
  it("should warn on very short inputs", () => {
    const result = analyzeEntropy("abc");
    expect(result.warning).toContain("short");
    expect(result.length).toBe(3);
  });

  it("should warn on low entropy", () => {
    const result = analyzeEntropy("aaaaaaaaaa");
    expect(result.warning).toContain("low entropy");
  });

  it("should not warn on high-entropy long strings", () => {
    const result = analyzeEntropy("sk-proj-aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4yZ5");
    expect(result.warning).toBeNull();
  });
});

describe("analyzeEntropyFromBuffer", () => {
  it("should produce consistent results with string version", () => {
    const data = "AKIAIOSFODNN7EXAMPLE";
    const fromString = analyzeEntropy(data);
    const sb = SecureBuffer.fromString(data);
    const fromBuffer = analyzeEntropyFromBuffer(sb);
    sb.dispose();

    expect(fromBuffer.shannonEntropy).toBe(fromString.shannonEntropy);
    expect(fromBuffer.encoding).toBe(fromString.encoding);
    expect(fromBuffer.length).toBe(fromString.length);
  });

  it("should trim whitespace from buffer", () => {
    const sb = SecureBuffer.fromString("  test  ");
    const result = analyzeEntropyFromBuffer(sb);
    expect(result.length).toBe(4); // "test" without whitespace
    sb.dispose();
  });
});
