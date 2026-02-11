import { describe, it, expect } from "vitest";
import { shannonEntropy, detectEncoding, analyzeEntropy } from "../src/core/entropy.js";

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
