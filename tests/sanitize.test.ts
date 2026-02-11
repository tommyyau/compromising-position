import { describe, it, expect } from "vitest";
import { sanitizeForTerminal } from "../src/core/sanitize.js";

describe("sanitizeForTerminal", () => {
  it("should pass through normal text", () => {
    expect(sanitizeForTerminal("hello world")).toBe("hello world");
  });

  it("should strip ANSI escape sequences (CSI)", () => {
    expect(sanitizeForTerminal("\x1b[2J\x1b[HFake output")).toBe("Fake output");
  });

  it("should strip OSC escape sequences (title setting)", () => {
    expect(sanitizeForTerminal("\x1b]0;pwned\x07safe text")).toBe("safe text");
  });

  it("should strip control characters", () => {
    expect(sanitizeForTerminal("before\x00\x01\x02\x03after")).toBe("beforeafter");
  });

  it("should preserve newlines and tabs", () => {
    expect(sanitizeForTerminal("line1\nline2\ttab")).toBe("line1\nline2\ttab");
  });

  it("should strip cursor movement sequences", () => {
    expect(sanitizeForTerminal("\x1b[10;20H\x1b[KOverwritten")).toBe("Overwritten");
  });

  it("should strip color codes embedded in error messages", () => {
    const malicious = "\x1b[32mNo breaches found\x1b[0m (actually found 500)";
    const cleaned = sanitizeForTerminal(malicious);
    expect(cleaned).not.toContain("\x1b");
    expect(cleaned).toContain("actually found 500");
  });

  it("should handle empty string", () => {
    expect(sanitizeForTerminal("")).toBe("");
  });
});
