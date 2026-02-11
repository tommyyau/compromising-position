import { describe, it, expect } from "vitest";
import { formatSarif } from "../src/output/sarif.js";
import { formatCsv } from "../src/output/csv.js";
import type { CheckResult } from "../src/types/index.js";
import { KeyProvider } from "../src/types/index.js";

function makeResult(overrides: Partial<CheckResult> = {}): CheckResult {
  return {
    local: {
      identification: {
        provider: KeyProvider.OpenAI,
        confidence: "high",
        description: "OpenAI API key",
      },
      entropy: {
        shannonEntropy: 4.5,
        maxPossibleEntropy: 6,
        normalizedEntropy: 0.75,
        encoding: "mixed",
        length: 48,
        warning: null,
      },
      warnings: [],
      looksLikeSecret: true,
    },
    hibpPassword: {
      checked: true,
      found: true,
      occurrences: 100,
      hashPrefix: "5BAA6",
      error: null,
    },
    hibpEmail: null,
    pluginResults: [],
    verification: null,
    riskLevel: "critical",
    summary: "Identified as OpenAI — EXPOSED in 100 breach(es)",
    fingerprint: "abc123def456",
    timestamp: "2024-01-01T00:00:00.000Z",
    ...overrides,
  };
}

describe("formatSarif", () => {
  it("should produce valid SARIF structure", () => {
    const result = makeResult();
    const sarif = formatSarif([result]);
    const parsed = JSON.parse(sarif);

    expect(parsed.version).toBe("2.1.0");
    expect(parsed.$schema).toContain("sarif");
    expect(parsed.runs).toHaveLength(1);
    expect(parsed.runs[0].results).toHaveLength(1);
  });

  it("should map risk levels to SARIF levels", () => {
    const results = [
      makeResult({ riskLevel: "critical" }),
      makeResult({ riskLevel: "high", fingerprint: "fp2" }),
      makeResult({ riskLevel: "medium", fingerprint: "fp3" }),
      makeResult({ riskLevel: "low", fingerprint: "fp4" }),
    ];

    const sarif = JSON.parse(formatSarif(results));
    const levels = sarif.runs[0].results.map((r: any) => r.level);

    expect(levels).toEqual(["error", "error", "warning", "note"]);
  });

  it("should include fingerprint", () => {
    const sarif = JSON.parse(formatSarif([makeResult()]));
    const result = sarif.runs[0].results[0];

    expect(result.fingerprints.primaryLocationHash).toBe("abc123def456");
  });

  it("should handle multiple results", () => {
    const results = [
      makeResult({ fingerprint: "fp1" }),
      makeResult({ fingerprint: "fp2" }),
    ];

    const sarif = JSON.parse(formatSarif(results));
    expect(sarif.runs[0].results).toHaveLength(2);
  });
});

describe("formatCsv", () => {
  it("should produce valid CSV with header", () => {
    const csv = formatCsv([makeResult()]);
    const lines = csv.split("\n");

    expect(lines[0]).toBe(
      "fingerprint,provider,confidence,risk_level,hibp_found,hibp_occurrences,entropy,summary,timestamp",
    );
    expect(lines).toHaveLength(2);
  });

  it("should escape values with commas", () => {
    const result = makeResult({
      summary: "Found in 100, maybe more",
    });
    const csv = formatCsv([result]);

    expect(csv).toContain('"Found in 100, maybe more"');
  });

  it("should include all fields", () => {
    const csv = formatCsv([makeResult()]);
    const dataLine = csv.split("\n")[1]!;
    const fields = dataLine.split(",");

    // fingerprint, provider, confidence, risk, found, occurrences, entropy
    expect(fields[0]).toBe("abc123def456");
    expect(fields[1]).toBe("OpenAI");
    expect(fields[2]).toBe("high");
    expect(fields[3]).toBe("critical");
    expect(fields[4]).toBe("true");
    expect(fields[5]).toBe("100");
  });

  it("should handle multiple results", () => {
    const csv = formatCsv([
      makeResult({ fingerprint: "fp1" }),
      makeResult({ fingerprint: "fp2" }),
    ]);

    expect(csv.split("\n")).toHaveLength(3); // header + 2 rows
  });
});
