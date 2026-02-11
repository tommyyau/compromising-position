import type { CheckResult } from "../types/index.js";

/** Escape a value for CSV (RFC 4180). */
function csvEscape(value: string): string {
  if (value.includes(",") || value.includes('"') || value.includes("\n")) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

/**
 * Format check results as CSV.
 */
export function formatCsv(results: CheckResult[]): string {
  const header = "fingerprint,provider,confidence,risk_level,hibp_found,hibp_occurrences,entropy,summary,timestamp";
  const rows = results.map((r) => {
    return [
      r.fingerprint,
      csvEscape(r.local.identification.provider),
      r.local.identification.confidence,
      r.riskLevel,
      r.hibpPassword?.found ?? "",
      r.hibpPassword?.occurrences ?? "",
      r.local.entropy.shannonEntropy,
      csvEscape(r.summary),
      r.timestamp,
    ].join(",");
  });

  return [header, ...rows].join("\n");
}
