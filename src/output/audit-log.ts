import { appendFile } from "node:fs/promises";
import type { AuditEntry, CheckResult } from "../types/index.js";

/** Convert a CheckResult to an audit entry (no secrets, only fingerprint). */
export function toAuditEntry(result: CheckResult): AuditEntry {
  return {
    timestamp: result.timestamp,
    fingerprint: result.fingerprint,
    provider: result.local.identification.provider,
    riskLevel: result.riskLevel,
    hibpFound: result.hibpPassword?.found ?? null,
    summary: result.summary,
  };
}

/** Append an audit entry to a JSONL file. */
export async function writeAuditLog(
  path: string,
  result: CheckResult,
): Promise<void> {
  const entry = toAuditEntry(result);
  const line = JSON.stringify(entry) + "\n";
  await appendFile(path, line, "utf-8");
}
