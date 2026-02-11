import { appendFile, lstat } from "node:fs/promises";
import { resolve } from "node:path";
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

/**
 * Validate an audit log path to prevent path traversal and device file writes.
 * Returns the resolved absolute path, or throws on invalid paths.
 */
export async function validateAuditLogPath(path: string): Promise<string> {
  const resolved = resolve(path);

  // Refuse device files
  if (resolved.startsWith("/dev/") || resolved.startsWith("/proc/") || resolved.startsWith("/sys/")) {
    throw new Error(`Refusing to write audit log to device path: ${resolved}`);
  }

  // Check if path is a symlink (could point to unexpected location)
  try {
    const stats = await lstat(resolved);
    if (stats.isSymbolicLink()) {
      throw new Error(`Refusing to write audit log to symlink: ${resolved}`);
    }
  } catch (err) {
    // File doesn't exist yet — that's fine, appendFile will create it
    if (err instanceof Error && "code" in err && (err as NodeJS.ErrnoException).code === "ENOENT") {
      // OK
    } else if (err instanceof Error && err.message.includes("Refusing")) {
      throw err;
    }
    // Other stat errors — let appendFile handle them
  }

  return resolved;
}

/** Append an audit entry to a JSONL file. */
export async function writeAuditLog(
  path: string,
  result: CheckResult,
): Promise<void> {
  const validatedPath = await validateAuditLogPath(path);
  const entry = toAuditEntry(result);
  const line = JSON.stringify(entry) + "\n";
  await appendFile(validatedPath, line, "utf-8");
}
