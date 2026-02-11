import { readFileSync } from "node:fs";
import { SecureBuffer } from "../core/secure-buffer.js";

export interface BatchEntry {
  name: string;
  secret: SecureBuffer;
}

/**
 * Parse a .env file into batch entries.
 * Supports KEY=VALUE and KEY="VALUE" formats.
 * Skips comments (#) and empty lines.
 */
export function parseEnvFile(path: string): BatchEntry[] {
  const content = readFileSync(path, "utf-8");
  return parseEnvString(content);
}

export function parseEnvString(content: string): BatchEntry[] {
  const entries: BatchEntry[] = [];

  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    // Skip empty lines and comments
    if (!trimmed || trimmed.startsWith("#")) continue;

    const eqIndex = trimmed.indexOf("=");
    if (eqIndex === -1) continue;

    const name = trimmed.slice(0, eqIndex).trim();
    let value = trimmed.slice(eqIndex + 1).trim();

    // Strip surrounding quotes
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (!name || !value) continue;

    entries.push({
      name,
      secret: SecureBuffer.fromString(value),
    });
  }

  return entries;
}

/**
 * Parse a JSON file into batch entries.
 * Expects { "KEY_NAME": "secret_value", ... }
 */
export function parseJsonFile(path: string): BatchEntry[] {
  const content = readFileSync(path, "utf-8");
  return parseJsonString(content);
}

export function parseJsonString(content: string): BatchEntry[] {
  const data = JSON.parse(content) as Record<string, unknown>;
  const entries: BatchEntry[] = [];

  for (const [name, value] of Object.entries(data)) {
    if (typeof value === "string" && value.length > 0) {
      entries.push({
        name,
        secret: SecureBuffer.fromString(value),
      });
    }
  }

  return entries;
}

/** Dispose all SecureBuffers in a batch. */
export function disposeBatch(entries: BatchEntry[]): void {
  for (const entry of entries) {
    entry.secret.dispose();
  }
}
