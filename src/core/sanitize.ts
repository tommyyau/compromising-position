/**
 * Sanitize a string for safe terminal output.
 * Strips ANSI escape sequences and non-printable control characters
 * to prevent terminal escape injection attacks.
 */
export function sanitizeForTerminal(s: string): string {
  return s
    // Remove ANSI escape sequences (CSI, OSC, etc.)
    .replace(/\x1b\[[0-9;]*[A-Za-z]/g, "")
    .replace(/\x1b\][^\x07]*\x07/g, "")
    .replace(/\x1b[^[\]]/g, "")
    // Remove non-printable control characters (keep newline \n and tab \t)
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/g, "");
}
