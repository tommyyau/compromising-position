import { SecureBuffer } from "../core/secure-buffer.js";

/**
 * Read a secret from stdin.
 *
 * - If stdin is a pipe: reads all data from the pipe.
 * - If stdin is a TTY: prompts interactively with hidden input.
 *
 * Always returns a SecureBuffer (Buffer-backed, not String).
 */
export async function readSecret(): Promise<SecureBuffer> {
  if (!process.stdin.isTTY) {
    return readFromPipe();
  }
  return readFromTTY();
}

async function readFromPipe(): Promise<SecureBuffer> {
  const chunks: Buffer[] = [];

  return new Promise((resolve, reject) => {
    process.stdin.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
    });

    process.stdin.on("end", () => {
      const combined = Buffer.concat(chunks);
      // Strip trailing newline that shells typically add
      let end = combined.length;
      while (end > 0 && (combined[end - 1] === 0x0a || combined[end - 1] === 0x0d)) {
        end--;
      }
      const trimmed = combined.subarray(0, end);
      const secret = SecureBuffer.fromBuffer(trimmed);
      // Zero the intermediate buffers
      for (const chunk of chunks) {
        chunk.fill(0);
      }
      combined.fill(0);
      resolve(secret);
    });

    process.stdin.on("error", reject);
  });
}

async function readFromTTY(): Promise<SecureBuffer> {
  process.stderr.write("Enter secret (input hidden): ");

  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;

    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf-8");

    const chunks: string[] = [];

    const onData = (key: string) => {
      const code = key.charCodeAt(0);

      // Ctrl+C
      if (code === 3) {
        stdin.setRawMode(wasRaw ?? false);
        stdin.pause();
        stdin.removeListener("data", onData);
        process.stderr.write("\n");
        reject(new Error("Aborted"));
        return;
      }

      // Enter
      if (code === 13 || code === 10) {
        stdin.setRawMode(wasRaw ?? false);
        stdin.pause();
        stdin.removeListener("data", onData);
        process.stderr.write("\n");

        const combined = chunks.join("");
        const secret = SecureBuffer.fromString(combined);
        // Clear the chunks
        chunks.length = 0;
        resolve(secret);
        return;
      }

      // Backspace
      if (code === 127 || code === 8) {
        chunks.pop();
        return;
      }

      // Regular character — don't echo
      chunks.push(key);
    };

    stdin.on("data", onData);
  });
}
