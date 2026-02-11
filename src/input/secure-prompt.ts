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
      // Strip trailing newline that shells typically add.
      // Note: combined.subarray() returns a view, not a copy.
      // SecureBuffer.fromBuffer() copies the data before we zero combined.
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

    process.stdin.on("error", (err) => {
      // Zero any accumulated data before rejecting
      for (const chunk of chunks) {
        chunk.fill(0);
      }
      reject(err);
    });
  });
}

/** Max input length for TTY (4 KiB should be sufficient for any API key). */
const TTY_BUFFER_SIZE = 4096;

async function readFromTTY(): Promise<SecureBuffer> {
  process.stderr.write("Enter secret (input hidden): ");

  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;

    // Accumulate input directly into a Buffer (not strings) so we can zero it.
    const buf = Buffer.alloc(TTY_BUFFER_SIZE);
    let pos = 0;

    stdin.setRawMode(true);
    stdin.resume();

    const cleanup = () => {
      stdin.setRawMode(wasRaw ?? false);
      stdin.pause();
      stdin.removeListener("data", onData);
    };

    const onData = (data: Buffer) => {
      // data is a Buffer in raw mode when encoding is not set
      for (let i = 0; i < data.length; i++) {
        const byte = data[i]!;

        // Ctrl+C (0x03)
        if (byte === 0x03) {
          cleanup();
          process.stderr.write("\n");
          buf.fill(0);
          reject(new Error("Aborted"));
          return;
        }

        // Enter (CR=0x0d or LF=0x0a)
        if (byte === 0x0d || byte === 0x0a) {
          cleanup();
          process.stderr.write("\n");
          const secret = SecureBuffer.fromBuffer(buf.subarray(0, pos));
          buf.fill(0);
          resolve(secret);
          return;
        }

        // Backspace (0x7f) or BS (0x08)
        if (byte === 0x7f || byte === 0x08) {
          if (pos > 0) {
            pos--;
            buf[pos] = 0; // Zero the removed byte
          }
          continue;
        }

        // Regular byte — don't echo. Silently discard if buffer full.
        if (pos < TTY_BUFFER_SIZE) {
          buf[pos] = byte;
          pos++;
        }
      }
    };

    stdin.on("data", onData);
  });
}
