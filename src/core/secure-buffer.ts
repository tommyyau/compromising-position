import { createHash } from "node:crypto";

/**
 * Buffer wrapper that auto-zeroes memory on disposal.
 * Secrets should always be held in SecureBuffer, never plain strings.
 */
export class SecureBuffer {
  #buffer: Buffer;
  #disposed = false;

  private constructor(buffer: Buffer) {
    this.#buffer = buffer;
  }

  static fromBuffer(buf: Buffer): SecureBuffer {
    // Copy so caller can't mutate our internal buffer
    const copy = Buffer.alloc(buf.length);
    buf.copy(copy);
    return new SecureBuffer(copy);
  }

  static fromString(str: string): SecureBuffer {
    const buf = Buffer.from(str, "utf-8");
    return new SecureBuffer(buf);
  }

  get length(): number {
    this.#ensureNotDisposed();
    return this.#buffer.length;
  }

  get isDisposed(): boolean {
    return this.#disposed;
  }

  /** Returns the raw buffer — use sparingly, never store the reference. */
  unsafeGetBuffer(): Buffer {
    this.#ensureNotDisposed();
    return this.#buffer;
  }

  /** Returns the content as a UTF-8 string — use sparingly. */
  unsafeGetString(): string {
    this.#ensureNotDisposed();
    return this.#buffer.toString("utf-8");
  }

  sha1Hex(): string {
    this.#ensureNotDisposed();
    return createHash("sha1").update(this.#buffer).digest("hex").toUpperCase();
  }

  sha256Hex(): string {
    this.#ensureNotDisposed();
    return createHash("sha256")
      .update(this.#buffer)
      .digest("hex")
      .toLowerCase();
  }

  /** Zero out the buffer memory. */
  dispose(): void {
    if (!this.#disposed) {
      this.#buffer.fill(0);
      this.#disposed = true;
    }
  }

  /** Support `using` keyword (TC39 Explicit Resource Management). */
  [Symbol.dispose](): void {
    this.dispose();
  }

  /** Never accidentally leak the secret. */
  toString(): string {
    return "[SecureBuffer: REDACTED]";
  }

  toJSON(): string {
    return "[SecureBuffer: REDACTED]";
  }

  /** Node.js inspect — also redacted. */
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return "[SecureBuffer: REDACTED]";
  }

  #ensureNotDisposed(): void {
    if (this.#disposed) {
      throw new Error("SecureBuffer has been disposed");
    }
  }
}
