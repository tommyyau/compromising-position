import { createHash } from "node:crypto";

/**
 * Buffer wrapper that auto-zeroes memory on disposal.
 * Secrets should always be held in SecureBuffer, never plain strings.
 *
 * SECURITY NOTE: Prefer fromBuffer() over fromString(). JavaScript strings
 * are immutable and cannot be zeroed from memory — they persist on the V8
 * heap until garbage collected. fromString() is provided for convenience
 * but the caller's original string will remain in memory.
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

  /**
   * @deprecated Prefer fromBuffer() — JS strings are immutable and cannot
   * be zeroed from memory. The original `str` will persist until GC.
   */
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

  /**
   * Returns the raw buffer. The caller MUST NOT store the reference
   * beyond immediate use, and MUST NOT mutate it.
   */
  unsafeGetBuffer(): Buffer {
    this.#ensureNotDisposed();
    return this.#buffer;
  }

  /**
   * Returns the content as a UTF-8 string.
   *
   * SECURITY WARNING: The returned string is immutable and cannot be
   * zeroed from memory. Minimize use and scope of the return value.
   */
  unsafeGetString(): string {
    this.#ensureNotDisposed();
    return this.#buffer.toString("utf-8");
  }

  /** Returns full SHA-1 as an uppercase hex string. */
  sha1Hex(): string {
    this.#ensureNotDisposed();
    return createHash("sha1").update(this.#buffer).digest("hex").toUpperCase();
  }

  /**
   * Returns SHA-1 as a raw Buffer (20 bytes). Caller is responsible
   * for zeroing this buffer when done.
   */
  sha1Buffer(): Buffer {
    this.#ensureNotDisposed();
    return createHash("sha1").update(this.#buffer).digest();
  }

  sha256Hex(): string {
    this.#ensureNotDisposed();
    return createHash("sha256")
      .update(this.#buffer)
      .digest("hex")
      .toLowerCase();
  }

  /**
   * Test whether the buffer content matches a regex pattern.
   * Internally creates a temporary string, but the scope is minimized
   * to this method call. This avoids exposing the string to callers.
   */
  testPattern(pattern: RegExp): boolean {
    this.#ensureNotDisposed();
    return pattern.test(this.#buffer.toString("utf-8"));
  }

  /**
   * Apply a function to the buffer's string representation.
   * The temporary string is scoped to the callback, minimizing exposure.
   * Returns the callback's result without exposing the string to callers.
   */
  withString<T>(fn: (s: string) => T): T {
    this.#ensureNotDisposed();
    return fn(this.#buffer.toString("utf-8"));
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
