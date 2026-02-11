import type { KeyProvider } from "../types/index.js";
import type { KeyVerifier } from "./verifier.js";

/**
 * Registry mapping KeyProvider enum values to their verifier implementations.
 */
export class VerifierRegistry {
  readonly #verifiers = new Map<KeyProvider, KeyVerifier>();

  register(verifier: KeyVerifier): void {
    this.#verifiers.set(verifier.provider, verifier);
  }

  get(provider: KeyProvider): KeyVerifier | undefined {
    return this.#verifiers.get(provider);
  }

  has(provider: KeyProvider): boolean {
    return this.#verifiers.has(provider);
  }

  getAll(): KeyVerifier[] {
    return Array.from(this.#verifiers.values());
  }
}
