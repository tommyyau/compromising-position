import type { SecureBuffer } from "../core/secure-buffer.js";
import { identifyKey } from "../core/key-identifier.js";
import { analyzeEntropy } from "../core/entropy.js";
import { KeyProvider, type LocalCheckResult } from "../types/index.js";

/** Perform local-only analysis: provider identification, entropy, format checks. */
export function performLocalCheck(secret: SecureBuffer): LocalCheckResult {
  const raw = secret.unsafeGetString().trim();
  const identification = identifyKey(raw);
  const entropy = analyzeEntropy(raw);
  const warnings: string[] = [];

  // Collect warnings
  if (entropy.warning) {
    warnings.push(entropy.warning);
  }

  if (raw.length < 8) {
    warnings.push("Input is very short — unlikely to be a real API key");
  }

  if (identification.provider === KeyProvider.StripeTest) {
    warnings.push(
      "This is a Stripe TEST key — not a production secret, but still should not be shared",
    );
  }

  if (identification.provider === KeyProvider.Unknown && entropy.shannonEntropy < 3.0) {
    warnings.push(
      "Unrecognized format with low entropy — may be a password or placeholder",
    );
  }

  // Heuristic: does this look like a real secret?
  const looksLikeSecret =
    identification.provider !== KeyProvider.Unknown ||
    (entropy.shannonEntropy >= 3.5 && raw.length >= 16);

  return {
    identification,
    entropy,
    warnings,
    looksLikeSecret,
  };
}
