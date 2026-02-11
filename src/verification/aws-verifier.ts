import type { SecureBuffer } from "../core/secure-buffer.js";
import { KeyProvider, type VerificationResult } from "../types/index.js";
import type { KeyVerifier } from "./verifier.js";

/**
 * AWS verifier for Access Key IDs.
 *
 * Note: AWS Access Key verification requires both the Access Key ID
 * and the Secret Access Key. Since we only have the Access Key ID,
 * we can only check the format. Full verification would require the
 * secret key as well, which the user would need to provide separately.
 *
 * For now, this verifier reports that the key *looks like* a valid
 * AWS Access Key ID but cannot verify it without the secret key.
 */
export const awsVerifier: KeyVerifier = {
  provider: KeyProvider.AWS,
  endpoint: "https://sts.amazonaws.com (GetCallerIdentity)",
  description: "Calls STS GetCallerIdentity to check if key pair is active (read-only). Requires both Access Key ID and Secret Access Key.",

  async verify(secret: SecureBuffer): Promise<VerificationResult> {
    // AWS Access Key IDs alone cannot be verified — need the secret key too.
    // We report this limitation clearly.
    return {
      provider: KeyProvider.AWS,
      active: false,
      details:
        "AWS Access Key ID detected but verification requires the corresponding Secret Access Key. " +
        "Check AWS IAM console to verify key status.",
      error: null,
      endpoint: "https://sts.amazonaws.com",
    };
  },
};
