import { createHash } from "node:crypto";
import type { CheckPlugin } from "../plugin.js";
import type { SecureBuffer } from "../../core/secure-buffer.js";
import type { AppConfig, PluginCheckResult } from "../../types/index.js";

/**
 * SHA-256 hashes of common passwords, default credentials, and placeholder values.
 * Stored as hashes so the actual secrets never appear in source code.
 * Implements NIST SP 800-63B Rev 4 mandatory blocklist screening.
 */
const COMMON_SECRET_HASHES = new Set([
  // Top passwords: password, 123456, 12345678, qwerty, abc123, monkey, 1234567,
  // letmein, trustno1, dragon, baseball, master, etc.
  "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", // password
  "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", // 123456
  "ef797c8118f02dfb649607dd5d3f8c7623048c9c063d532cc95c5ed7a898a64f", // 12345678
  "65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5", // qwerty
  "6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090", // abc123
  "ab56b4d92b40713acc5af89985d4b786c2f8fcc30898a36a2c8e3b3b3cdd7460", // 1234567
  "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", // 123456789
  "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4", // 1234
  "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5", // 12345
  "20f3765880a5c269b747e1e906054a4b4a3a991259f1e16b5dde4742cec2319a", // 1234567890
  "b822f1cd2dcfc685b47e83e3980289fd5d8e3ff3a82def24d7d1d68bb272eb32", // letmein
  "fcab0453879a2b2281bc5073e3f5f93b2aee8f41109fbc3983180bfbf6ce8ade", // trustno1
  "8621ffdbc5698829397d97767ac13db3f084e3e8d68e506c9cf5658c9e89b1c8", // dragon
  "5906ac361a137e2d286465cd6588ebb5ac3f5ae955001100bc41577c3d751764", // baseball
  "a8cfcd74832004951b4408cdb0a5dbcd8c7e52d43f7fe244bf720582e05241da", // iloveyou
  "0ffe1abd1a08215353c233d6e009613e95eec4253832a761af28ff37ac5a150c", // master
  "b7e94be513e96e8c45cd23f162275e5a12ebde9100a425c4ebcdd7fa4dcd897c", // sunshine
  "f2d81a260dea8a100dd517984e53c56a7523d96942a834b9cdc249bd4e8c7aa9", // ashley
  "b4b147bc522828731f1a016bfa72c073571be76ab0adb1a841c5eb4b79a56271", // michael
  "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", // hello

  // Common placeholder/test values
  "057ba03d6c44104863dc7361fe4578965d1887360f90a0895882e58a6248fc86", // changeme
  "8bb0cf6eb9b17d0f7d22b456f121257dc1254e1f01665370476383ea776df414", // password1
  "b03ddf3ca2e714a6548e7495e2a03f5e824eaac9837cd7f159c67b90fb4b7342", // Password1
  "a075d17f3d453073853f813838c15b8023b8c487038436354fe599c3942e1f95", // admin
  "f0e4c2f76c58916ec258f246851bea091d14d4247a2fc3e18694461b1816e13b", // test
  "e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8", // default
  "4fc82b26aecb47d2868c4efbe3581732a3e7cbcc6c2efb32062c08170a05eeb8", // secret
  "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b", // secret
]);

/** Known placeholder patterns that indicate test/dummy values. */
const PLACEHOLDER_PATTERNS = [
  /^your[-_]?api[-_]?key[-_]?here$/i,
  /^insert[-_]?api[-_]?key$/i,
  /^replace[-_]?me$/i,
  /^xxx+$/i,
  /^todo$/i,
  /^fixme$/i,
  /^example$/i,
  /^test[-_]?key$/i,
  /^dummy$/i,
  /^fake[-_]?key$/i,
  /^placeholder$/i,
  /^changeme$/i,
  /^your[-_]?token[-_]?here$/i,
  /^sk[-_]test[-_]xxx+$/i,
];

/** Sequential and keyboard patterns. */
const SEQUENTIAL_PATTERNS = [
  /^(.)\1{7,}$/, // aaaaaaaa
  /^0123456789/,
  /^abcdefgh/i,
  /^qwerty/i,
  /^asdfgh/i,
  /^zxcvbn/i,
];

export const commonSecretsPlugin: CheckPlugin = {
  id: "common-secrets",
  name: "Common/Weak Secret Detection",
  inputKind: "secret",
  requiresNetwork: false,
  requiredConfigKeys: [],
  isFree: true,
  privacySummary: "No data sent (local only)",

  async check(
    input: SecureBuffer | string,
    _config: AppConfig,
  ): Promise<PluginCheckResult> {
    const secret = input as SecureBuffer;

    // Check against hashed blocklist
    const hash = secret.sha256Hex();
    if (COMMON_SECRET_HASHES.has(hash)) {
      return {
        pluginId: "common-secrets",
        pluginName: "Common/Weak Secret Detection",
        found: true,
        details: "Matches a commonly used password or default credential",
        severity: "critical",
        error: null,
        metadata: { matchType: "blocklist" },
      };
    }

    // Check placeholder patterns
    const matchesPlaceholder = secret.withString((raw) => {
      const trimmed = raw.trim();
      return PLACEHOLDER_PATTERNS.some((p) => p.test(trimmed));
    });

    if (matchesPlaceholder) {
      return {
        pluginId: "common-secrets",
        pluginName: "Common/Weak Secret Detection",
        found: true,
        details: "Matches a known placeholder or test value pattern",
        severity: "medium",
        error: null,
        metadata: { matchType: "placeholder" },
      };
    }

    // Check sequential/keyboard patterns
    const matchesSequential = secret.withString((raw) => {
      const trimmed = raw.trim();
      return SEQUENTIAL_PATTERNS.some((p) => p.test(trimmed));
    });

    if (matchesSequential) {
      return {
        pluginId: "common-secrets",
        pluginName: "Common/Weak Secret Detection",
        found: true,
        details: "Contains a sequential or keyboard pattern",
        severity: "high",
        error: null,
        metadata: { matchType: "sequential" },
      };
    }

    return {
      pluginId: "common-secrets",
      pluginName: "Common/Weak Secret Detection",
      found: false,
      details: "Not found in common secrets blocklist",
      severity: "low",
      error: null,
    };
  },
};
