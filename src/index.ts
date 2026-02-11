import { Command } from "commander";
import { loadConfig } from "./config/config.js";
import { readSecret } from "./input/secure-prompt.js";
import { performLocalCheck } from "./checks/local-check.js";
import { checkHibpPassword } from "./checks/hibp-password.js";
import { checkHibpEmail } from "./checks/hibp-email.js";
import { fingerprint } from "./core/fingerprint.js";
import { formatReport, formatJson } from "./output/formatter.js";
import { writeAuditLog } from "./output/audit-log.js";
import type {
  CheckResult,
  HibpPasswordResult,
  HibpEmailResult,
  RiskLevel,
} from "./types/index.js";

const program = new Command();

program
  .name("compromising-position")
  .description("Privacy-preserving credential exposure checker using k-anonymity")
  .version("1.0.0");

program
  .command("check")
  .description("Check a secret/API key for exposure in breach databases")
  .option("--offline", "Local analysis only — skip network checks")
  .option("--json", "Output JSON to stdout (human report still goes to stderr)")
  .option("--verbose", "Show additional details")
  .option("--hibp-api-key <key>", "HIBP API key (or set HIBP_API_KEY env var)")
  .option("--audit-log <path>", "Path to append audit log entries")
  .action(async (opts) => {
    const config = loadConfig({
      offline: opts.offline,
      json: opts.json,
      verbose: opts.verbose,
      hibpApiKey: opts.hibpApiKey,
      auditLogPath: opts.auditLog,
    });

    // Read the secret securely
    const secret = await readSecret();

    try {
      // Layer 1: Local analysis
      const local = performLocalCheck(secret);

      // Layer 2: HIBP k-anonymity check (unless offline)
      let hibpPassword: HibpPasswordResult | null = null;
      if (!config.offline) {
        if (!process.stdin.isTTY) {
          // Already read from pipe, proceed
        }
        process.stderr.write("Checking HIBP (k-anonymity)...\n");
        hibpPassword = await checkHibpPassword(secret);
      }

      // Compute fingerprint before disposing
      const fp = fingerprint(secret);

      // Build result
      const result: CheckResult = {
        local,
        hibpPassword,
        hibpEmail: null,
        riskLevel: determineRiskLevel(local, hibpPassword, null),
        summary: buildSummary(local, hibpPassword),
        fingerprint: fp,
        timestamp: new Date().toISOString(),
      };

      // Output
      if (config.json) {
        process.stdout.write(formatJson(result) + "\n");
      }
      // Always write human report to stderr
      process.stderr.write(formatReport(result));

      // Audit log
      if (config.auditLogPath) {
        await writeAuditLog(config.auditLogPath, result);
      }

      // Exit code: 0=safe, 1=exposed, 2=error
      const exitCode = result.riskLevel === "critical" || result.riskLevel === "high"
        ? 1
        : 0;
      process.exit(exitCode);
    } finally {
      secret.dispose();
    }
  });

program
  .command("check-email <email>")
  .description("Check an email address against HIBP breach databases")
  .option("--json", "Output JSON to stdout")
  .option("--hibp-api-key <key>", "HIBP API key (required, or set HIBP_API_KEY env var)")
  .option("--audit-log <path>", "Path to append audit log entries")
  .action(async (email: string, opts) => {
    const config = loadConfig({
      json: opts.json,
      hibpApiKey: opts.hibpApiKey,
      auditLogPath: opts.auditLog,
    });

    if (!config.hibpApiKey) {
      process.stderr.write(
        "Error: HIBP API key required for email checks.\n" +
        "Set HIBP_API_KEY environment variable or use --hibp-api-key flag.\n" +
        "Get a key at https://haveibeenpwned.com/API/Key ($3.50/mo)\n",
      );
      process.exit(2);
    }

    process.stderr.write(`Checking email breaches for ${email}...\n`);

    const emailResult: HibpEmailResult = await checkHibpEmail(
      email,
      config.hibpApiKey,
    );

    const riskLevel = determineEmailRiskLevel(emailResult);
    const result: CheckResult = {
      local: {
        identification: {
          provider: "Unknown" as any,
          confidence: "low",
          description: "Email breach check",
        },
        entropy: {
          shannonEntropy: 0,
          maxPossibleEntropy: 0,
          normalizedEntropy: 0,
          encoding: "mixed",
          length: email.length,
          warning: null,
        },
        warnings: [],
        looksLikeSecret: false,
      },
      hibpPassword: null,
      hibpEmail: emailResult,
      riskLevel,
      summary: buildEmailSummary(emailResult),
      fingerprint: "email-check",
      timestamp: new Date().toISOString(),
    };

    if (config.json) {
      process.stdout.write(formatJson(result) + "\n");
    }
    process.stderr.write(formatReport(result));

    if (config.auditLogPath) {
      await writeAuditLog(config.auditLogPath, result);
    }

    const exitCode = riskLevel === "critical" || riskLevel === "high" ? 1 : 0;
    process.exit(exitCode);
  });

function determineRiskLevel(
  local: CheckResult["local"],
  hibp: HibpPasswordResult | null,
  _email: HibpEmailResult | null,
): RiskLevel {
  // Found in breach data = critical
  if (hibp?.found && (hibp.occurrences ?? 0) > 0) {
    return "critical";
  }

  // Recognized provider key with high entropy = high risk if no HIBP check done
  if (local.identification.confidence === "high" && local.looksLikeSecret) {
    if (hibp === null) {
      return "medium"; // offline check — we don't know
    }
    return "low"; // checked HIBP, not found
  }

  // Looks like a secret but unrecognized
  if (local.looksLikeSecret) {
    if (hibp?.found) return "critical";
    return hibp ? "low" : "medium";
  }

  // Doesn't look like a secret
  return "info";
}

function determineEmailRiskLevel(email: HibpEmailResult): RiskLevel {
  if (email.stealerLogs.length > 0) return "critical";
  if (email.breaches.length > 10) return "critical";
  if (email.breaches.length > 0) return "high";
  if (email.pastes.length > 0) return "medium";
  return "low";
}

function buildSummary(
  local: CheckResult["local"],
  hibp: HibpPasswordResult | null,
): string {
  const parts: string[] = [];

  if (local.identification.provider !== "Unknown") {
    parts.push(`Identified as ${local.identification.provider}`);
  } else {
    parts.push("Unknown key format");
  }

  if (hibp?.found) {
    parts.push(
      `EXPOSED in ${hibp.occurrences.toLocaleString()} breach(es)`,
    );
  } else if (hibp?.checked && !hibp.error) {
    parts.push("not found in HIBP breach data");
  } else if (hibp?.error) {
    parts.push(`HIBP check failed: ${hibp.error}`);
  }

  return parts.join(" — ");
}

function buildEmailSummary(email: HibpEmailResult): string {
  if (email.error) return `Email check failed: ${email.error}`;

  const parts: string[] = [];
  if (email.breaches.length > 0) {
    parts.push(`${email.breaches.length} breach(es)`);
  }
  if (email.stealerLogs.length > 0) {
    parts.push(`${email.stealerLogs.length} stealer log(s)`);
  }
  if (email.pastes.length > 0) {
    parts.push(`${email.pastes.length} paste(s)`);
  }

  return parts.length > 0
    ? `Found in: ${parts.join(", ")}`
    : "No breaches found";
}

program.parse();
