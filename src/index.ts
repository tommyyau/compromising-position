import { Command } from "commander";
import { loadConfig } from "./config/config.js";
import { readSecret } from "./input/secure-prompt.js";
import { performLocalCheck } from "./checks/local-check.js";
import { checkHibpPassword } from "./checks/hibp-password.js";
import { checkHibpEmail } from "./checks/hibp-email.js";
import { CheckRegistry } from "./checks/registry.js";
import { fingerprint } from "./core/fingerprint.js";
import { sanitizeForTerminal } from "./core/sanitize.js";
import { formatReport, formatJson, formatPrivacySummary } from "./output/formatter.js";
import { formatSarif } from "./output/sarif.js";
import { formatCsv } from "./output/csv.js";
import { writeAuditLog } from "./output/audit-log.js";
import { parseEnvFile, parseJsonFile, disposeBatch, type BatchEntry } from "./input/batch-parser.js";
import type {
  CheckResult,
  HibpPasswordResult,
  HibpEmailResult,
  PluginCheckResult,
  VerificationResult,
  RiskLevel,
} from "./types/index.js";

// Import plugins
import { hibpPasswordPlugin } from "./checks/plugins/hibp-password-plugin.js";
import { hibpEmailPlugin } from "./checks/plugins/hibp-email-plugin.js";
import { localAnalysisPlugin } from "./checks/plugins/local-analysis-plugin.js";
import { commonSecretsPlugin } from "./checks/plugins/common-secrets-plugin.js";
import { emailRepPlugin } from "./checks/plugins/emailrep-plugin.js";
import { gitGuardianHslPlugin } from "./checks/plugins/gitguardian-hsl-plugin.js";
import { dehashedPlugin } from "./checks/plugins/dehashed-plugin.js";
import { leakCheckPlugin } from "./checks/plugins/leakcheck-plugin.js";
import { intelXPlugin } from "./checks/plugins/intelx-plugin.js";

// Import verifiers
import { VerifierRegistry } from "./verification/verifier-registry.js";
import { openaiVerifier, openaiServiceVerifier } from "./verification/openai-verifier.js";
import { anthropicVerifier } from "./verification/anthropic-verifier.js";
import { githubPatVerifier, githubFineGrainedVerifier } from "./verification/github-verifier.js";
import { awsVerifier } from "./verification/aws-verifier.js";
import { slackBotVerifier, slackUserVerifier } from "./verification/slack-verifier.js";

// Build the global plugin registry
const registry = new CheckRegistry();
registry.register(localAnalysisPlugin);
registry.register(hibpPasswordPlugin);
registry.register(hibpEmailPlugin);
registry.register(commonSecretsPlugin);
registry.register(emailRepPlugin);
registry.register(gitGuardianHslPlugin);
registry.register(dehashedPlugin);
registry.register(leakCheckPlugin);
registry.register(intelXPlugin);

// Build the global verifier registry
const verifierRegistry = new VerifierRegistry();
verifierRegistry.register(openaiVerifier);
verifierRegistry.register(openaiServiceVerifier);
verifierRegistry.register(anthropicVerifier);
verifierRegistry.register(githubPatVerifier);
verifierRegistry.register(githubFineGrainedVerifier);
verifierRegistry.register(awsVerifier);
verifierRegistry.register(slackBotVerifier);
verifierRegistry.register(slackUserVerifier);

/** Simple yes/no prompt for verification consent. */
function promptYesNo(): Promise<boolean> {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();

    const onData = (data: Buffer) => {
      const ch = data.toString().toLowerCase();
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener("data", onData);

      if (ch === "y") {
        process.stderr.write("y\n");
        resolve(true);
      } else {
        process.stderr.write("n\n");
        resolve(false);
      }
    };

    stdin.on("data", onData);
  });
}

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
  .option("--verify", "Attempt active key verification (sends key to provider API)")
  .option("--privacy", "Show what data each plugin sends and where")
  .option("--env-file <path>", "Path to .env file (default: auto-detect in cwd)")
  .option("--audit-log <path>", "Path to append audit log entries")
  .option("--enable-plugins <ids>", "Comma-separated list of plugin IDs to enable")
  .option("--disable-plugins <ids>", "Comma-separated list of plugin IDs to disable")
  .action(async (opts) => {
    const config = loadConfig({
      offline: opts.offline,
      json: opts.json,
      verbose: opts.verbose,
      verify: opts.verify,
      envFile: opts.envFile,
      auditLogPath: opts.auditLog,
      enabledPlugins: opts.enablePlugins
        ? (opts.enablePlugins as string).split(",").map((s: string) => s.trim())
        : [],
      disabledPlugins: opts.disablePlugins
        ? (opts.disablePlugins as string).split(",").map((s: string) => s.trim())
        : [],
    });

    // --privacy: show data flow summary and exit
    if (opts.privacy) {
      process.stderr.write(formatPrivacySummary(registry.getAll()));
      process.exit(0);
    }

    // Read the secret securely
    const secret = await readSecret();

    try {
      // Layer 1: Local analysis (always runs)
      const local = performLocalCheck(secret);

      // Layer 2: HIBP k-anonymity check (unless offline)
      let hibpPassword: HibpPasswordResult | null = null;
      if (!config.offline) {
        process.stderr.write("Checking HIBP (k-anonymity)...\n");
        hibpPassword = await checkHibpPassword(secret);
      }

      // Layer 3: Run registered plugins
      const runnablePlugins = registry.getRunnable("secret", config);
      const pluginResults: PluginCheckResult[] = [];
      for (const plugin of runnablePlugins) {
        // Skip built-in plugins that are already handled directly
        if (plugin.id === "local-analysis" || plugin.id === "hibp-password") {
          continue;
        }
        process.stderr.write(`Running ${plugin.name}...\n`);
        const result = await plugin.check(secret, config);
        pluginResults.push(result);
      }

      // Layer 4: Active verification (opt-in, requires --verify flag)
      let verification: VerificationResult | null = null;
      if (config.verify && local.identification.provider !== "Unknown") {
        const verifier = verifierRegistry.get(local.identification.provider);
        if (verifier) {
          process.stderr.write(
            `\nVerification will send your key to: ${verifier.endpoint}\n` +
            `Purpose: ${verifier.description}\n` +
            `Proceed? [y/N] `,
          );

          // In non-interactive mode (pipe), skip verification
          if (!process.stdin.isTTY) {
            process.stderr.write("(skipped — non-interactive mode)\n");
          } else {
            const confirmed = await promptYesNo();
            if (confirmed) {
              process.stderr.write("Verifying key...\n");
              verification = await verifier.verify(secret);
            } else {
              process.stderr.write("Verification skipped.\n");
            }
          }
        }
      }

      // Compute fingerprint before disposing
      const fp = fingerprint(secret);

      // Build result
      const result: CheckResult = {
        local,
        hibpPassword,
        hibpEmail: null,
        pluginResults,
        verification,
        riskLevel: determineRiskLevel(local, hibpPassword, null, pluginResults, verification),
        summary: buildSummary(local, hibpPassword, pluginResults, verification),
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
  .option("--env-file <path>", "Path to .env file (default: auto-detect in cwd)")
  .option("--audit-log <path>", "Path to append audit log entries")
  .option("--enable-plugins <ids>", "Comma-separated list of plugin IDs to enable")
  .option("--disable-plugins <ids>", "Comma-separated list of plugin IDs to disable")
  .action(async (email: string, opts) => {
    // Validate email format before proceeding
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
      process.stderr.write("Error: invalid email address format.\n");
      process.exit(2);
    }

    const config = loadConfig({
      json: opts.json,
      envFile: opts.envFile,
      auditLogPath: opts.auditLog,
      enabledPlugins: opts.enablePlugins
        ? (opts.enablePlugins as string).split(",").map((s: string) => s.trim())
        : [],
      disabledPlugins: opts.disablePlugins
        ? (opts.disablePlugins as string).split(",").map((s: string) => s.trim())
        : [],
    });

    if (!config.hibpApiKey) {
      process.stderr.write(
        "Error: HIBP API key required for email checks.\n" +
        "Set HIBP_API_KEY environment variable or provide via .env file.\n" +
        "Get a key at https://haveibeenpwned.com/API/Key ($3.50/mo)\n",
      );
      process.exit(2);
    }

    // Sanitize email for terminal output (prevent escape sequence injection)
    process.stderr.write(`Checking email breaches for ${sanitizeForTerminal(email)}...\n`);

    const emailResult: HibpEmailResult = await checkHibpEmail(
      email,
      config.hibpApiKey,
    );

    // Run email-type plugins
    const runnablePlugins = registry.getRunnable("email", config);
    const pluginResults: PluginCheckResult[] = [];
    for (const plugin of runnablePlugins) {
      if (plugin.id === "hibp-email") continue; // already handled
      process.stderr.write(`Running ${plugin.name}...\n`);
      const result = await plugin.check(email, config);
      pluginResults.push(result);
    }

    const riskLevel = determineEmailRiskLevel(emailResult, pluginResults);
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
      pluginResults,
      verification: null,
      riskLevel,
      summary: buildEmailSummary(emailResult, pluginResults),
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
  pluginResults: PluginCheckResult[],
  verification: VerificationResult | null,
): RiskLevel {
  // Active + exposed = critical
  if (verification?.active && pluginResults.some((p) => p.found)) {
    return "critical";
  }
  if (verification?.active && hibp?.found) {
    return "critical";
  }

  // Found in breach data = critical
  if (hibp?.found && (hibp.occurrences ?? 0) > 0) {
    return "critical";
  }

  // Any plugin found exposure at critical level
  if (pluginResults.some((p) => p.found && p.severity === "critical")) {
    return "critical";
  }

  // Any plugin found exposure at high level
  if (pluginResults.some((p) => p.found && p.severity === "high")) {
    return "high";
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

  // Plugin found something at medium level
  if (pluginResults.some((p) => p.found && p.severity === "medium")) {
    return "medium";
  }

  // Doesn't look like a secret
  return "info";
}

function determineEmailRiskLevel(
  email: HibpEmailResult,
  pluginResults: PluginCheckResult[],
): RiskLevel {
  if (email.stealerLogs.length > 0) return "critical";
  if (email.breaches.length > 10) return "critical";
  if (pluginResults.some((p) => p.found && p.severity === "critical")) return "critical";
  if (email.breaches.length > 0) return "high";
  if (pluginResults.some((p) => p.found && p.severity === "high")) return "high";
  if (email.pastes.length > 0) return "medium";
  if (pluginResults.some((p) => p.found && p.severity === "medium")) return "medium";
  return "low";
}

function buildSummary(
  local: CheckResult["local"],
  hibp: HibpPasswordResult | null,
  pluginResults: PluginCheckResult[],
  verification: VerificationResult | null,
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

  // Summarize plugin findings
  const foundPlugins = pluginResults.filter((p) => p.found);
  if (foundPlugins.length > 0) {
    parts.push(`found in ${foundPlugins.length} additional source(s)`);
  }

  if (verification?.active) {
    parts.push("KEY IS CURRENTLY ACTIVE");
  }

  return parts.join(" — ");
}

function buildEmailSummary(
  email: HibpEmailResult,
  pluginResults: PluginCheckResult[],
): string {
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

  const foundPlugins = pluginResults.filter((p) => p.found);
  if (foundPlugins.length > 0) {
    parts.push(`${foundPlugins.length} additional source(s)`);
  }

  return parts.length > 0
    ? `Found in: ${parts.join(", ")}`
    : "No breaches found";
}

program
  .command("check-batch <file>")
  .description("Check multiple secrets from a .env or JSON file")
  .option("--offline", "Local analysis only — skip network checks")
  .option("--format <format>", "Output format: json, sarif, csv (default: json)", "json")
  .option("--env-file <path>", "Path to .env file for config")
  .option("--audit-log <path>", "Path to append audit log entries")
  .action(async (file: string, opts) => {
    const config = loadConfig({
      offline: opts.offline,
      envFile: opts.envFile,
      auditLogPath: opts.auditLog,
      json: true,
    });

    // Determine file format from extension
    let entries: BatchEntry[];
    if (file.endsWith(".json")) {
      entries = parseJsonFile(file);
    } else {
      // Default to .env format
      entries = parseEnvFile(file);
    }

    if (entries.length === 0) {
      process.stderr.write("No secrets found in input file.\n");
      process.exit(0);
    }

    process.stderr.write(`Checking ${entries.length} secret(s)...\n`);

    const results: CheckResult[] = [];
    let hasExposure = false;

    try {
      for (const entry of entries) {
        process.stderr.write(`  Checking ${sanitizeForTerminal(entry.name)}...\n`);

        const local = performLocalCheck(entry.secret);

        let hibpPassword: HibpPasswordResult | null = null;
        if (!config.offline) {
          hibpPassword = await checkHibpPassword(entry.secret);
        }

        // Run plugins
        const runnablePlugins = registry.getRunnable("secret", config);
        const pluginResults: PluginCheckResult[] = [];
        for (const plugin of runnablePlugins) {
          if (plugin.id === "local-analysis" || plugin.id === "hibp-password") continue;
          const pr = await plugin.check(entry.secret, config);
          pluginResults.push(pr);
        }

        const fp = fingerprint(entry.secret);

        const result: CheckResult = {
          local,
          hibpPassword,
          hibpEmail: null,
          pluginResults,
          verification: null,
          riskLevel: determineRiskLevel(local, hibpPassword, null, pluginResults, null),
          summary: `[${entry.name}] ${buildSummary(local, hibpPassword, pluginResults, null)}`,
          fingerprint: fp,
          timestamp: new Date().toISOString(),
        };

        results.push(result);

        if (result.riskLevel === "critical" || result.riskLevel === "high") {
          hasExposure = true;
        }

        if (config.auditLogPath) {
          await writeAuditLog(config.auditLogPath, result);
        }
      }

      // Output
      const format = opts.format as string;
      if (format === "sarif") {
        process.stdout.write(formatSarif(results) + "\n");
      } else if (format === "csv") {
        process.stdout.write(formatCsv(results) + "\n");
      } else {
        process.stdout.write(JSON.stringify(results, null, 2) + "\n");
      }

      // Summary to stderr
      const critCount = results.filter((r) => r.riskLevel === "critical").length;
      const highCount = results.filter((r) => r.riskLevel === "high").length;
      process.stderr.write(
        `\nBatch complete: ${results.length} checked, ${critCount} critical, ${highCount} high\n`,
      );

      process.exit(hasExposure ? 1 : 0);
    } finally {
      disposeBatch(entries);
    }
  });

// Export registry for external use (e.g., registering new plugins)
export { registry };

program.parse();
