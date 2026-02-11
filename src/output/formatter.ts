import chalk from "chalk";
import type { CheckResult, RiskLevel } from "../types/index.js";

const RISK_COLORS: Record<RiskLevel, (text: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow.bold,
  low: chalk.green.bold,
  info: chalk.blue,
};

const RISK_LABELS: Record<RiskLevel, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

function riskBadge(level: RiskLevel): string {
  return RISK_COLORS[level](`[${RISK_LABELS[level]}]`);
}

/** Format a full check result as a colored terminal report. Writes to stderr. */
export function formatReport(result: CheckResult): string {
  const lines: string[] = [];

  lines.push("");
  lines.push(chalk.bold("--- Credential Exposure Report ---"));
  lines.push("");

  // Risk level
  lines.push(`  Risk Level:  ${riskBadge(result.riskLevel)}`);
  lines.push(`  Summary:     ${result.summary}`);
  lines.push(`  Fingerprint: ${chalk.dim(result.fingerprint)}`);
  lines.push("");

  // Local analysis
  const local = result.local;
  lines.push(chalk.bold.underline("Local Analysis"));
  lines.push(
    `  Provider:    ${local.identification.provider} (${local.identification.confidence} confidence)`,
  );
  lines.push(`  Description: ${local.identification.description}`);
  lines.push(
    `  Entropy:     ${local.entropy.shannonEntropy} bits/char (${local.entropy.normalizedEntropy} normalized)`,
  );
  lines.push(
    `  Encoding:    ${local.entropy.encoding} | Length: ${local.entropy.length}`,
  );

  if (local.warnings.length > 0) {
    lines.push("");
    lines.push(chalk.yellow("  Warnings:"));
    for (const w of local.warnings) {
      lines.push(chalk.yellow(`    ! ${w}`));
    }
  }

  // HIBP password check
  if (result.hibpPassword) {
    lines.push("");
    lines.push(chalk.bold.underline("HIBP Password Check (k-Anonymity)"));
    const hp = result.hibpPassword;
    if (hp.error) {
      lines.push(chalk.red(`  Error: ${hp.error}`));
    } else if (hp.found) {
      lines.push(
        chalk.red.bold(
          `  FOUND in breach data — ${hp.occurrences.toLocaleString()} occurrence(s)`,
        ),
      );
    } else {
      lines.push(chalk.green("  Not found in breach data"));
    }
    lines.push(chalk.dim(`  Hash prefix sent: ${hp.hashPrefix}`));
  }

  // HIBP email check
  if (result.hibpEmail) {
    lines.push("");
    lines.push(chalk.bold.underline("HIBP Email Breach Check"));
    const he = result.hibpEmail;
    if (he.error) {
      lines.push(chalk.red(`  Error: ${he.error}`));
    } else {
      if (he.breaches.length > 0) {
        lines.push(
          chalk.red(`  Found in ${he.breaches.length} breach(es):`),
        );
        for (const b of he.breaches.slice(0, 10)) {
          lines.push(`    - ${b.Name} (${b.BreachDate})`);
        }
        if (he.breaches.length > 10) {
          lines.push(
            chalk.dim(`    ... and ${he.breaches.length - 10} more`),
          );
        }
      } else {
        lines.push(chalk.green("  No breaches found"));
      }

      if (he.stealerLogs.length > 0) {
        lines.push(
          chalk.red(
            `  Found in ${he.stealerLogs.length} stealer log(s):`,
          ),
        );
        for (const s of he.stealerLogs.slice(0, 5)) {
          lines.push(`    - ${s.Name} (${s.Date})`);
        }
      }

      if (he.pastes.length > 0) {
        lines.push(
          chalk.yellow(`  Found in ${he.pastes.length} paste(s):`),
        );
        for (const p of he.pastes.slice(0, 5)) {
          lines.push(`    - ${p.Source}: ${p.Title ?? p.Id}`);
        }
      }
    }
  }

  lines.push("");
  lines.push(chalk.dim(`  Timestamp: ${result.timestamp}`));
  lines.push("");

  return lines.join("\n");
}

/** Format a result as JSON for piping. */
export function formatJson(result: CheckResult): string {
  return JSON.stringify(result, null, 2);
}
