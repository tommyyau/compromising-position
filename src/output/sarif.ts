import type { CheckResult, RiskLevel } from "../types/index.js";

/**
 * SARIF severity mapping.
 * See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */
const SARIF_SEVERITY: Record<RiskLevel, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "none",
};

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  fingerprints: { primaryLocationHash: string };
  properties: {
    riskLevel: RiskLevel;
    provider: string;
    timestamp: string;
  };
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: {
        id: string;
        shortDescription: { text: string };
        defaultConfiguration: { level: string };
      }[];
    };
  };
  results: SarifResult[];
}

interface SarifReport {
  version: string;
  $schema: string;
  runs: SarifRun[];
}

/**
 * Format check results as SARIF for GitHub Advanced Security.
 */
export function formatSarif(results: CheckResult[]): string {
  const sarifResults: SarifResult[] = results.map((r) => ({
    ruleId: `credential-exposure/${r.local.identification.provider.toLowerCase().replace(/\s+/g, "-")}`,
    level: SARIF_SEVERITY[r.riskLevel],
    message: { text: r.summary },
    fingerprints: { primaryLocationHash: r.fingerprint },
    properties: {
      riskLevel: r.riskLevel,
      provider: r.local.identification.provider,
      timestamp: r.timestamp,
    },
  }));

  const report: SarifReport = {
    version: "2.1.0",
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "compromising-position",
            version: "1.0.0",
            informationUri: "https://github.com/your-org/compromising-position",
            rules: [
              {
                id: "credential-exposure",
                shortDescription: { text: "Credential found in breach database or identified as weak" },
                defaultConfiguration: { level: "error" },
              },
            ],
          },
        },
        results: sarifResults,
      },
    ],
  };

  return JSON.stringify(report, null, 2);
}
