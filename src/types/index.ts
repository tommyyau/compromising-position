export enum KeyProvider {
  OpenAI = "OpenAI",
  OpenAIService = "OpenAI Service Account",
  Anthropic = "Anthropic",
  AWS = "AWS",
  GitHubPAT = "GitHub PAT",
  GitHubFineGrained = "GitHub Fine-Grained",
  StripeLive = "Stripe Live",
  StripeTest = "Stripe Test",
  GoogleAPI = "Google API",
  SlackBot = "Slack Bot",
  SlackUser = "Slack User",
  SendGrid = "SendGrid",
  Twilio = "Twilio",
  Mailgun = "Mailgun",
  DiscordBot = "Discord Bot",
  TelegramBot = "Telegram Bot",
  Unknown = "Unknown",
}

export type Encoding = "base64" | "hex" | "base62" | "alphanumeric" | "mixed";

export interface EntropyResult {
  shannonEntropy: number;
  maxPossibleEntropy: number;
  normalizedEntropy: number;
  encoding: Encoding;
  length: number;
  warning: string | null;
}

export interface KeyIdentification {
  provider: KeyProvider;
  confidence: "high" | "medium" | "low";
  description: string;
}

export interface LocalCheckResult {
  identification: KeyIdentification;
  entropy: EntropyResult;
  warnings: string[];
  looksLikeSecret: boolean;
}

export interface HibpPasswordResult {
  checked: boolean;
  found: boolean;
  occurrences: number;
  hashPrefix: string;
  error: string | null;
}

export interface BreachEntry {
  Name: string;
  BreachDate: string;
  DataClasses: string[];
}

export interface PasteEntry {
  Source: string;
  Id: string;
  Title: string | null;
  Date: string | null;
}

export interface StealerLogEntry {
  Name: string;
  Date: string;
}

export interface HibpEmailResult {
  checked: boolean;
  breaches: BreachEntry[];
  stealerLogs: StealerLogEntry[];
  pastes: PasteEntry[];
  error: string | null;
}

export type RiskLevel = "critical" | "high" | "medium" | "low" | "info";

export interface CheckResult {
  local: LocalCheckResult;
  hibpPassword: HibpPasswordResult | null;
  hibpEmail: HibpEmailResult | null;
  riskLevel: RiskLevel;
  summary: string;
  fingerprint: string;
  timestamp: string;
}

export interface AuditEntry {
  timestamp: string;
  fingerprint: string;
  provider: KeyProvider;
  riskLevel: RiskLevel;
  hibpFound: boolean | null;
  summary: string;
}

export interface AppConfig {
  hibpApiKey: string | null;
  auditLogPath: string | null;
  offline: boolean;
  json: boolean;
  verbose: boolean;
}
