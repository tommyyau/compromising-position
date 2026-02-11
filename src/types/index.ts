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
  // Phase 1 additions
  GitLabPAT = "GitLab PAT",
  GitLabPipeline = "GitLab Pipeline",
  NpmToken = "npm Token",
  PyPIToken = "PyPI Token",
  ShopifyPrivate = "Shopify Private",
  ShopifyAccess = "Shopify Access",
  DigitalOceanPAT = "DigitalOcean PAT",
  DigitalOceanOAuth = "DigitalOcean OAuth",
  Supabase = "Supabase",
  HashiCorpVault = "HashiCorp Vault",
  TerraformCloud = "Terraform Cloud",
  PlanetScale = "PlanetScale",
  Postman = "Postman",
  GrafanaService = "Grafana Service",
  Linear = "Linear",
  Netlify = "Netlify",
  DopplerServiceToken = "Doppler Service Token",
  DopplerServiceAccount = "Doppler Service Account",
  Buildkite = "Buildkite",
  Atlassian = "Atlassian",
  Figma = "Figma",
  CircleCI = "CircleCI",
  Notion = "Notion",
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

export type PluginInputKind = "secret" | "email" | "both";

export interface PluginCheckResult {
  pluginId: string;
  pluginName: string;
  found: boolean;
  details: string;
  severity: RiskLevel;
  error: string | null;
  metadata?: Record<string, unknown>;
}

export interface VerificationResult {
  provider: KeyProvider;
  active: boolean;
  details: string;
  error: string | null;
  endpoint: string;
}

export interface CheckResult {
  local: LocalCheckResult;
  hibpPassword: HibpPasswordResult | null;
  hibpEmail: HibpEmailResult | null;
  pluginResults: PluginCheckResult[];
  verification: VerificationResult | null;
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
  envFile?: string;
  offline: boolean;
  json: boolean;
  verbose: boolean;
  verify: boolean;
  enabledPlugins: string[];
  disabledPlugins: string[];
  pluginApiKeys: Record<string, string>;
}
