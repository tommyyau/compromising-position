import { KeyProvider, type KeyIdentification } from "../types/index.js";

interface KeyPattern {
  provider: KeyProvider;
  regex: RegExp;
  confidence: "high" | "medium";
  description: string;
}

const KEY_PATTERNS: KeyPattern[] = [
  // OpenAI project keys
  {
    provider: KeyProvider.OpenAI,
    regex: /^sk-proj-[A-Za-z0-9_-]{80,180}$/,
    confidence: "high",
    description: "OpenAI project API key",
  },
  // OpenAI service account keys
  {
    provider: KeyProvider.OpenAIService,
    regex: /^sk-svcacct-[A-Za-z0-9_-]{80,180}$/,
    confidence: "high",
    description: "OpenAI service account key",
  },
  // OpenAI legacy keys
  {
    provider: KeyProvider.OpenAI,
    regex: /^sk-[A-Za-z0-9]{32,64}$/,
    confidence: "medium",
    description: "OpenAI API key (legacy format)",
  },
  // Anthropic
  {
    provider: KeyProvider.Anthropic,
    regex: /^sk-ant-api03-[A-Za-z0-9_-]{90,110}$/,
    confidence: "high",
    description: "Anthropic API key",
  },
  // AWS Access Key ID
  {
    provider: KeyProvider.AWS,
    regex: /^AKIA[0-9A-Z]{16}$/,
    confidence: "high",
    description: "AWS Access Key ID",
  },
  // GitHub Personal Access Token (classic)
  {
    provider: KeyProvider.GitHubPAT,
    regex: /^ghp_[a-zA-Z0-9]{36}$/,
    confidence: "high",
    description: "GitHub Personal Access Token (classic)",
  },
  // GitHub Fine-Grained PAT
  {
    provider: KeyProvider.GitHubFineGrained,
    regex: /^github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}$/,
    confidence: "high",
    description: "GitHub Fine-Grained Personal Access Token",
  },
  // Stripe live secret key
  {
    provider: KeyProvider.StripeLive,
    regex: /^sk_live_[0-9a-zA-Z]{24,34}$/,
    confidence: "high",
    description: "Stripe live secret key",
  },
  // Stripe test secret key
  {
    provider: KeyProvider.StripeTest,
    regex: /^sk_test_[0-9a-zA-Z]{24,34}$/,
    confidence: "high",
    description: "Stripe test secret key",
  },
  // Google API key
  {
    provider: KeyProvider.GoogleAPI,
    regex: /^AIza[0-9A-Za-z\-_]{35}$/,
    confidence: "high",
    description: "Google API key",
  },
  // Slack Bot Token
  {
    provider: KeyProvider.SlackBot,
    regex: /^xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+$/,
    confidence: "high",
    description: "Slack Bot token",
  },
  // Slack User Token
  {
    provider: KeyProvider.SlackUser,
    regex: /^xoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+$/,
    confidence: "high",
    description: "Slack User token",
  },
  // SendGrid
  {
    provider: KeyProvider.SendGrid,
    regex: /^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/,
    confidence: "high",
    description: "SendGrid API key",
  },
  // Twilio
  {
    provider: KeyProvider.Twilio,
    regex: /^SK[0-9a-fA-F]{32}$/,
    confidence: "high",
    description: "Twilio API key",
  },
  // Mailgun
  {
    provider: KeyProvider.Mailgun,
    regex: /^key-[0-9a-f]{32}$/,
    confidence: "high",
    description: "Mailgun API key",
  },
  // Discord Bot Token
  {
    provider: KeyProvider.DiscordBot,
    regex: /^[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}$/,
    confidence: "medium",
    description: "Discord Bot token",
  },
  // Telegram Bot Token
  {
    provider: KeyProvider.TelegramBot,
    regex: /^[0-9]{8,10}:[A-Za-z0-9_-]{35}$/,
    confidence: "high",
    description: "Telegram Bot token",
  },
];

/** Identify the provider and confidence for a given key string. */
export function identifyKey(key: string): KeyIdentification {
  const trimmed = key.trim();

  for (const pattern of KEY_PATTERNS) {
    if (pattern.regex.test(trimmed)) {
      return {
        provider: pattern.provider,
        confidence: pattern.confidence,
        description: pattern.description,
      };
    }
  }

  return {
    provider: KeyProvider.Unknown,
    confidence: "low",
    description: "Unknown key format",
  };
}
