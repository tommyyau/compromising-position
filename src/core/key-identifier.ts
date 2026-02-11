import type { SecureBuffer } from "./secure-buffer.js";
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
  // GitLab Personal Access Token
  {
    provider: KeyProvider.GitLabPAT,
    regex: /^glpat-[A-Za-z0-9_-]{20,}$/,
    confidence: "high",
    description: "GitLab Personal Access Token",
  },
  // GitLab Pipeline Trigger Token
  {
    provider: KeyProvider.GitLabPipeline,
    regex: /^glptt-[A-Za-z0-9_-]{20,}$/,
    confidence: "high",
    description: "GitLab Pipeline Trigger Token",
  },
  // npm token
  {
    provider: KeyProvider.NpmToken,
    regex: /^npm_[A-Za-z0-9]{36,}$/,
    confidence: "high",
    description: "npm access token",
  },
  // PyPI token
  {
    provider: KeyProvider.PyPIToken,
    regex: /^pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}$/,
    confidence: "high",
    description: "PyPI API token",
  },
  // Shopify Private App Token
  {
    provider: KeyProvider.ShopifyPrivate,
    regex: /^shppa_[a-fA-F0-9]{32,}$/,
    confidence: "high",
    description: "Shopify Private App token",
  },
  // Shopify Access Token
  {
    provider: KeyProvider.ShopifyAccess,
    regex: /^shpat_[a-fA-F0-9]{32,}$/,
    confidence: "high",
    description: "Shopify Access token",
  },
  // DigitalOcean Personal Access Token
  {
    provider: KeyProvider.DigitalOceanPAT,
    regex: /^dop_v1_[a-f0-9]{64}$/,
    confidence: "high",
    description: "DigitalOcean Personal Access Token",
  },
  // DigitalOcean OAuth Token
  {
    provider: KeyProvider.DigitalOceanOAuth,
    regex: /^doo_v1_[a-f0-9]{64}$/,
    confidence: "high",
    description: "DigitalOcean OAuth token",
  },
  // Supabase
  {
    provider: KeyProvider.Supabase,
    regex: /^sbp_[a-f0-9]{40,}$/,
    confidence: "high",
    description: "Supabase service key",
  },
  // HashiCorp Vault
  {
    provider: KeyProvider.HashiCorpVault,
    regex: /^hvs\.[A-Za-z0-9_-]{24,}$/,
    confidence: "high",
    description: "HashiCorp Vault token",
  },
  // Terraform Cloud
  {
    provider: KeyProvider.TerraformCloud,
    regex: /^atlasv1-[A-Za-z0-9_-]{60,}$/,
    confidence: "high",
    description: "Terraform Cloud API token",
  },
  // PlanetScale
  {
    provider: KeyProvider.PlanetScale,
    regex: /^pscale_tkn_[A-Za-z0-9_-]{30,}$/,
    confidence: "high",
    description: "PlanetScale database token",
  },
  // Postman
  {
    provider: KeyProvider.Postman,
    regex: /^PMAK-[A-Za-z0-9]{24,}-[A-Za-z0-9]{34,}$/,
    confidence: "high",
    description: "Postman API key",
  },
  // Grafana Service Account
  {
    provider: KeyProvider.GrafanaService,
    regex: /^glsa_[A-Za-z0-9_]{32,}_[a-f0-9]{8}$/,
    confidence: "high",
    description: "Grafana Service Account token",
  },
  // Linear
  {
    provider: KeyProvider.Linear,
    regex: /^lin_api_[A-Za-z0-9]{40,}$/,
    confidence: "high",
    description: "Linear API key",
  },
  // Netlify
  {
    provider: KeyProvider.Netlify,
    regex: /^nfp_[A-Za-z0-9]{40,}$/,
    confidence: "high",
    description: "Netlify personal access token",
  },
  // Doppler Service Token
  {
    provider: KeyProvider.DopplerServiceToken,
    regex: /^dp\.st\.[A-Za-z0-9_-]{40,}$/,
    confidence: "high",
    description: "Doppler service token",
  },
  // Doppler Service Account
  {
    provider: KeyProvider.DopplerServiceAccount,
    regex: /^dp\.sa\.[A-Za-z0-9_-]{40,}$/,
    confidence: "high",
    description: "Doppler service account token",
  },
  // Buildkite
  {
    provider: KeyProvider.Buildkite,
    regex: /^bkua_[A-Za-z0-9]{40,}$/,
    confidence: "high",
    description: "Buildkite Agent token",
  },
  // Atlassian API Token
  {
    provider: KeyProvider.Atlassian,
    regex: /^ATATT3xFfGF0[A-Za-z0-9_-]{50,}$/,
    confidence: "high",
    description: "Atlassian API token",
  },
  // Figma
  {
    provider: KeyProvider.Figma,
    regex: /^figd_[A-Za-z0-9_-]{22,}$/,
    confidence: "high",
    description: "Figma personal access token",
  },
  // CircleCI
  {
    provider: KeyProvider.CircleCI,
    regex: /^CIRCLE[A-Za-z0-9_-]{32,}$/,
    confidence: "medium",
    description: "CircleCI API token",
  },
  // Notion
  {
    provider: KeyProvider.Notion,
    regex: /^secret_[A-Za-z0-9]{43}$/,
    confidence: "medium",
    description: "Notion integration token",
  },
];

/**
 * Identify the provider and confidence for a given key.
 * Accepts SecureBuffer — regex matching is done via testPattern()
 * to keep the temporary string scoped inside SecureBuffer.
 */
export function identifyKey(secret: SecureBuffer): KeyIdentification {
  // Use withString to trim once, then test trimmed value against patterns.
  // The string is scoped to the callback and not returned.
  return secret.withString((raw) => {
    const trimmed = raw.trim();
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
      confidence: "low" as const,
      description: "Unknown key format",
    };
  });
}
