import { describe, it, expect } from "vitest";
import { identifyKey } from "../src/core/key-identifier.js";
import { SecureBuffer } from "../src/core/secure-buffer.js";
import { KeyProvider } from "../src/types/index.js";

/** Helper to identify a key string via SecureBuffer. */
function identify(key: string) {
  const sb = SecureBuffer.fromString(key);
  const result = identifyKey(sb);
  sb.dispose();
  return result;
}

describe("identifyKey", () => {
  it("should identify OpenAI project keys", () => {
    const result = identify("sk-proj-" + "a".repeat(100));
    expect(result.provider).toBe(KeyProvider.OpenAI);
    expect(result.confidence).toBe("high");
  });

  it("should identify OpenAI service account keys", () => {
    const result = identify("sk-svcacct-" + "b".repeat(100));
    expect(result.provider).toBe(KeyProvider.OpenAIService);
    expect(result.confidence).toBe("high");
  });

  it("should identify Anthropic keys", () => {
    const result = identify("sk-ant-api03-" + "c".repeat(95));
    expect(result.provider).toBe(KeyProvider.Anthropic);
    expect(result.confidence).toBe("high");
  });

  it("should identify AWS access key IDs", () => {
    const result = identify("AKIAIOSFODNN7EXAMPLE");
    expect(result.provider).toBe(KeyProvider.AWS);
    expect(result.confidence).toBe("high");
  });

  it("should identify GitHub PATs", () => {
    const result = identify("ghp_" + "a".repeat(36));
    expect(result.provider).toBe(KeyProvider.GitHubPAT);
    expect(result.confidence).toBe("high");
  });

  it("should identify GitHub fine-grained tokens", () => {
    const result = identify("github_pat_" + "a".repeat(22) + "_" + "b".repeat(59));
    expect(result.provider).toBe(KeyProvider.GitHubFineGrained);
    expect(result.confidence).toBe("high");
  });

  it("should identify Stripe live keys", () => {
    const result = identify("sk_live_" + "a".repeat(24));
    expect(result.provider).toBe(KeyProvider.StripeLive);
    expect(result.confidence).toBe("high");
  });

  it("should identify Stripe test keys", () => {
    const result = identify("sk_test_" + "a".repeat(24));
    expect(result.provider).toBe(KeyProvider.StripeTest);
    expect(result.confidence).toBe("high");
  });

  it("should identify Google API keys", () => {
    const result = identify("AIzaSyA1234567890abcdefghijklmnopqrstuv");
    expect(result.provider).toBe(KeyProvider.GoogleAPI);
    expect(result.confidence).toBe("high");
  });

  it("should identify SendGrid keys", () => {
    const result = identify("SG." + "a".repeat(22) + "." + "b".repeat(43));
    expect(result.provider).toBe(KeyProvider.SendGrid);
    expect(result.confidence).toBe("high");
  });

  it("should identify Twilio keys", () => {
    const result = identify("SK" + "a".repeat(32));
    expect(result.provider).toBe(KeyProvider.Twilio);
    expect(result.confidence).toBe("high");
  });

  it("should identify Mailgun keys", () => {
    const result = identify("key-" + "a".repeat(32));
    expect(result.provider).toBe(KeyProvider.Mailgun);
    expect(result.confidence).toBe("high");
  });

  it("should identify Telegram bot tokens", () => {
    const result = identify("123456789:" + "A".repeat(35));
    expect(result.provider).toBe(KeyProvider.TelegramBot);
    expect(result.confidence).toBe("high");
  });

  it("should return Unknown for unrecognized formats", () => {
    const result = identify("some-random-string");
    expect(result.provider).toBe(KeyProvider.Unknown);
    expect(result.confidence).toBe("low");
  });

  it("should handle whitespace trimming", () => {
    const result = identify("  AKIAIOSFODNN7EXAMPLE  ");
    expect(result.provider).toBe(KeyProvider.AWS);
  });

  // --- Phase 1: New provider patterns ---

  it("should identify GitLab PATs", () => {
    const result = identify("glpat-" + "a1B2c3D4e5F6g7H8i9J0" + "abcdef");
    expect(result.provider).toBe(KeyProvider.GitLabPAT);
    expect(result.confidence).toBe("high");
  });

  it("should not match GitLab PAT without prefix", () => {
    const result = identify("glpa-" + "a".repeat(20));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify GitLab Pipeline tokens", () => {
    const result = identify("glptt-" + "a1B2c3D4e5F6g7H8i9J0" + "abcdef");
    expect(result.provider).toBe(KeyProvider.GitLabPipeline);
    expect(result.confidence).toBe("high");
  });

  it("should not match GitLab Pipeline without correct prefix", () => {
    const result = identify("glpt-" + "a".repeat(20));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify npm tokens", () => {
    const result = identify("npm_" + "a".repeat(36));
    expect(result.provider).toBe(KeyProvider.NpmToken);
    expect(result.confidence).toBe("high");
  });

  it("should not match npm token that is too short", () => {
    const result = identify("npm_abc");
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify PyPI tokens", () => {
    const result = identify("pypi-AgEIcHlwaS5vcmc" + "a".repeat(60));
    expect(result.provider).toBe(KeyProvider.PyPIToken);
    expect(result.confidence).toBe("high");
  });

  it("should not match PyPI token without proper prefix", () => {
    const result = identify("pypi-" + "a".repeat(60));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify Shopify Private App tokens", () => {
    const result = identify("shppa_" + "a".repeat(32));
    expect(result.provider).toBe(KeyProvider.ShopifyPrivate);
    expect(result.confidence).toBe("high");
  });

  it("should not match Shopify Private with wrong prefix", () => {
    const result = identify("shpp_" + "a".repeat(32));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify Shopify Access tokens", () => {
    const result = identify("shpat_" + "a".repeat(32));
    expect(result.provider).toBe(KeyProvider.ShopifyAccess);
    expect(result.confidence).toBe("high");
  });

  it("should not match Shopify Access with wrong prefix", () => {
    const result = identify("shpa_" + "a".repeat(32));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify DigitalOcean PATs", () => {
    const result = identify("dop_v1_" + "a".repeat(64));
    expect(result.provider).toBe(KeyProvider.DigitalOceanPAT);
    expect(result.confidence).toBe("high");
  });

  it("should not match DigitalOcean PAT with wrong length", () => {
    const result = identify("dop_v1_" + "a".repeat(10));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify DigitalOcean OAuth tokens", () => {
    const result = identify("doo_v1_" + "a".repeat(64));
    expect(result.provider).toBe(KeyProvider.DigitalOceanOAuth);
    expect(result.confidence).toBe("high");
  });

  it("should not match DigitalOcean OAuth with wrong prefix", () => {
    const result = identify("doo_v2_" + "a".repeat(64));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify Supabase keys", () => {
    const result = identify("sbp_" + "a".repeat(40));
    expect(result.provider).toBe(KeyProvider.Supabase);
    expect(result.confidence).toBe("high");
  });

  it("should not match Supabase with wrong prefix", () => {
    const result = identify("sbq_" + "a".repeat(40));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify HashiCorp Vault tokens", () => {
    const result = identify("hvs." + "a".repeat(30));
    expect(result.provider).toBe(KeyProvider.HashiCorpVault);
    expect(result.confidence).toBe("high");
  });

  it("should not match HashiCorp Vault with wrong prefix", () => {
    const result = identify("hvb." + "a".repeat(30));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify Terraform Cloud tokens", () => {
    const result = identify("atlasv1-" + "a".repeat(64));
    expect(result.provider).toBe(KeyProvider.TerraformCloud);
    expect(result.confidence).toBe("high");
  });

  it("should not match Terraform Cloud without proper prefix", () => {
    const result = identify("atlasv2-" + "a".repeat(64));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify PlanetScale tokens", () => {
    const result = identify("pscale_tkn_" + "a".repeat(40));
    expect(result.provider).toBe(KeyProvider.PlanetScale);
    expect(result.confidence).toBe("high");
  });

  it("should not match PlanetScale with wrong prefix", () => {
    const result = identify("pscale_tok_" + "a".repeat(40));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify Postman keys", () => {
    const result = identify("PMAK-" + "a".repeat(24) + "-" + "b".repeat(34));
    expect(result.provider).toBe(KeyProvider.Postman);
    expect(result.confidence).toBe("high");
  });

  it("should not match Postman without dash separator", () => {
    const result = identify("PMAK-" + "a".repeat(60));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify Grafana Service Account tokens", () => {
    const result = identify("glsa_" + "a".repeat(32) + "_" + "a".repeat(8));
    expect(result.provider).toBe(KeyProvider.GrafanaService);
    expect(result.confidence).toBe("high");
  });

  it("should not match Grafana without trailing hash", () => {
    const result = identify("glsa_" + "a".repeat(32));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify Linear API keys", () => {
    const result = identify("lin_api_" + "a".repeat(40));
    expect(result.provider).toBe(KeyProvider.Linear);
    expect(result.confidence).toBe("high");
  });

  it("should not match Linear with wrong prefix", () => {
    const result = identify("lin_ap_" + "a".repeat(40));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify Netlify tokens", () => {
    const result = identify("nfp_" + "a".repeat(40));
    expect(result.provider).toBe(KeyProvider.Netlify);
    expect(result.confidence).toBe("high");
  });

  it("should not match Netlify with wrong prefix", () => {
    const result = identify("nft_" + "a".repeat(40));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify Doppler service tokens", () => {
    const result = identify("dp.st." + "a".repeat(40));
    expect(result.provider).toBe(KeyProvider.DopplerServiceToken);
    expect(result.confidence).toBe("high");
  });

  it("should not match Doppler service token with wrong prefix", () => {
    const result = identify("dp.sv." + "a".repeat(40));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify Doppler service account tokens", () => {
    const result = identify("dp.sa." + "a".repeat(40));
    expect(result.provider).toBe(KeyProvider.DopplerServiceAccount);
    expect(result.confidence).toBe("high");
  });

  it("should not match Doppler service account with wrong prefix", () => {
    const result = identify("dp.sb." + "a".repeat(40));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify Buildkite tokens", () => {
    const result = identify("bkua_" + "a".repeat(40));
    expect(result.provider).toBe(KeyProvider.Buildkite);
    expect(result.confidence).toBe("high");
  });

  it("should not match Buildkite with wrong prefix", () => {
    const result = identify("bkub_" + "a".repeat(40));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify Atlassian API tokens", () => {
    const result = identify("ATATT3xFfGF0" + "a".repeat(60));
    expect(result.provider).toBe(KeyProvider.Atlassian);
    expect(result.confidence).toBe("high");
  });

  it("should not match Atlassian with wrong prefix", () => {
    const result = identify("ATATT3xFfGX0" + "a".repeat(60));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify Figma tokens", () => {
    const result = identify("figd_" + "a".repeat(30));
    expect(result.provider).toBe(KeyProvider.Figma);
    expect(result.confidence).toBe("high");
  });

  it("should not match Figma with wrong prefix", () => {
    const result = identify("figx_" + "a".repeat(30));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify CircleCI tokens", () => {
    const result = identify("CIRCLE" + "a".repeat(40));
    expect(result.provider).toBe(KeyProvider.CircleCI);
    expect(result.confidence).toBe("medium");
  });

  it("should not match CircleCI with short value", () => {
    const result = identify("CIRCLE" + "a".repeat(5));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });

  it("should identify Notion integration tokens", () => {
    const result = identify("secret_" + "a".repeat(43));
    expect(result.provider).toBe(KeyProvider.Notion);
    expect(result.confidence).toBe("medium");
  });

  it("should not match Notion with wrong length", () => {
    const result = identify("secret_" + "a".repeat(10));
    expect(result.provider).toBe(KeyProvider.Unknown);
  });
});
