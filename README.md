# compromising-position

**Were your API keys compromised? Find out.**

A privacy-preserving credential exposure checker that identifies what kind of key you have, checks if it appears in breach databases, and optionally verifies if it's still active — all from a single CLI command.

Built in response to the [OpenClaw security crisis](https://www.theregister.com/2026/02/05/openclaw_skills_marketplace_leaky_security) where tens of thousands of API keys were exposed through leaky skills, malicious plugins, and publicly accessible instances. Security advisories tell you to rotate your keys — but **compromising-position** tells you what happened *before* you rotated.

## The Problem

You connected your API keys to a service. That service got breached, misconfigured, or had a supply chain attack. You rotated your keys. But:

- Were your old keys sold on dark web marketplaces?
- Did someone use your Anthropic key to run up charges?
- Was your Slack token used to read company messages?
- Is your old key *still active* because you forgot to revoke it?

**No existing open-source tool answers all of these questions.**

## What It Does

```
echo "sk-proj-abc123..." | npx compromising-position check
```

```
--- Credential Exposure Report ---

  Risk Level:  [CRITICAL]
  Summary:     Identified as OpenAI — EXPOSED in 3 breach(es) — KEY IS CURRENTLY ACTIVE

Local Analysis
  Provider:    OpenAI (high confidence)
  Entropy:     4.82 bits/char (0.81 normalized)

HIBP Password Check (k-Anonymity)
  FOUND in breach data — 3 occurrence(s)

Plugin Results
  Common/Weak Secret Detection: Not found in common secrets blocklist
  GitGuardian HasMySecretLeaked: Found in 2 public GitHub repo(s)

Active Key Verification
  KEY IS ACTIVE — rotate immediately!
```

### The Pipeline

1. **Identify** — Recognizes 39 API key formats (OpenAI, Anthropic, AWS, GitHub, Stripe, Slack, and 33 more)
2. **Analyze** — Shannon entropy, encoding detection, weak/common secret blocklist (NIST SP 800-63B compliant)
3. **Check breach databases** — HIBP (k-anonymity), GitGuardian, EmailRep.io, DeHashed, LeakCheck, Intelligence X
4. **Verify liveness** — Optionally calls the provider API to check if the key still works (read-only, with explicit consent)
5. **Risk score** — Single assessment from `info` to `critical`

## Quick Start

```bash
# Install
npm install -g compromising-position

# Check a single key (interactive, hidden input)
compromising-position check

# Pipe a key in
echo "ghp_abc123..." | compromising-position check

# Check without network calls
echo "sk_live_abc123" | compromising-position check --offline

# Check + verify if key is still active (asks for consent)
echo "sk-proj-abc123" | compromising-position check --verify

# Check an email for breaches (requires HIBP API key)
compromising-position check-email user@example.com

# Batch check an entire .env file
compromising-position check-batch .env.old

# Output as SARIF for GitHub Advanced Security
compromising-position check-batch secrets.json --format sarif
```

## Privacy Model

Your secrets never leave your machine unless you explicitly opt in:

| Check | What's Sent | Where |
|-------|-------------|-------|
| Local analysis | Nothing | Local only |
| Common secrets blocklist | Nothing | Local only |
| HIBP password | 5-char SHA-1 prefix | api.pwnedpasswords.com |
| GitGuardian | SHA-256 hash | api.gitguardian.com |
| EmailRep.io | Full email | emailrep.io |
| Active verification | Full key | Provider API (opt-in) |

Run `compromising-position check --privacy` to see the full data flow summary.

## Supported Key Formats (39)

| Provider | Prefix | Confidence |
|----------|--------|------------|
| OpenAI | `sk-proj-`, `sk-svcacct-`, `sk-` | high |
| Anthropic | `sk-ant-api03-` | high |
| AWS | `AKIA` | high |
| GitHub | `ghp_`, `github_pat_` | high |
| Stripe | `sk_live_`, `sk_test_` | high |
| Google | `AIza` | high |
| Slack | `xoxb-`, `xoxp-` | high |
| GitLab | `glpat-`, `glptt-` | high |
| npm | `npm_` | high |
| PyPI | `pypi-AgEIcHlwaS5vcmc` | high |
| Shopify | `shppa_`, `shpat_` | high |
| DigitalOcean | `dop_v1_`, `doo_v1_` | high |
| Supabase | `sbp_` | high |
| HashiCorp Vault | `hvs.` | high |
| Terraform Cloud | `atlasv1-` | high |
| PlanetScale | `pscale_tkn_` | high |
| Postman | `PMAK-` | high |
| Grafana | `glsa_` | high |
| Linear | `lin_api_` | high |
| Netlify | `nfp_` | high |
| Doppler | `dp.st.`, `dp.sa.` | high |
| Buildkite | `bkua_` | high |
| Atlassian | `ATATT3xFfGF0` | high |
| Figma | `figd_` | high |
| SendGrid | `SG.` | high |
| Twilio | `SK` | high |
| Mailgun | `key-` | high |
| Discord | token format | medium |
| Telegram | bot token format | high |
| CircleCI | `CIRCLE` | medium |
| Notion | `secret_` | medium |

## Data Sources

### Free (no API key needed)
- **HIBP Passwords** — k-anonymity, checks 600M+ breached passwords
- **Common secrets blocklist** — Top passwords, default credentials, placeholders (fully local)
- **EmailRep.io** — Email reputation, dark web presence (100 lookups/day free)

### Requires API Key
- **HIBP Email** — Breaches, stealer logs, pastes ($3.50/mo)
- **GitGuardian** — Public GitHub repo secret scanning (free tier available)
- **DeHashed** — 15B+ records, deep/dark web
- **LeakCheck** — 28B+ records
- **Intelligence X** — Tor, I2P, paste sites

Configure keys via environment variables or `.env` file:

```bash
export HIBP_API_KEY=your-key
export GITGUARDIAN_API_TOKEN=your-token
export EMAILREP_API_KEY=your-key        # optional, higher rate limits
export DEHASHED_EMAIL=your@email.com
export DEHASHED_API_KEY=your-key
export LEAKCHECK_API_KEY=your-key
export INTELX_API_KEY=your-key
```

## Active Key Verification

The `--verify` flag checks if a key is still active by calling the provider's API:

| Provider | Endpoint | Method |
|----------|----------|--------|
| OpenAI | `/v1/models` | GET |
| Anthropic | `/v1/models` | GET |
| GitHub | `/user` | GET |
| Slack | `auth.test` | POST |
| AWS | Requires secret key — reports format only | — |

All verification is:
- **Opt-in only** — requires `--verify` flag
- **Consent-gated** — interactive prompt before each call
- **Read-only** — never makes write operations

## CI/CD Integration

### GitHub Actions

```yaml
- name: Check rotated secrets
  run: |
    echo "${{ secrets.OLD_API_KEY }}" | npx compromising-position check --json
    # Exit code 1 = exposed, 0 = clean
```

### Batch + SARIF

```yaml
- name: Scan secrets file
  run: npx compromising-position check-batch secrets.json --format sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Pre-commit Hook

```bash
# .pre-commit-config.yaml
- repo: local
  hooks:
    - id: check-secrets
      name: Check for weak secrets
      entry: bash -c 'echo "$1" | npx compromising-position check --offline'
      language: system
```

## Output Formats

| Flag | Format | Use Case |
|------|--------|----------|
| (default) | Human-readable | Terminal |
| `--json` | JSON | Scripting, pipelines |
| `--format sarif` | SARIF 2.1.0 | GitHub Advanced Security |
| `--format csv` | CSV | Spreadsheets, reporting |

## Security Design

- **SecureBuffer** — All secrets held in zeroable Buffer wrappers, never plain strings
- **Constant-time comparison** — HIBP suffix matching uses `timingSafeEqual`
- **Memory zeroing** — Buffers zeroed on disposal, secure heap allocation via `--secure-heap`
- **No secret logging** — Audit logs contain only truncated SHA-256 fingerprints
- **Terminal injection protection** — All external data sanitized before terminal output
- **Explicit Resource Management** — Supports TC39 `using` keyword for automatic cleanup

## Development

```bash
git clone https://github.com/tommyyau/compromising-position.git
cd compromising-position
npm install
npm run build
npm test          # 196 tests across 23 test files
```

## License

MIT
