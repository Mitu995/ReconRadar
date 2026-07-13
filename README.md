cat > README.md << 'EOF'
# ReconRadar

**Consolidated Web & GitHub Reconnaissance Tool** — single-file recon script for authorized security testing / bug bounty hunting.

> ⚠️ **ETHICAL USE ONLY** — Only run this against a target you own, a target explicitly in-scope in an active bug bounty program (verify against the official scope page), or a target covered by a signed authorization/contract. This tool performs **read-only, non-destructive** checks only — it does not exploit anything, brute-force credentials, or send exploit payloads. Unauthorized scanning may violate computer misuse laws in your jurisdiction.

---

## Features

- **Security Header Analysis** — checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, plus cookie flags (Secure/HttpOnly/SameSite) and info-leaking headers (Server, X-Powered-By).
- **Exposed Sensitive File Detection** — probes for `.git/HEAD`, `.env`, backup files, `id_rsa`, `swagger.json`, actuator endpoints, and more (threaded scanning).
- **SSL/TLS Certificate Check** — expiry, issuer, and validity status.
- **robots.txt / sitemap.xml Discovery** — surfaces disallowed paths and sitemap URLs for further scanning.
- **Technology / Framework / CMS Detection** — passive fingerprinting via headers, HTML markers, and cookies (WordPress, Drupal, Next.js, Laravel, Django, etc.).
- **Deep Crawl (optional)** — integrates with [Katana](https://github.com/projectdiscovery/katana) to discover JS files and URLs beyond the homepage.
- **JS File Secret & Sensitive Endpoint Scanning** — detects hardcoded AWS/Google/Stripe/Slack/Twilio/Mailgun keys, JWTs, bearer tokens, and private keys in JS bundles. **Secrets are never printed in full** — only a redacted preview plus file location.
- **Low-Hanging-Fruit Misconfiguration Checks** — CORS misconfig, directory listing, verbose error/stack trace disclosure, risky HTTP methods (PUT/DELETE/TRACE), exposed admin/API panels.
- **Subdomain Enumeration** — passive discovery via crt.sh (Certificate Transparency logs), with optional integration for subfinder, assetfinder, and findomain.
- **GitHub Org Secret-Leak Audit** — GitHub Code Search dorks across categories (credentials, CI/CD configs, staging/dev leaks, cloud pivot points, Azure/OpenAI API keys) plus optional [TruffleHog](https://github.com/trufflesecurity/trufflehog) full-history scanning with verified-secret detection.
- **Plugin Architecture** — checks register via `@register_plugin`, making it easy to add new scans without touching the main loop.
- **Flexible Output** — plain terminal output, `--output` for a text report, `--json-output` for structured JSON findings.

## Requirements

- Python 3.8+
- `pip install -r requirements.txt`

**Optional external tools** (auto-detected, skipped gracefully if missing):
| Tool | Purpose | Install |
|---|---|---|
| [katana](https://github.com/projectdiscovery/katana) | Deep crawl for JS discovery | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Subdomain enumeration | `go install github.com/tomnomnom/assetfinder@latest` |
| [findomain](https://github.com/findomain/findomain) | Subdomain enumeration | see project releases |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | Full git-history secret scan | see project releases |

## Installation

```bash
git clone <your-repo-url> ReconRadar
cd ReconRadar
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan
python reconradar.py example.com

# Full URL, with GitHub org audit
python reconradar.py https://example.com --github-org my-org

# Save findings to a text report and JSON
python reconradar.py example.com --output report.txt --json-output findings.json

# Subdomain enumeration (crt.sh + subfinder)
python reconradar.py example.com --subdomains --subfinder --subdomain-output subs.txt

# Deep crawl with Katana for JS discovery
python reconradar.py example.com --deep-crawl --crawl-depth 3

# Scan a list of targets from a file
python reconradar.py --list targets.txt

# Skip specific checks
python reconradar.py example.com --skip-js --skip-fruit
```

### GitHub Org Audit Setup

```bash
export GITHUB_TOKEN=ghp_xxxxxxxxxxxx   # classic PAT, no scopes needed for public code search
python reconradar.py example.com --github-org my-org
```

## CLI Options

| Flag | Description |
|---|---|
| `target` | Domain or URL to scan |
| `--list <file>` | Scan multiple targets from a file (one per line) |
| `--github-org <org>` | Audit a GitHub org for leaked secrets |
| `--subdomains` | Enumerate subdomains via crt.sh |
| `--subfinder` / `--assetfinder` / `--findomain` | Also run these tools if installed (needs `--subdomains`) |
| `--subdomain-output <file>` | Save discovered subdomains |
| `--output <file>` | Save findings to a text report |
| `--json-output <file>` | Save findings as structured JSON |
| `--skip-js` | Skip JS secret scanning |
| `--skip-fruit` | Skip low-hanging-fruit misconfig checks |
| `--deep-crawl` | Use Katana to crawl beyond homepage |
| `--crawl-depth <n>` | Katana crawl depth (default: 3) |
| `--crawl-limit <n>` | Max URLs kept from Katana crawl (default: 500) |

## Security Notes

- Secrets found in JS files or via GitHub audit are **redacted** in output — only enough characters are shown to verify the finding manually.
- All web checks are non-destructive GET/HEAD/OPTIONS requests only.
- Subdomain enumeration via crt.sh is fully passive (queries crt.sh only, never touches the target).

## License

MIT
EOF
