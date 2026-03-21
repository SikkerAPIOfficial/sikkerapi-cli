<p align="center">
  <a href="https://sikkerapi.com">
    <img src="https://api.sikkerapi.com/images/5f84902c-b8b2-4426-8d95-46494c170e2b.svg" alt="SikkerAPI" width="200" />
  </a>
</p>

# @sikkerapi/cli

[![npm version](https://img.shields.io/npm/v/@sikkerapi/cli)](https://www.npmjs.com/package/@sikkerapi/cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

The official CLI for [SikkerAPI](https://sikkerapi.com) — IP reputation, blacklists, abuse reports, threat alerts, and TAXII/STIX feeds from your terminal.

**[Full documentation](https://sikkerapi.com/docs/cli)** | **[Get an API key](https://sikkerapi.com/register)**

## Install

```sh
npm install -g @sikkerapi/cli
```

Or run without installing:

```sh
npx @sikkerapi/cli check 1.2.3.4
```

Supports Linux, macOS, and Windows on both x64 and arm64.

## Quick start

```sh
# Save your API key (one time)
sikker auth sk_your_api_key

# Look up an IP
sikker check 1.2.3.4

# Download a blacklist
sikker blacklist --score-min 75

# Report a malicious IP
sikker report 5.6.7.8 --category brute_force --protocol ssh

# Set up alerts
sikker cidr-alert 10.0.0.0/24 -l "office network"
sikker ip-alert 1.2.3.4
```

## Commands

### `sikker auth <api-key>`

Save your API key locally. Stored at `~/.config/sikkerapi/config.json`.

You can also set the `SIKKERAPI_KEY` environment variable instead.

### `sikker check <ip>`

Look up an IP address against the SikkerAPI threat intelligence database.

```sh
sikker check 8.8.8.8
sikker check 1.2.3.4 --max-age 30 --protocols ssh,http
sikker check 1.2.3.4 --json
sikker check 1.2.3.4 --fail-above 50 || block_ip 1.2.3.4
```

| Flag | Description |
|------|-------------|
| `--max-age` | Maximum data age in seconds |
| `--verbose` | Include detailed data (default: true) |
| `--protocols` | Comma-separated protocol filter |
| `--exclude` | Fields to exclude from response |
| `--ignore-whitelist` | Ignore whitelist filtering |
| `--fail-above` | Exit with code 1 if confidence >= this value |
| `--json` | Output raw JSON |

### `sikker blacklist`

Download a scored IP blacklist.

```sh
sikker blacklist --score-min 75 --limit 1000
sikker blacklist --plaintext > /etc/blocklist.txt
sikker blacklist --protocols ssh --only-countries US,CN
```

| Flag | Description |
|------|-------------|
| `--score-min` | Minimum confidence score, 1-100 (default: 50) |
| `--limit` | Maximum number of IPs |
| `--plaintext` | One IP per line, no formatting |
| `--only-countries` | Comma-separated ISO country codes to include |
| `--except-countries` | Comma-separated ISO country codes to exclude |
| `--ip-version` | `4`, `6`, or `mixed` |
| `--protocols` | Comma-separated protocol filter |
| `--min-severity` | `low`, `medium`, `high`, or `very_high` |
| `--only-asn` | Comma-separated ASNs to include |
| `--except-asn` | Comma-separated ASNs to exclude |
| `--ignore-whitelist` | Ignore whitelist filtering |
| `--json` | Output raw JSON |

### `sikker report <ip>`

Submit an abuse report for a single IP.

```sh
sikker report 1.2.3.4 --category brute_force --protocol ssh
sikker report 5.6.7.8 --category 3 --comment "repeated login attempts"
```

| Flag | Description |
|------|-------------|
| `--category` | Attack category — name or number 1-16 (required) |
| `--protocol` | Protocol (e.g. `ssh`, `http`) |
| `--comment` | Free text, max 1000 characters |
| `--json` | Output raw JSON |

**Categories:** `brute_force`, `port_scan`, `ddos`, `web_exploit`, `sql_injection`, `phishing`, `spam`, `bad_bot`, `exploited_host`, `malware`, `dns_abuse`, `open_proxy`, `iot_targeted`, `spoofing`, `fraud`, `other`

### `sikker bulk-report <file>`

Submit abuse reports in bulk from a CSV or JSON file.

```sh
sikker bulk-report reports.csv
sikker bulk-report reports.json
```

**CSV format** (header row optional):
```csv
IP,Category,Protocol,Comment
1.2.3.4,brute_force,ssh,Attack attempt
5.6.7.8,3,http,
```

**JSON format:**
```json
{"reports": [{"ip": "1.2.3.4", "category": "brute_force", "protocol": "ssh"}]}
```

Max 10,000 reports per file. Max 2MB.

### `sikker taxii list`

List STIX 2.1 objects from a TAXII collection.

```sh
sikker taxii list --limit 100
sikker taxii list --added-after 2026-02-01T00:00:00Z --json
```

| Flag | Description |
|------|-------------|
| `--limit` | Maximum number of objects |
| `--offset` | Pagination offset |
| `--added-after` | ISO 8601 timestamp filter |
| `--collection` | Collection ID (default: `sikker-threat-intel`) |
| `--json` | Output raw JSON |

### `sikker taxii get <ip>`

Get the STIX indicator for a specific IP.

```sh
sikker taxii get 1.2.3.4
sikker taxii get 1.2.3.4 --json
```

### `sikker username <username>`

Look up a brute-force username in the attack database.

```sh
sikker username root
sikker username admin --json
```

### `sikker email <email>`

Look up an SMTP recipient email in the attack database.

```sh
sikker email admin@example.com
sikker email test@gmail.com --json
```

### `sikker bulk-check <file>`

Check multiple IPs at once from a file.

```sh
sikker bulk-check ips.txt
sikker bulk-check ips.txt -o results.csv
sikker bulk-check ips.txt --json
```

File format: one IP per line (.txt or .csv). Max 10,000 IPs per request.

| Flag | Description |
|------|-------------|
| `-o, --output` | Output CSV file path (default: `bulk-check-<timestamp>.csv`) |
| `--json` | Output raw JSON |

### `sikker ip-alert`

Manage IP address alerts.

```sh
sikker ip-alert 1.2.3.4
sikker ip-alert 1.2.3.4 -l "production server"
sikker ip-alert list
sikker ip-alert delete <alert-id>
```

### `sikker cidr-alert`

Manage CIDR range alerts.

```sh
sikker cidr-alert 192.168.1.0/24
sikker cidr-alert 10.0.0.0/16 -l "office network"
sikker cidr-alert list
sikker cidr-alert delete <alert-id>
```

### `sikker username-alert`

Manage username alerts.

```sh
sikker username-alert admin
sikker username-alert deploy -l "CI/CD user"
sikker username-alert list
sikker username-alert delete <alert-id>
```

### `sikker email-alert`

Manage email address alerts.

```sh
sikker email-alert admin@example.com
sikker email-alert ops@company.com -l "ops inbox"
sikker email-alert list
sikker email-alert delete <alert-id>
```

All alert commands support `-l, --label` to add a label and `--json` for raw JSON output. Alert limits are enforced based on your subscription tier.

## Environment variables

| Variable | Description |
|----------|-------------|
| `SIKKERAPI_KEY` | API key (overrides saved config) |
| `SIKKERAPI_URL` | Base URL override (default: `https://api.sikkerapi.com`) |
| `NO_COLOR` | Disable colored output |

## What is SikkerAPI?

[SikkerAPI](https://sikkerapi.com) is an IP threat intelligence platform powered by a global network of honeypots. We capture real attacker behavior across 15+ protocols (SSH, HTTP, FTP, SMTP, and more) and provide IP reputation scores, blacklists, and structured threat data via API.

- [Documentation](https://sikkerapi.com/docs)
- [Pricing](https://sikkerapi.com/pricing)
- [Threat catalog](https://sikkerapi.com/threats)

## License

MIT
