# sikker

The official CLI for [SikkerAPI](https://sikkerapi.com) — IP reputation, blacklists, abuse reports, and TAXII/STIX feeds from your terminal.

## Install

### Quick install (Linux / macOS)

```sh
curl -sSL https://raw.githubusercontent.com/sikkerapi/sikker-cli/main/scripts/install.sh | sh
```

### Go install

```sh
go install github.com/sikkerapi/sikker-cli@latest
```

### GitHub Releases

Download pre-built binaries from [Releases](https://github.com/sikkerapi/sikker-cli/releases).

Available for Linux, macOS, and Windows (amd64 + arm64).

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
```

| Flag | Description |
|------|-------------|
| `--max-age` | Maximum data age in seconds |
| `--verbose` | Include detailed data (default: true) |
| `--protocols` | Comma-separated protocol filter |
| `--exclude` | Fields to exclude from response |
| `--ignore-whitelist` | Ignore whitelist filtering |
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

## Environment variables

| Variable | Description |
|----------|-------------|
| `SIKKERAPI_KEY` | API key (overrides saved config) |
| `SIKKERAPI_URL` | Base URL override (default: `https://api.sikkerapi.com`) |
| `NO_COLOR` | Disable colored output |

## License

MIT
