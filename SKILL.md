# SubdomainEnum — Analysis Skill

You are assisting with subdomain enumeration and external attack surface analysis using the **SubdomainEnum** tool (`subenum.py`).

## Tool Overview

SubdomainEnum discovers subdomains via VirusTotal, resolves them through DNS, and validates web accessibility (HTTPS/HTTP). It is an OSINT and recon tool — not a fuzzer or brute-force scanner.

**Pipeline:** VirusTotal → DNS resolution → HTTPS/HTTP check → output

## Key CLI Options

| Flag | Purpose |
|---|---|
| `--virustotal-max-results N` | Cap VirusTotal results (default: 1000) |
| `--no-check-web` | Skip web validation, DNS only |
| `--check-web` | Force web validation |
| `--web-timeout N` | HTTP/HTTPS timeout in seconds |
| `--http-only` | Use HTTP instead of HTTPS |
| `--allow-http-fallback` | Try HTTP when HTTPS fails |
| `--insecure` | Disable TLS validation |
| `-t / --threads N` | Concurrency (default: 20, max: 200) |
| `--timeout N` | DNS resolution timeout (default: 2.0s) |
| `-o FILE` | Save active subdomains to file |

## Output Interpretation

- `[+] Found N active subdomain(s)` — resolved via DNS, IP shown
- `[+] Web-accessible hosts` — responded to HTTP/HTTPS with a status code
- **Status 403/404** — service is exposed even if it rejects the request; do not treat as absent
- **DNS resolves but no web response** — could be internal service, firewall, or misconfiguration
- **No DNS resolution** — stale record, deprecated asset, or dangling subdomain risk

## Analysis Guidelines

When analyzing results, consider:

1. **Scope validation** — confirm the target domain is in scope before proceeding
2. **IP clustering** — group subdomains by resolved IP to map infrastructure
3. **Interesting status codes** — 200 (open), 301/302 (redirect chain), 401/403 (auth wall), 500 (error leak)
4. **Dangling subdomains** — subdomains with no DNS resolution may indicate subdomain takeover candidates
5. **Unexpected assets** — staging, dev, admin, internal-sounding names exposed externally
6. **Certificate mismatches** — use `--insecure` only to confirm presence, never to bypass in production analysis

## Responsible Use

- Only enumerate domains you own or have explicit written authorization to test
- VirusTotal results reflect passive historical data — not active scanning of the target
- Do not publish or share subdomain inventories for third-party domains
- Treat discovered subdomains as sensitive recon data

## Common Workflows

**Quick surface check:**
```bash
python3 subenum.py target.com --virustotal-max-results 50
```

**Full recon with web validation:**
```bash
python3 subenum.py target.com -o results.txt
```

**DNS-only (no HTTP noise):**
```bash
python3 subenum.py target.com --no-check-web -o dns_only.txt
```

**Broken TLS environment:**
```bash
python3 subenum.py target.com --insecure --allow-http-fallback
```

## Environment

- Requires `VT_API_KEY` in environment or `.env` file
- Python 3.10+, `dnspython` installed
- Virtual environment: `.venv/` (activate with `source .venv/bin/activate`)
