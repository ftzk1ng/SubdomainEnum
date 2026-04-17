# SubdomainEnum

<p align="center">
  A lightweight tool for subdomain discovery through VirusTotal, DNS resolution, and initial web validation.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10%2B-111111?style=flat-square&logo=python&logoColor=white&labelColor=000000" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/license-MIT-111111?style=flat-square&logo=open-source-initiative&logoColor=white&labelColor=000000" alt="MIT License">
  <img src="https://img.shields.io/badge/source-VirusTotal-111111?style=flat-square&logo=virustotal&logoColor=white&labelColor=000000" alt="VirusTotal Source">
  <img src="https://img.shields.io/badge/focus-OSINT%20%7C%20Surface%20Web-111111?style=flat-square&logo=datadog&logoColor=white&labelColor=000000" alt="OSINT and Surface Web Focus">
</p>

## About

`SubdomainEnum` was built for a simple and practical workflow: query subdomains known by VirusTotal, check which ones resolve through DNS, and, when useful, validate which hosts actually respond over `HTTPS` or `HTTP`.

This is not an exploitation, fuzzing, or brute-force tool. The goal is to support triage, OSINT workflows, and initial external surface validation in a direct and useful way.

## What it does

- queries subdomains through the VirusTotal API
- resolves discovered hostnames concurrently
- tests `HTTPS` by default
- allows `HTTP` only when explicitly requested
- saves results to a file when needed
- reads the API key from an environment variable or secure prompt

## Technologies

- Python 3
- `dnspython`
- VirusTotal API v3
- `ThreadPoolExecutor` for concurrency
- standard library `urllib` and `ssl`

## Workflow

```text
VirusTotal -> DNS -> HTTPS/HTTP -> terminal or file output
```

## Installation

Clone the repository and enter the project folder:

```bash
git clone https://github.com/ftzk1ng/SubdomainEnum.git
cd SubdomainEnum
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the required dependency:

```bash
python -m pip install dnspython
```

## Configuration

The safest way is to define the API key in your environment:

```bash
export VT_API_KEY="your_key_here"
```

If you prefer a local file, copy the template:

```bash
cp .env.example .env
```

Then edit `.env` locally with your key. That file should never be versioned.

## Quick usage

Basic query:

```bash
python3 subenum.py google.com
```

Query with web validation:

```bash
python3 subenum.py google.com --insecure
```

Smaller test run:

```bash
python3 subenum.py google.com --virustotal-max-results 20
```

Save output to a file:

```bash
python3 subenum.py google.com -o results.txt
```

Use HTTP only:

```bash
python3 subenum.py google.com --http-only
```

Allow fallback from HTTPS to HTTP:

```bash
python3 subenum.py google.com --allow-http-fallback
```

## Main options

- `--virustotal-max-results`: defines the maximum number of queried subdomains
- `--check-web`: keeps web validation enabled
- `--no-check-web`: skips the HTTP/HTTPS validation step
- `--web-timeout`: adjusts the web validation timeout
- `--http-only`: uses HTTP only
- `--allow-http-fallback`: tries HTTP after HTTPS fails
- `--insecure`: disables TLS validation for controlled testing
- `-o` or `--output`: saves output to a file

To view all options:

```bash
python3 subenum.py --help
```

## Example output

```text
[*] VirusTotal returned 20 subdomain(s).
[+] Found 16 active subdomain(s):
 - ead.example.com -> 203.0.113.10
 - app.example.com -> 203.0.113.11
[*] Tested 20 candidate(s).
[*] Failed or inactive: 4
[+] Web-accessible hosts: 8
 - ead.example.com -> https://ead.example.com (status: 200)
 - app.example.com -> https://app.example.com (status: 403)
```

## Repository structure

```text
.
├── subenum.py
├── .env.example
├── .gitignore
├── README.md
├── SECURITY.md
└── LICENSE
```

## Good practices

- use the tool only in authorized contexts
- treat `403` and `404` as signs of an exposed web service, not as host absence
- avoid publishing sensitive third-party inventories
- revoke any exposed key immediately
- use `--insecure` only when you clearly understand why

## Limitations

- result quality depends on what VirusTotal knows about the target domain
- not every resolved host represents a relevant or current asset
- the web check confirms service presence, not application behavior
- environments with broken certificates may require TLS validation adjustments

## Security

Guidance on responsible use, secret handling, and reporting security issues is available in [SECURITY.md](./SECURITY.md).

## License

This project is licensed under the [MIT License](./LICENSE).
