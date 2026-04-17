# Security Policy

## Overview

This project was designed for passive enumeration and initial web surface validation. It was not built for active exploitation, brute force, fuzzing, or aggressive testing.

It should only be used in authorized contexts, with legitimate goals such as defense, research, internal auditing, or previously approved assessment work.

## Security scope

This repository is mainly concerned with:

- protection of local secrets
- safe interaction with the VirusTotal API
- predictable DNS and HTTP/HTTPS validation behavior
- reduction of accidental exposure during usage and versioning

## Secrets and credentials

To keep this project safe:

- never version the `.env` file
- never publish your `VT_API_KEY` in commits, screenshots, issues, or pull requests
- use `.env.example` only as a template
- if there is any suspicion of exposure, revoke the key immediately and generate a new one

## Responsible use

When using this tool:

- confirm that you are authorized to analyze the target domain
- respect the VirusTotal API limits
- avoid disclosing active subdomain inventories without a real operational need
- treat results as triage support, not as absolute truth

## Reporting security issues

If you identify a security issue in this project, avoid opening a public issue with sensitive details.

The preferred approach is a private report including:

- a short description of the issue
- the potential impact
- minimal reproduction steps
- a suggested fix, when possible

## Maintenance guidelines

Before publishing changes:

- review what is included in the commit
- confirm that `.env` and local files were not added
- avoid placing tokens in command lines, examples, or documentation
- clearly document any new external integration

## Final note

Even small tools deserve careful operational handling. In projects like this, security depends not only on the code, but also on how the repository is maintained and how the tool is used.
