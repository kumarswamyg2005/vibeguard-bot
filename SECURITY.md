# Security policy

## What VibeGuard stores

Per installed repo: GitHub installation/repo IDs, repo full name, default
branch, last scanned commit SHA, the `.vibeguard.yml` flags, and findings
metadata: rule id, severity, file path, line, table name, key type and
`sha256(key)[:12]`.

## What it never stores

- Secret values. Only `sha256(value)[:12]` fingerprints are persisted.
- Row data. Live proofs are HEAD requests that read `Content-Range` counts.
- Any data from repos the App isn't installed on.
- Contents of your database — the bot never connects to an owner database.

## Data lifecycle

Uninstall the App → all API calls for your repos stop at the next tick
(≤15 min). Findings are kept for 30 days (so re-installing doesn't lose
history), then deleted.

## What is public

This repo and its Actions logs are public. Logs contain only counts,
timings and opaque IDs — enforced by a privacy test that greps a full tick's
output. The scoreboard site shows aggregates only; repo names appear only
for owners who set `public_on_scoreboard: true`.

## Reporting

Found a vulnerability in VibeGuard itself, or in a PR it opened?
Open an issue on this repo **without** including secret values, or contact
the operator via GitHub. For a bot PR that may have broken your app, reply
on the PR — it is triaged daily.
