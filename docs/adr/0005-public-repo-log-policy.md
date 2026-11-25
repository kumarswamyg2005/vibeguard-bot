# ADR 0005: Public-repo log policy (invariant 7)

Status: accepted

## Context

`vibeguard-bot` is public (required for free Actions minutes and the public
scoreboard narrative). Actions logs are therefore public. Findings name
private repos, files, and tables — leaking them in logs would expose the
very vulnerabilities the bot reports.

## Decision

- One formatter, `PublicLogFormatter`: emitted lines may contain only
  counts, durations, and opaque IDs (installation id, repo id, scan id).
  Repo names, logins, paths, table names, finding details are forbidden.
- A `SecretRedactionFilter` additionally scrubs `eyJ*` JWTs, `sb_secret_*`,
  `sb_publishable_*`, `postgres(ql)?://` URLs, and `x-access-token:` URLs.
- The privacy test runs a full tick over fixtures with private-sounding
  names and greps captured stdout/stderr/logs for all of them.

## Consequences

- + Findings can never leak through the loudest accidental channel.
- − Debugging real runs is harder; `tick_runs` carries counts and error
  classes (not messages) for the operator.
