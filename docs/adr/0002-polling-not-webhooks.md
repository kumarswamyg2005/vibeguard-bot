# ADR 0002: Poll the App API instead of webhooks

Status: accepted

## Context

A webhook needs a public endpoint — a server. ADR 0001 removed the server.

## Decision

The GitHub App is created with `hook_attributes.active = false`. The tick
polls:

- installations + repos via `GET /app/installations` and
  `GET /installation/repositories`
- new PR/issue comments via `?since=` on the comments endpoints, deduplicated
  in `seen_comments`
- outbound PR state via `GET /repos/{owner}/{repo}/pulls/{n}`

## Consequences

- + No inbound endpoint, no webhook secret to rotate (one is stored anyway
  for future use), no missed-event recovery logic — state is rebuilt from
  listings each tick.
- − Comment commands (`/vibeguard accept`) take effect within one tick, not
  instantly. Documented in `docs/config.md`.
