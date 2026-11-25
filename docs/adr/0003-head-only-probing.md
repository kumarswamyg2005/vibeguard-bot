# ADR 0003: Prove exposure with HEAD requests, never read rows

Status: accepted

## Context

"Your table is publicly readable" is far more convincing with proof, but the
bot must never read owner data. PostgREST returns `Content-Range: 0-0/N` on
`HEAD` with `Prefer: count=exact` and `Range: 0-0` — the row count without a
single row.

## Decision

VG003 probes are HEAD-only, enforced by an httpx transport that raises on any
other method. Only the `Content-Range` count is stored in evidence. Probes
require all of:

1. `.vibeguard.yml` on the repo's default branch has `live_probe: true`
2. the request host equals the `supabase_url` found in that same repo
3. the credential is the repo's own anon/publishable key — a discovered
   secret/service_role key is reported, never sent

Caps: 1 request/second/host, max 50 tables, table names only from files in
the repo (migrations, generated types).

## Consequences

- + A finding can say "N rows are publicly readable" — real, minimal, legal.
- + The HEAD-only transport makes "the bot read a row" impossible by
  construction, not by policy.
- − Apps behind non-PostgREST frontends aren't provable; they stay static
  findings.
