# ADR 0001: GitHub Actions cron instead of a server

Status: accepted

## Context

Infra budget is $0 and no credit card exists. The previous VibeGuard used
FastAPI + Celery + a hosted worker, which dies the moment a host bill is
missed. The bot must also keep running after the Devin Max month ends.

## Decision

All recurring work runs as `tick.yml` on GitHub Actions (`*/15 * * * *` +
`workflow_dispatch`) in the public repo `vibeguard-bot`. State lives in the
operator's Supabase free-tier Postgres. `keepalive.yml` commits a weekly
scoreboard snapshot so GitHub never auto-disables the schedules (60-day
inactivity rule).

## Consequences

- + Zero recurring cost, nothing inbound to attack, nothing to keep alive.
- + Public-repo Actions minutes are free.
- − Webhook events are polled at up to 15-minute latency. Accepted: fix PRs
  are not time-critical at this granularity.
- − Actions logs are public → invariant 7 (counts/IDs only in logs) plus a
  test that greps a full tick's output.
- A tick longer than 15 minutes is serialized by `concurrency.group: tick`,
  never overlapped.
