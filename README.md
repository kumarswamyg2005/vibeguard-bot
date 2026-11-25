# VibeGuard Bot

An opt-in security engineer for Supabase apps built with AI app builders
(Lovable, Bolt, v0, Cursor).

Install the GitHub App on a repo and, within 15 minutes, VibeGuard:

- finds tables without Row Level Security, secret keys shipped to the client,
  and write-anything policies;
- opens **one small fix PR at a time** — each with a pgTAP test that proves
  the fix and a 30-second way to prove the problem yourself;
- re-checks every push and closes findings when the fix lands;
- proves live exposure with HEAD-only row-count probes — never a single row
  of your data (and only when you turn `live_probe` on).

There is no server to hack, no webhook to spoof and nothing to pay for:
the whole bot is a cron job on GitHub Actions plus your operator's
free-tier Supabase Postgres.

## Install

**[Install VibeGuard Bot](https://github.com/apps/vibeguard-bot/installations/new)**

Then merge the `.vibeguard.yml` PR it opens. Options live in
[docs/config.md](docs/config.md).

## What owners get

| Signal | Rule | What it means |
|---|---|---|
| critical | VG001 | secret/service_role key reachable from client code |
| critical | VG002 | public table with RLS never enabled |
| critical | VG003 | live proof: N rows readable via the anon API |
| high | VG004 | write policy `using (true)` for anon/public |
| high | VG005 | policy exists but RLS off; RLS on with no policy (info) |
| high | VG006 | `security definer` function without `set search_path` |
| high | VG007 | public storage bucket + broad select on storage.objects |
| medium | VG008 | committed `.env` containing a Supabase key |
| high | VG009 | admin authorization only in client code (heuristic) |
| info | VG010 | legacy JWT keys in use (deprecation end of 2026) |

## What it never does

- Reads your data — probes are HEAD requests returning only `Content-Range`.
- Uses a secret key it finds — they're reported, never sent anywhere.
- Touches repos you didn't install it on.
- Guesses a policy — no ownership column means a decision issue, not a PR.

## Commands

Comment on any bot PR or issue:

- `/vibeguard accept` — mark the finding as intended exposure
- `/vibeguard false-positive` — mark the finding as wrong

## For the operator

- `docs/ARCHITECTURE.md` — the tick loop and trust boundaries
- `docs/runbook.md` — tokens, expiry, recovery
- `SECURITY.md` — what's stored, what's never stored, disclosure
- `AGENTS.md` — invariants and dev commands

## Dev

```sh
uv sync && uv run pytest
supabase start && supabase test db
```
