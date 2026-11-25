# Runbook — VibeGuard Bot

## Architecture in one line

`tick.yml` (Actions cron, */15*) → `python -m vibeguard.tick` → Supabase
Postgres for state → GitHub App credentials for all repo access.

## Secrets inventory

| Secret | Where | Used for | Expiry |
|---|---|---|---|
| `GH_APP_ID` | Actions secret | mint App JWT | never |
| `GH_APP_PRIVATE_KEY` | Actions secret | mint App JWT (PEM, raw or base64) | never |
| `GH_APP_WEBHOOK_SECRET` | Actions secret | stored, unused (polling) | never |
| `SUPABASE_DB_URL` | Actions secret | session pooler conn as `vibeguard_app`, `sslmode=require` | rotate manually |
| `SUPABASE_PROJECT_REF` | Actions secret | project admin ops | never |
| `GH_ADMIN_TOKEN` | Devin org / local only | admin steps: secrets, Pages, App ops | 90 days |
| `SUPABASE_ACCESS_TOKEN` | Devin org / `~/.config/vibeguard/` | create/unpause project via Management API | manual |

**The runtime never needs `GH_ADMIN_TOKEN`** — when it lapses (90 days),
only admin/setup work is affected. Runtime uses App credentials only.

## Bootstrap: vibeguard_app role password

The migration creates `vibeguard_app` NOLOGIN. To give the bot a login:

```sql
alter role vibeguard_app with login password '<generated>';
```

Run once in the Supabase SQL editor as postgres; store the resulting
`postgresql://vibeguard_app:<pw>@aws-0-ap-south-1.pooler.supabase.com:5432/postgres?sslmode=require`
as `SUPABASE_DB_URL`. (Session pooler host: confirm under
Project Settings → Database → Connection string.)

## Failure behaviours (by design)

- Crash mid-tick → next tick resumes; every write is an upsert.
- GitHub 403/429 → tick stops cleanly, next tick continues.
- Owner force-push over a bot branch → outbound marked closed, rescan.
- Owner closes fix PR unmerged → 14-day cooldown on that repo.
- Supabase project paused (free tier) → first query fails loudly; unpause
  via dashboard or Management API
  (`POST /v1/projects/{ref}/restore`) then re-run tick.
- `supabase start` unavailable in a tick run → gate runner reports failure;
  fix becomes `needs_decision` rather than shipping unverified.

## Recovery procedures

**Supabase project paused**: Supabase free projects pause after ~7 days
inactive. The tick fails on its first query. Unpause: dashboard "Restore",
or `curl -X POST https://api.supabase.com/v1/projects/$REF/restore -H "Authorization: Bearer $SUPABASE_ACCESS_TOKEN"`, then
`gh workflow run tick.yml`.

**Pages disabled**: re-enable via `gh api repos/{owner}/{repo}/pages -X POST -f build_type=workflow`.

**App private key leaked**: GitHub App settings → revoke, generate new PEM,
`gh secret set GH_APP_PRIVATE_KEY < new.pem`.

**Migrate state DB**: `supabase db push` is idempotent; new project =
new `SUPABASE_DB_URL` + `SUPABASE_PROJECT_REF` secrets.
