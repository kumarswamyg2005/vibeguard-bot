# VibeGuard Bot — Architecture

## One line
A cron job on GitHub Actions clones opted-in repos, finds Supabase security
problems, and opens small fix PRs that carry their own tests. No server.

## The tick (every 15 minutes)

```
tick.yml (cron) ── python -m vibeguard.tick
        │
        ├─ 1. Sync installations ── App API: list installations + repos
        │      upsert installations/repos, mark removed → stop calling them
        │
        ├─ 2. Scan changed repos ── compare HEAD sha vs repos.last_scanned_sha
        │      git clone --depth 1 → scanner/ → findings upserted by fingerprint
        │      findings no longer present → status=fixed (if a fix PR merged)
        │      post Check Run "VibeGuard: N critical" on new HEAD
        │
        ├─ 3. Commands ── list new comments on bot PRs/issues
        │      /vibeguard accept → accepted_risk; /vibeguard false-positive → closed
        │      dedupe via seen_comments
        │
        ├─ 4. Outbound bookkeeping ── refresh open PR/issue states
        │      merged → merged_at; closed unmerged → 14-day repo cooldown
        │
        ├─ 5. Emit ── at most the rate-limited number of outbound items:
        │      onboarding PR (new repo) → fix PR (max 1 open per repo) →
        │      decision issue (no safe deterministic fix)
        │      every fix PR passes the self-review gate first
        │
        └─ 6. tick_runs row + one line of counts to stdout
```

## Self-review gate (replaces human approval)

Before any outbound fix PR:

1. **pgTAP** — the generated migration + generated pgTAP test are applied to an
   ephemeral local Supabase database (`supabase start` in a temp dir). If the
   test fails, there is no PR.
2. **Diff scope** — the PR may only add new files (migration, test) or edit the
   exact flagged lines. Verified against the computed change set.
3. **Copy lint** — the PR body is scanned for secrets and anything resembling
   row data before it leaves.

Any failure → finding becomes `needs_decision` and the operator is told.

## Why no server

- $0 forever: public-repo Actions minutes are free; Supabase free tier holds state.
- Nothing to keep alive, nothing inbound to attack.
- 15-minute polling latency is fine for "find and fix" — the worst case is a
  fix PR landing 30 minutes after a vulnerable push instead of 15.
- Trade-off accepted: owner commands in comments are also 15-minute-polled,
  and the bot cannot react to uninstall events instantly (next tick catches it).

## Trust boundaries

| Actor | Can | Cannot |
|---|---|---|
| Owner | install app, set `live_probe`, merge/close PRs, `/vibeguard` commands | see other owners' findings |
| Bot (Actions) | read opted-in repos, open PRs/issues, probe with anon key only | read row data, use secret keys, touch uninstalled repos |
| Operator (Kumar/Devin Bot) | read all findings via Supabase MCP/SQL | read owner row data |
| Public | Pages site, aggregates only | open findings, repo names (unless opted in) |

Untrusted input: everything in owner repos (file contents, migration SQL) and
every comment on bot PRs/issues. All of it is parsed as data. Comment text is
matched against an exact command grammar; nothing is ever executed or
interpolated into shell, SQL, or prompts. Repo file contents are read by the
scanner only — never eval'd, templated, or echoed to logs.

## Components

| Module | Job |
|---|---|
| `vibeguard/policy.py` | the 13 invariants as data + consent/rate-limit helpers |
| `vibeguard/tick.py` | orchestrator; all decisions, no I/O of its own |
| `vibeguard/scanner/` | repo file walk, pglast migration analysis, secret rules |
| `vibeguard/scanner/probe.py` | HEAD-only live proof (VG003), consent + host + rate caps |
| `vibeguard/fixer/` | deterministic fix generators, PR body templates |
| `vibeguard/fixer/gate.py` | self-review gate (pgTAP, diff scope, copy lint) |
| `vibeguard/gh/` | App JWT, installation tokens, REST client, shallow clone |
| `vibeguard/db/` | psycopg3 raw SQL; `Store` protocol + `FakeStore` for tests |
| `vibeguard/site/` | Jinja2 → static HTML for GitHub Pages |
| `vibeguard/logging_config.py` | public-safe logging: counts/ids only + secret redaction |

## State

One Postgres: Kumar's Supabase project. Schema in `supabase/migrations`,
applied with `supabase db push`. The bot connects as role `vibeguard_app`
(session pooler URL in the `SUPABASE_DB_URL` Actions secret). RLS is enabled
on every table; policies grant `vibeguard_app` exactly what it needs.

All runtime credentials are GitHub App credentials (`GH_APP_ID`,
`GH_APP_PRIVATE_KEY`) stored as Actions secrets. `GH_ADMIN_TOKEN` is used only
for admin/setup tasks and may expire without stopping the bot.

## Failure model

Every write is an upsert keyed on natural uniqueness (`repo_id+fingerprint`,
`repo_id+commit_sha`, `comment_id`). A crash mid-tick leaves consistent state;
the next tick resumes. Actions `concurrency: tick, cancel-in-progress: false`
guarantees no overlap. GitHub 403/429 → the tick stops cleanly and records it.
