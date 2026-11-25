# .vibeguard.yml — configuration schema

Lives at the root of the repo's default branch. Created by the onboarding
PR; both flags default to `false`.

```yaml
# Allow live proof-of-exposure probes.
# When true, VibeGuard may send HEAD requests to the Supabase project URL
# it found in THIS repo, for table names found in THIS repo's files, using
# the repo's own anon/publishable key. Only Content-Range row counts are
# read — never row data. Max 1 req/s, max 50 tables per scan.
live_probe: false

# Show this repo's full name on the public scoreboard under
# "Opted-in public repos". Aggregates only either way.
public_on_scoreboard: false
```

## Owner commands

Posted as comments on any VibeGuard PR or issue (processed within 15 min):

- `/vibeguard accept` — mark the finding as intended exposure; it is closed
  as `accepted_risk` and won't be re-reported.
- `/vibeguard false-positive` — mark the finding as wrong; it is closed as
  `false_positive` and won't be re-reported.

## Rate limits (fixed, not configurable)

- Max 1 open fix PR per repo at a time.
- Max 3 new PRs/issues per repo per day.
- Closing a bot PR unmerged pauses outbound items on that repo for 14 days.
