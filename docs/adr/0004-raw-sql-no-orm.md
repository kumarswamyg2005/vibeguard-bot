# ADR 0004: Raw SQL over psycopg3, no ORM

Status: accepted

## Context

State is ~8 tables with simple upserts and one aggregate view. An ORM adds a
migration framework, a model layer, and a second schema source of truth.

## Decision

- `psycopg[binary]` v3, `dict_row`, parameterized raw SQL only.
- Schema lives in `supabase/migrations` and is applied with
  `supabase db push` — the same mechanism the bot writes fix migrations for.
- `vibeguard/db/` exposes a `Store` protocol; `SqlStore` implements it on a
  connection, `FakeStore` (in-memory, constraint-faithful) implements it for
  tests so tick tests are hermetic.
- RLS on every table; the app connects as `vibeguard_app`, not `postgres`.

## Consequences

- + The schema is reviewed exactly like the migrations the bot ships.
- + Hermetic tests for the whole tick loop.
- − Discipline required: every query goes through `Store` methods so fakes
  stay faithful.
