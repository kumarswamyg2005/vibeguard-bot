# ADR 0006: No live JS-bundle fetching for VG001

Status: accepted

## Context

The rule spec for VG001 mentions also scanning the app's live JS bundle when
`live_probe` is on. But fetching a bundle is a GET request, and invariant 3
limits all outbound requests to HEAD with row-count semantics. A custom
transport makes anything-but-HEAD impossible by construction.

## Decision

Do not fetch live bundles. Secret detection covers the repo's source, which
is where the bundle's contents originate anyway — a `service_role` key in
`src/` is caught at the source, which is also where the fix must land.

## Consequences

- + Invariant 3 stays absolute: the bot physically cannot read a response
  body from an owner's app.
- − A key injected into the bundle by a build step not present in source
  would be missed. Accepted: it would also be unfixable by a PR.
