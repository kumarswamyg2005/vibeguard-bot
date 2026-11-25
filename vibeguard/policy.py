"""VibeGuard invariants — the non-negotiable rules of the bot.

Every invariant has at least one test. Keep this list numbered and identical
to the copy in AGENTS.md.

1.  Only repos in an active installation are read or written. Every operation
    checks installation_id + repo_id in SQL first.
2.  Live probing runs only when .vibeguard.yml on the default branch has
    live_probe: true AND the host equals the Supabase project URL found in
    that same repo. Otherwise zero requests go to that app.
3.  Probes are HEAD only, with `Prefer: count=exact` and `Range: 0-0`; only
    the Content-Range count is read. No row data is ever requested, stored or
    logged.
4.  Probes use only the publishable/anon key. A secret/service_role key the
    scanner finds is reported, never used.
5.  Max 1 probe/second/host, max 50 tables per scan, table names only from
    the repo (supabase/migrations, src/integrations/supabase/types.ts,
    generated types files).
6.  Secret values are never stored or logged: store key type +
    sha256(value)[:12]. A logging filter redacts JWTs (eyJ...),
    sb_secret_..., sb_publishable_..., postgres:// URLs.
7.  PUBLIC LOGS: this repo is public, so Actions logs are public. Logs may
    contain only counts, timings and opaque IDs. Never a repo name, owner
    login, file path, table name or finding detail. Enforced by one log
    formatter and a test that runs a full tick on fixtures and greps the
    captured output.
8.  One finding = one PR. A fix PR only adds files (new migration, new test)
    or edits the exact flagged lines. No reformatting, no unrelated files,
    no new dependencies.
9.  No guessed policies. No ownership column (user_id / owner_id /
    profile_id referencing auth.users) -> decision issue, never a PR.
10. Public site never shows open findings, file paths, table names or repo
    names unless that owner set public_on_scoreboard: true. Only
    closed-finding aggregates.
11. Self-review gate (replaces human approval): before any outbound PR, the
    tick must (a) apply the generated migration to an ephemeral
    `supabase start` database and pass its pgTAP test, (b) pass the
    diff-scope check (invariant 8), (c) pass the copy lint (no secret, no
    row data in the body). Any failure -> no PR; the finding becomes
    needs_decision and the operator is told.
12. Rate limits on owners: max 1 open fix PR per repo, max 3 new outbound
    items per repo per day, nothing on a repo within 14 days after its owner
    closed a bot PR unmerged (unless severity rises).
13. App uninstalled or repo removed -> stop all API calls for it at the next
    tick; its findings are kept 30 days, then deleted.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Final

# --- Invariant 5: probing caps ------------------------------------------------

PROBE_INTERVAL_SECONDS: Final[float] = 1.0
PROBE_MAX_TABLES: Final[int] = 50

# --- Invariant 12: owner-facing rate limits ------------------------------------

MAX_OPEN_FIX_PRS_PER_REPO: Final[int] = 1
MAX_OUTBOUND_PER_REPO_PER_DAY: Final[int] = 3
CLOSED_PR_COOLDOWN_DAYS: Final[int] = 14

# --- Invariant 13: retention ----------------------------------------------------

REMOVED_FINDINGS_RETENTION_DAYS: Final[int] = 30

# --- Invariant 9: ownership columns --------------------------------------------

OWNERSHIP_COLUMN_NAMES: Final[tuple[str, ...]] = (
    "user_id",
    "owner_id",
    "profile_id",
    "owner",
    "created_by",
    "author_id",
    "uid",
)

# --- Invariant 6: secret handling ----------------------------------------------

KEY_HASH_LEN: Final[int] = 12

# Repo-relative prefixes whose contents are reachable by the client bundle.
CLIENT_REACHABLE_DIRS: Final[tuple[str, ...]] = (
    "src/",
    "app/",
    "pages/",
    "components/",
    "public/",
    "client/",
    "web/",
    "frontend/",
)

# Env vars with these prefixes are inlined into client bundles.
CLIENT_ENV_PREFIXES: Final[tuple[str, ...]] = (
    "NEXT_PUBLIC_",
    "VITE_",
    "EXPO_PUBLIC_",
    "REACT_APP_",
    "PUBLIC_",
)

# Server-side dirs that are never client-reachable.
SERVER_ONLY_DIRS: Final[tuple[str, ...]] = (
    "supabase/functions/",
    "supabase/edge-functions/",
    "server/",
    "api/",
    "functions/",
    "netlify/functions/",
    ".github/",
)


def key_hash(value: str) -> str:
    """Invariant 6: only ever store sha256(value)[:12], never the value."""
    return hashlib.sha256(value.encode()).hexdigest()[:KEY_HASH_LEN]


def is_client_reachable(repo_path: str) -> bool:
    """True if a repo-relative path ships to the client bundle."""
    p = repo_path.lstrip("/")
    for d in SERVER_ONLY_DIRS:
        if p.startswith(d):
            return False
    for d in CLIENT_REACHABLE_DIRS:
        if p.startswith(d):
            return True
    return False


def env_name_is_client_exposed(name: str) -> bool:
    return name.startswith(CLIENT_ENV_PREFIXES)


# --- Invariant 2: live-probe consent --------------------------------------------


@dataclass(frozen=True)
class ProbeConsent:
    """The inputs to the live-probe consent decision.

    All values come from the repo being scanned plus the stored repo row.
    """

    live_probe_flag: bool  # .vibeguard.yml live_probe on the default branch
    repo_supabase_url: str | None  # project URL found in this repo's files
    request_host: str  # host a probe would go to

    @property
    def allowed(self) -> bool:
        if not self.live_probe_flag:
            return False
        if not self.repo_supabase_url:
            return False
        expected = host_of(self.repo_supabase_url)
        return bool(expected) and expected == self.request_host


_HOST_RE = re.compile(r"^https?://([^/]+)")


def host_of(url: str) -> str | None:
    m = _HOST_RE.match(url.strip())
    return m.group(1).lower() if m else None
