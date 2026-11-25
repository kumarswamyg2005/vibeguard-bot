"""Invariant 7: a full tick on fixtures must leak nothing private into logs.

Captures stdout/stderr + every logging record and greps for repo names,
paths, table names, JWTs, sb_ keys, postgres URLs.
"""

from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path

from tests.fake_gh import FakeGh
from vibeguard.db.fake import FakeStore
from vibeguard.logging_config import configure_logging, redact
from vibeguard.tick import run_tick

FIXTURES = Path(__file__).parent / "fixtures"
NOW = dt.datetime(2026, 11, 25, 12, 0, 0, tzinfo=dt.UTC)

PRIVATE = [
    "acme-secretapp",       # repo name
    "owner-login",          # owner login
    "posts", "profiles", "comments", "likes", "orders", "get_stats",  # tables/fns
    "src/lib/admin.ts", "supabase/migrations", ".env.local",          # paths
    "eyJhbGciOi",           # JWT prefix
    "sb_secret_", "sb_publishable_",
    "postgres://", "postgresql://",
]


def test_full_tick_log_is_public_safe(capsys):
    logger = configure_logging()
    store = FakeStore()
    gh = FakeGh([{
        "gh_installation_id": 1, "account_login": "owner-login",
        "repos": [
            {"gh_repo_id": 11, "full_name": "owner-login/acme-secretapp",
             "default_branch": "main", "sha": "s1",
             "fixture": FIXTURES / "lovable_app"},
            {"gh_repo_id": 12, "full_name": "owner-login/acme-bolt",
             "default_branch": "main", "sha": "s2",
             "fixture": FIXTURES / "bolt_app"},
        ],
    }])
    run_tick(store, gh, now=NOW, logger=logger, prober=lambda *a, **k: {})  # noqa: E501
    out = capsys.readouterr()
    blob = out.out + out.err
    for bad in PRIVATE:
        assert bad not in blob, f"log leaked {bad!r}: {blob!r}"


def test_untagged_log_lines_degrade_to_generic():
    configure_logging()
    # PublicLogFormatter turns untagged messages into level+logger only
    rec = logging.LogRecord("x", logging.INFO, "", 0,
                            "repo acme-secretapp table posts", (), None)
    formatted = logging.getLogger().handlers[0].formatter.format(rec)
    assert "acme-secretapp" not in formatted
    assert "posts" not in formatted


def test_redaction_scrubs_secrets():
    blob = (
        "jwt eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.c2ln "
        "sb_secret_abcdefghijklmnop "
        "sb_publishable_abcdefghijklmnop "
        "postgres://u:p@db.x.supabase.co/db "
        "https://x-access-token:ghs_secret@github.com/x"
    )
    cleaned = redact(blob)
    for frag in ("eyJhbGciOi", "sb_secret_a", "sb_publishable_a",
                 "postgres://u:p", "ghs_secret"):
        assert frag not in cleaned
