"""Store protocol shared by SqlStore (psycopg3) and FakeStore (tests).

ADR 0004: every DB access goes through these methods so the in-memory fake
stays faithful to the real constraints (unique keys, upsert semantics).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Protocol

from vibeguard.scanner.model import Finding


@dataclass
class RepoRow:
    id: int
    installation_id: int  # GitHub installation id (from installations.gh_installation_id)
    gh_repo_id: int
    full_name: str
    default_branch: str
    last_scanned_sha: str | None = None
    supabase_url: str | None = None
    live_probe: bool = False
    public_on_scoreboard: bool = False
    onboarded_at: dt.datetime | None = None
    cooldown_until: dt.datetime | None = None
    status: str = "active"


@dataclass
class FindingRow:
    id: int
    repo_id: int
    rule_id: str
    severity: str
    fingerprint: str
    evidence: dict[str, Any]
    status: str
    opened_at: dt.datetime | None = None
    closed_at: dt.datetime | None = None


@dataclass
class OutboundRow:
    id: int
    repo_id: int
    finding_id: int | None
    kind: str
    gh_number: int | None
    state: str
    created_at: dt.datetime | None = None
    merged_at: dt.datetime | None = None
    closed_at: dt.datetime | None = None


@dataclass
class Comment:
    comment_id: int
    repo_id: int
    gh_number: int  # PR or issue number the comment is on
    body: str


@dataclass
class TickStats:
    repos_checked: int = 0
    scans: int = 0
    prs_opened: int = 0
    errors: int = 0
    extra: dict[str, int] = field(default_factory=dict)


class Store(Protocol):
    def sync_installations(self, installs: list[dict[str, Any]], now: dt.datetime) -> None: ...
    def list_active_repos(self) -> list[RepoRow]: ...
    def get_repo(self, repo_id: int) -> RepoRow | None: ...
    def update_repo_scan(self, repo_id: int, sha: str, *, supabase_url: str | None,
                         live_probe: bool, public_on_scoreboard: bool) -> None: ...
    def mark_onboarded(self, repo_id: int, now: dt.datetime) -> None: ...
    def create_scan(self, repo_id: int, sha: str, trigger: str, version: str,
                    now: dt.datetime) -> int: ...
    def finish_scan(self, scan_id: int, now: dt.datetime, error: str | None = None) -> None: ...
    def upsert_findings(self, repo_id: int, scan_id: int,
                        findings: list[Finding], now: dt.datetime) -> None: ...
    def close_absent_findings(self, repo_id: int, present: set[str],
                              now: dt.datetime) -> int: ...
    def open_findings(
        self, repo_id: int,
        statuses: tuple[str, ...] = ("open", "needs_decision"),
    ) -> list[FindingRow]: ...
    def set_finding_status(self, finding_id: int, status: str, now: dt.datetime) -> None: ...
    def find_finding(self, repo_id: int, fingerprint: str) -> FindingRow | None: ...
    def repo_has_open_fix_pr(self, repo_id: int) -> bool: ...
    def finding_has_outbound(self, finding_id: int) -> bool: ...
    def outbound_today(self, repo_id: int, day: dt.date) -> int: ...
    def record_outbound(self, repo_id: int, finding_id: int | None, kind: str,
                        gh_number: int | None, state: str, now: dt.datetime) -> int: ...
    def list_open_outbound(self) -> list[OutboundRow]: ...
    def update_outbound_state(self, outbound_id: int, state: str, now: dt.datetime,
                              merged: bool = False) -> None: ...
    def set_cooldown(self, repo_id: int, until: dt.datetime) -> None: ...
    def comment_seen(self, comment_id: int) -> bool: ...
    def mark_comment_seen(self, comment_id: int) -> None: ...
    def finding_for_outbound(self, outbound_id: int) -> FindingRow | None: ...
    def write_tick_run(self, started: dt.datetime, finished: dt.datetime,
                       stats: TickStats) -> None: ...
    def delete_stale_removed_findings(self, before: dt.datetime) -> int: ...
