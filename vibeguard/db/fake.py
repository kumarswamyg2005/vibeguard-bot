"""In-memory Store that mimics the real constraints for hermetic tests."""

from __future__ import annotations

import datetime as dt
from typing import Any

from vibeguard.db.store import FindingRow, OutboundRow, RepoRow, TickStats
from vibeguard.scanner.model import Finding


class FakeStore:
    def __init__(self) -> None:
        self.installations: dict[int, dict[str, Any]] = {}
        self.repos: dict[int, RepoRow] = {}
        self.scans: dict[int, dict[str, Any]] = {}
        self.findings: dict[int, FindingRow] = {}
        self.outbound: dict[int, OutboundRow] = {}
        self.seen_comments: set[int] = set()
        self.tick_runs: list[dict[str, Any]] = []
        self.deleted_findings = 0
        self._next = 1

    def _id(self) -> int:
        i = self._next
        self._next += 1
        return i

    # -- installations ----------------------------------------------------

    def sync_installations(self, installs: list[dict[str, Any]], now: dt.datetime) -> None:
        seen_inst: set[int] = set()
        seen_repos: set[int] = set()
        for inst in installs:
            gh_id = inst["gh_installation_id"]
            seen_inst.add(gh_id)
            row = self.installations.get(gh_id)
            if row is None:
                row = {"id": self._id(), "removed_at": None,
                       "account_login": inst["account_login"]}
                self.installations[gh_id] = row
            row["removed_at"] = None
            for r in inst.get("repos", []):
                gh_repo_id = r["gh_repo_id"]
                seen_repos.add(gh_repo_id)
                existing = self._repo_by_gh_id(gh_repo_id)
                if existing is None:
                    rid = self._id()
                    self.repos[rid] = RepoRow(
                        id=rid,
                        installation_id=gh_id,
                        gh_repo_id=gh_repo_id,
                        full_name=r["full_name"],
                        default_branch=r.get("default_branch", "main"),
                    )
                else:
                    existing.status = "active"
                    existing.full_name = r["full_name"]
                    existing.default_branch = r.get("default_branch", "main")
        for gh_id, inst in self.installations.items():
            if gh_id not in seen_inst and inst["removed_at"] is None:
                inst["removed_at"] = now
        for repo in self.repos.values():
            inst_removed = any(
                gh_id == repo.installation_id and i["removed_at"] is not None
                for gh_id, i in self.installations.items()
            )
            if repo.gh_repo_id not in seen_repos or inst_removed:
                repo.status = "removed"

    def _repo_by_gh_id(self, gh_repo_id: int) -> RepoRow | None:
        for r in self.repos.values():
            if r.gh_repo_id == gh_repo_id:
                return r
        return None

    def list_active_repos(self) -> list[RepoRow]:
        return [r for r in self.repos.values() if r.status == "active"]

    def get_repo(self, repo_id: int) -> RepoRow | None:
        return self.repos.get(repo_id)

    def update_repo_scan(self, repo_id: int, sha: str, *, supabase_url: str | None,
                         live_probe: bool, public_on_scoreboard: bool) -> None:
        r = self.repos[repo_id]
        r.last_scanned_sha = sha
        r.supabase_url = supabase_url or r.supabase_url
        r.live_probe = live_probe
        r.public_on_scoreboard = public_on_scoreboard

    def mark_onboarded(self, repo_id: int, now: dt.datetime) -> None:
        self.repos[repo_id].onboarded_at = now

    # -- scans + findings ---------------------------------------------------

    def create_scan(self, repo_id: int, sha: str, trigger: str, version: str,
                    now: dt.datetime) -> int:
        for s in self.scans.values():
            if s["repo_id"] == repo_id and s["commit_sha"] == sha:
                return s["id"]  # unique (repo_id, commit_sha) → idempotent
        sid = self._id()
        self.scans[sid] = {"id": sid, "repo_id": repo_id, "commit_sha": sha,
                           "trigger": trigger, "version": version, "started_at": now,
                           "finished_at": None, "error": None}
        return sid

    def finish_scan(self, scan_id: int, now: dt.datetime, error: str | None = None) -> None:
        self.scans[scan_id]["finished_at"] = now
        self.scans[scan_id]["error"] = error

    def upsert_findings(self, repo_id: int, scan_id: int,
                        findings: list[Finding], now: dt.datetime) -> None:
        for f in findings:
            existing = self.find_finding(repo_id, f.fingerprint)
            if existing is None:
                self.findings[self._id()] = FindingRow(
                    id=self._next - 1, repo_id=repo_id, rule_id=f.rule_id,
                    severity=f.severity, fingerprint=f.fingerprint,
                    evidence=dict(f.evidence), status="open", opened_at=now)
            else:
                if existing.status in ("accepted_risk", "false_positive"):
                    continue  # owner verdict sticks
                if existing.status in ("fixed",):
                    continue
                existing.evidence = dict(f.evidence)
                if existing.status == "open":
                    existing.status = "open"

    def close_absent_findings(self, repo_id: int, present: set[str],
                              now: dt.datetime) -> int:
        closed = 0
        for f in self.findings.values():
            if (f.repo_id == repo_id and f.fingerprint not in present
                    and f.status in ("open", "fix_pr_open", "needs_decision")):
                f.status = "fixed"
                f.closed_at = now
                closed += 1
        return closed

    def open_findings(self, repo_id: int,
                      statuses: tuple[str, ...] = ("open", "needs_decision")) -> list[FindingRow]:
        return [f for f in self.findings.values()
                if f.repo_id == repo_id and f.status in statuses]

    def set_finding_status(self, finding_id: int, status: str, now: dt.datetime) -> None:
        f = self.findings[finding_id]
        f.status = status
        if status in ("fixed", "accepted_risk", "false_positive"):
            f.closed_at = now

    def find_finding(self, repo_id: int, fingerprint: str) -> FindingRow | None:
        for f in self.findings.values():
            if f.repo_id == repo_id and f.fingerprint == fingerprint:
                return f
        return None

    # -- outbound -----------------------------------------------------------

    def repo_has_open_fix_pr(self, repo_id: int) -> bool:
        return any(o.repo_id == repo_id and o.kind == "fix_pr" and o.state == "open"
                   for o in self.outbound.values())

    def finding_has_outbound(self, finding_id: int) -> bool:
        return any(o.finding_id == finding_id for o in self.outbound.values())

    def outbound_today(self, repo_id: int, day: dt.date) -> int:
        return sum(1 for o in self.outbound.values()
                   if o.repo_id == repo_id and o.created_at and o.created_at.date() == day)

    def record_outbound(self, repo_id: int, finding_id: int | None, kind: str,
                        gh_number: int | None, state: str, now: dt.datetime) -> int:
        oid = self._id()
        self.outbound[oid] = OutboundRow(id=oid, repo_id=repo_id, finding_id=finding_id,
                                       kind=kind, gh_number=gh_number, state=state,
                                       created_at=now)
        return oid

    def list_open_outbound(self) -> list[OutboundRow]:
        return [o for o in self.outbound.values() if o.state == "open"]

    def update_outbound_state(self, outbound_id: int, state: str, now: dt.datetime,
                              merged: bool = False) -> None:
        o = self.outbound[outbound_id]
        o.state = state
        if merged:
            o.merged_at = now
        if state in ("closed", "merged"):
            o.closed_at = now

    def set_cooldown(self, repo_id: int, until: dt.datetime) -> None:
        self.repos[repo_id].cooldown_until = until

    def comment_seen(self, comment_id: int) -> bool:
        return comment_id in self.seen_comments

    def mark_comment_seen(self, comment_id: int) -> None:
        self.seen_comments.add(comment_id)

    def finding_for_outbound(self, outbound_id: int) -> FindingRow | None:
        o = self.outbound.get(outbound_id)
        if o is None or o.finding_id is None:
            return None
        return self.findings.get(o.finding_id)

    def write_tick_run(self, started: dt.datetime, finished: dt.datetime,
                       stats: TickStats) -> None:
        self.tick_runs.append({"started_at": started, "finished_at": finished,
                               "repos_checked": stats.repos_checked, "scans": stats.scans,
                               "prs_opened": stats.prs_opened, "errors": stats.errors})

    def delete_stale_removed_findings(self, before: dt.datetime) -> int:
        doomed = [fid for fid, f in self.findings.items()
                  if f.closed_at is not None and f.closed_at < before
                  and self.repos[f.repo_id].status == "removed"]
        for fid in doomed:
            del self.findings[fid]
        self.deleted_findings += len(doomed)
        return len(doomed)
