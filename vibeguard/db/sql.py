"""SqlStore — the real Store over psycopg3 raw SQL (ADR 0004)."""

from __future__ import annotations

import datetime as dt
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


def _row(cls, r: dict) -> object:
    keep = {k: v for k, v in r.items() if k in cls.__dataclass_fields__}
    return cls(**keep)

from vibeguard.db.store import FindingRow, OutboundRow, RepoRow, TickStats
from vibeguard.scanner.model import Finding


class SqlStore:
    def __init__(self, conn: psycopg.Connection[Any]) -> None:
        self.conn = conn

    @classmethod
    def connect(cls, url: str) -> SqlStore:
        return cls(psycopg.connect(url, row_factory=dict_row))

    def _one(self, sql: str, params: tuple = ()) -> dict[str, Any] | None:
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()

    def _all(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            return list(cur.fetchall())

    def _exec(self, sql: str, params: tuple = ()) -> int:
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.rowcount

    # -- installations ------------------------------------------------------

    def sync_installations(self, installs: list[dict[str, Any]], now: dt.datetime) -> None:
        seen_inst: set[int] = set()
        seen_repos: set[int] = set()
        for inst in installs:
            gh_id = inst["gh_installation_id"]
            seen_inst.add(gh_id)
            self._exec(
                """insert into installations (gh_installation_id, account_login, removed_at)
                   values (%s, %s, null)
                   on conflict (gh_installation_id)
                   do update set account_login = excluded.account_login, removed_at = null""",
                (gh_id, inst["account_login"]))
            inst_row = self._one(
                "select id from installations where gh_installation_id = %s", (gh_id,))
            if inst_row is None:  # pragma: no cover - upsert just ran
                raise RuntimeError("installation upsert failed")
            for r in inst.get("repos", []):
                seen_repos.add(r["gh_repo_id"])
                self._exec(
                    """insert into repos
                         (installation_id, gh_repo_id, full_name, default_branch, status)
                       values (%s, %s, %s, %s, 'active')
                       on conflict (gh_repo_id)
                       do update set installation_id = excluded.installation_id,
                                    full_name = excluded.full_name,
                                    default_branch = excluded.default_branch,
                                    status = 'active'""",
                    (inst_row["id"], r["gh_repo_id"], r["full_name"],
                     r.get("default_branch", "main")))
        if seen_inst:
            self._exec(
                """update installations set removed_at = %s
                   where removed_at is null and not (gh_installation_id = any(%s))""",
                (now, list(seen_inst)))
        else:
            self._exec("update installations set removed_at = %s where removed_at is null",
                       (now,))
        self._exec(
            """update repos r set status = 'removed'
               where r.status = 'active' and (
                 not (r.gh_repo_id = any(%s))
                 or r.installation_id in (select id from installations where removed_at is not null)
               )""",
            (list(seen_repos),))
        self.conn.commit()

    _REPO_SELECT = """select r.id, i.gh_installation_id as installation_id,
        r.gh_repo_id, r.full_name, r.default_branch, r.last_scanned_sha,
        r.supabase_url, r.live_probe, r.public_on_scoreboard, r.onboarded_at,
        r.cooldown_until, r.status
        from repos r join installations i on i.id = r.installation_id"""

    def list_active_repos(self) -> list[RepoRow]:
        return [RepoRow(**r) for r in self._all(
            f"{self._REPO_SELECT} where r.status = 'active' order by r.id")]

    def get_repo(self, repo_id: int) -> RepoRow | None:
        row = self._one(f"{self._REPO_SELECT} where r.id = %s", (repo_id,))
        return RepoRow(**row) if row else None

    def update_repo_scan(self, repo_id: int, sha: str, *, supabase_url: str | None,
                         live_probe: bool, public_on_scoreboard: bool) -> None:
        self._exec(
            """update repos set last_scanned_sha = %s,
                 supabase_url = coalesce(%s, supabase_url),
                 live_probe = %s, public_on_scoreboard = %s
               where id = %s""",
            (sha, supabase_url, live_probe, public_on_scoreboard, repo_id))
        self.conn.commit()

    def mark_onboarded(self, repo_id: int, now: dt.datetime) -> None:
        self._exec("update repos set onboarded_at = %s where id = %s", (now, repo_id))
        self.conn.commit()

    # -- scans + findings ----------------------------------------------------

    def create_scan(self, repo_id: int, sha: str, trigger: str, version: str,
                    now: dt.datetime) -> int:
        row = self._one(
            """insert into scans (repo_id, commit_sha, trigger, scanner_version, started_at)
               values (%s, %s, %s, %s, %s)
               on conflict (repo_id, commit_sha) do update set repo_id = excluded.repo_id
               returning id""",
            (repo_id, sha, trigger, version, now))
        self.conn.commit()
        if row is None:  # pragma: no cover - returning clause always yields a row
            raise RuntimeError("insert returned no id")
        return int(row["id"])

    def finish_scan(self, scan_id: int, now: dt.datetime, error: str | None = None) -> None:
        self._exec("update scans set finished_at = %s, error = %s where id = %s",
                   (now, error, scan_id))
        self.conn.commit()

    def upsert_findings(self, repo_id: int, scan_id: int,
                        findings: list[Finding], now: dt.datetime) -> None:
        for f in findings:
            self._exec(
                """insert into findings
                     (repo_id, rule_id, severity, fingerprint, evidence, status,
                      first_seen_scan_id, last_seen_scan_id, opened_at)
                   values (%s,%s,%s,%s,%s,'open',%s,%s,%s)
                   on conflict (repo_id, fingerprint) do update set
                     last_seen_scan_id = excluded.last_seen_scan_id,
                     evidence = excluded.evidence
                   where findings.status not in ('accepted_risk','false_positive','fixed')""",
                (repo_id, f.rule_id, f.severity, f.fingerprint, Jsonb(f.evidence),
                 scan_id, scan_id, now))
        self.conn.commit()

    def close_absent_findings(self, repo_id: int, present: set[str],
                              now: dt.datetime) -> int:
        n = self._exec(
            """update findings set status = 'fixed', closed_at = %s
               where repo_id = %s
                 and status in ('open','fix_pr_open','needs_decision')
                 and not (fingerprint = any(%s))""",
            (now, repo_id, list(present)))
        self.conn.commit()
        return n

    def open_findings(self, repo_id: int,
                      statuses: tuple[str, ...] = ("open", "needs_decision")) -> list[FindingRow]:
        rows = self._all(
            "select * from findings where repo_id = %s and status = any(%s) order by id",
            (repo_id, list(statuses)))
        return [_row(FindingRow, r) for r in rows]

    def set_finding_status(self, finding_id: int, status: str, now: dt.datetime) -> None:
        close = status in ("fixed", "accepted_risk", "false_positive")
        self._exec(
            "update findings set status = %s, closed_at = case when %s then %s else closed_at end"
            " where id = %s",
            (status, close, now, finding_id))
        self.conn.commit()

    def find_finding(self, repo_id: int, fingerprint: str) -> FindingRow | None:
        row = self._one("select * from findings where repo_id = %s and fingerprint = %s",
                        (repo_id, fingerprint))
        return _row(FindingRow, row) if row else None

    # -- outbound ------------------------------------------------------------

    def repo_has_open_fix_pr(self, repo_id: int) -> bool:
        row = self._one(
            "select 1 as x from outbound where repo_id = %s and kind = 'fix_pr' and state = 'open'",
            (repo_id,))
        return row is not None

    def finding_has_outbound(self, finding_id: int) -> bool:
        row = self._one("select 1 as x from outbound where finding_id = %s",
                        (finding_id,))
        return row is not None

    def outbound_today(self, repo_id: int, day: dt.date) -> int:
        row = self._one(
            """select count(*) as c from outbound
               where repo_id = %s and created_at >= %s and created_at < %s + interval '1 day'""",
            (repo_id, day, day))
        return int(row["c"]) if row else 0

    def record_outbound(self, repo_id: int, finding_id: int | None, kind: str,
                        gh_number: int | None, state: str, now: dt.datetime) -> int:
        row = self._one(
            """insert into outbound (repo_id, finding_id, kind, gh_number, state, created_at)
               values (%s,%s,%s,%s,%s,%s) returning id""",
            (repo_id, finding_id, kind, gh_number, state, now))
        self.conn.commit()
        if row is None:  # pragma: no cover - returning clause always yields a row
            raise RuntimeError("insert returned no id")
        return int(row["id"])

    def list_open_outbound(self) -> list[OutboundRow]:
        return [_row(OutboundRow, r)
                for r in self._all("select * from outbound where state = 'open'")]

    def update_outbound_state(self, outbound_id: int, state: str, now: dt.datetime,
                              merged: bool = False) -> None:
        self._exec(
            """update outbound set state = %s,
                 merged_at = case when %s then %s else merged_at end,
                 closed_at = case when %s then %s else closed_at end
               where id = %s""",
            (state, merged, now, state in ("closed", "merged"), now, outbound_id))
        self.conn.commit()

    def set_cooldown(self, repo_id: int, until: dt.datetime) -> None:
        self._exec("update repos set cooldown_until = %s where id = %s", (until, repo_id))
        self.conn.commit()

    def comment_seen(self, comment_id: int) -> bool:
        return self._one("select 1 as x from seen_comments where comment_id = %s",
                         (comment_id,)) is not None

    def mark_comment_seen(self, comment_id: int) -> None:
        self._exec("insert into seen_comments (comment_id) values (%s) on conflict do nothing",
                   (comment_id,))
        self.conn.commit()

    def finding_for_outbound(self, outbound_id: int) -> FindingRow | None:
        row = self._one(
            """select f.* from findings f join outbound o on o.finding_id = f.id
               where o.id = %s""", (outbound_id,))
        return _row(FindingRow, row) if row else None

    def write_tick_run(self, started: dt.datetime, finished: dt.datetime,
                       stats: TickStats) -> None:
        self._exec(
            """insert into tick_runs
                 (started_at, finished_at, repos_checked, scans, prs_opened, errors)
               values (%s,%s,%s,%s,%s,%s)""",
            (started, finished, stats.repos_checked, stats.scans, stats.prs_opened, stats.errors))
        self.conn.commit()

    def delete_stale_removed_findings(self, before: dt.datetime) -> int:
        n = self._exec(
            """delete from findings where closed_at is not null and closed_at < %s
               and repo_id in (select id from repos where status = 'removed')""",
            (before,))
        self.conn.commit()
        return n

    def scoreboard(self) -> list[dict[str, Any]]:
        return self._all("select * from weekly_scoreboard order by week desc")

    def close(self) -> None:
        self.conn.close()
