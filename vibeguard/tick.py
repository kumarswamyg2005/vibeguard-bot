"""The 15-minute tick. All decisions live here; every I/O goes through the
injected Store / Gh / prober / gate seams so the whole flow is testable.

Order (spec §Interfaces):
  1. sync installations + repos, mark removed
  2. scan repos whose default-branch HEAD changed
  3. apply /vibeguard commands from new comments
  4. refresh outbound states, set cooldowns
  5. emit at most the rate-limited number of outbound items
  6. write tick_runs, one public-safe log line
"""

from __future__ import annotations

import datetime as dt
import tempfile
from collections import Counter
from pathlib import Path
from typing import Protocol

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from vibeguard import fixer
from vibeguard.db.store import FindingRow, RepoRow, Store, TickStats
from vibeguard.fixer.gate import PgTapRunner, review
from vibeguard.gh.client import PrState, RateLimitedError, RepoComment
from vibeguard.logging_config import public_log
from vibeguard.policy import (
    CLOSED_PR_COOLDOWN_DAYS,
    MAX_OUTBOUND_PER_REPO_PER_DAY,
    PROBE_MAX_TABLES,
    REMOVED_FINDINGS_RETENTION_DAYS,
)
from vibeguard.scanner.model import Finding
from vibeguard.scanner.probe import ProbeRefusedError, probe
from vibeguard.scanner.rules import probe_findings, scan_repo

SCANNER_VERSION = "0.1.0"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}
COMMAND_ACCEPT = "/vibeguard accept"
COMMAND_FP = "/vibeguard false-positive"


class RepoOps(Protocol):
    full_name: str

    def head_sha(self, branch: str | None = None) -> str: ...
    def clone(self, dest: Path) -> None: ...
    def comments_since(self, since: dt.datetime) -> list[RepoComment]: ...
    def pr_state(self, number: int) -> PrState: ...
    def issue_state(self, number: int) -> str: ...
    def create_check_run(self, sha: str, title: str, summary: str) -> None: ...
    def push_files(self, branch: str, files: dict[str, str], message: str,
                   base_branch: str | None = None,
                   deletes: list[str] | None = None) -> None: ...
    def open_pr(self, title: str, body: str, head: str,
                base: str | None = None) -> int: ...
    def open_issue(self, title: str, body: str) -> int: ...
    def comment(self, number: int, body: str) -> None: ...


class GhOps(Protocol):
    def list_installations(self) -> list[dict]: ...
    def repo(self, full_name: str, installation_id: int) -> RepoOps: ...


Prober = type(probe)


def _jinja() -> Environment:
    # PR bodies are markdown, not HTML — autoescape does not apply (S701).
    return Environment(  # noqa: S701
        loader=FileSystemLoader(Path(__file__).parent.parent / "templates"),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def run_tick(
    store: Store,
    gh: GhOps,
    *,
    now: dt.datetime | None = None,
    prober=probe,
    gate_runner: PgTapRunner | None = None,
    comments_lookback: dt.timedelta = dt.timedelta(hours=26),
    logger=None,
) -> TickStats:
    started = now or dt.datetime.now(dt.UTC)
    stats = TickStats()

    try:
        store.sync_installations(gh.list_installations(), started)
    except RateLimitedError:
        store.write_tick_run(started, started, TickStats(errors=1))
        return TickStats(errors=1)

    repos = store.list_active_repos()
    stats.repos_checked = len(repos)
    scanned_dirs: dict[int, Path] = {}
    scan_results: dict[int, list[Finding]] = {}
    tmp = tempfile.TemporaryDirectory(prefix="vibeguard-tick-")

    # -- 2. scan changed repos ------------------------------------------------
    for repo in repos:
        try:
            ops = gh.repo(repo.full_name, repo.installation_id)
            sha = ops.head_sha()
            if sha == repo.last_scanned_sha:
                continue
            dest = Path(tmp.name) / str(repo.id)
            ops.clone(dest)
            result = scan_repo(dest)
            findings = list(result.findings)

            scan_id = store.create_scan(
                repo.id, sha,
                "install" if repo.last_scanned_sha is None else "change",
                SCANNER_VERSION, started)
            # live proof (VG003)
            if result.signals.live_probe and result.signals.supabase_url \
                    and result.signals.anon_key_values:
                try:
                    counts = prober(
                        result.signals.supabase_url,
                        result.signals.anon_key_values[0],
                        result.signals.table_names[:PROBE_MAX_TABLES],
                        live_probe=True,
                    )
                    provable = [(t, c) for t, c in counts.items() if c]
                    findings += probe_findings(provable)
                except ProbeRefusedError:
                    pass
            store.upsert_findings(repo.id, scan_id, findings, started)
            store.close_absent_findings(
                repo.id, {f.fingerprint for f in findings}, started)
            store.finish_scan(scan_id, started)
            store.update_repo_scan(
                repo.id, sha,
                supabase_url=result.signals.supabase_url,
                live_probe=result.signals.live_probe,
                public_on_scoreboard=result.signals.public_on_scoreboard)
            crit = sum(1 for f in findings if f.severity == "critical")
            ops.create_check_run(sha, f"VibeGuard: {crit} critical",
                                 f"{len(findings)} finding(s), {crit} critical.")
            scanned_dirs[repo.id] = dest
            scan_results[repo.id] = findings
            stats.scans += 1
        except RateLimitedError:
            stats.errors += 1
            break
        except Exception:  # noqa: BLE001 - one repo must not kill the tick
            stats.errors += 1

    # -- 3. /vibeguard commands ------------------------------------------------
    since = started - comments_lookback
    for repo in store.list_active_repos():
        try:
            ops = gh.repo(repo.full_name, repo.installation_id)
            for c in ops.comments_since(since):
                if store.comment_seen(c.comment_id):
                    continue
                store.mark_comment_seen(c.comment_id)
                body = c.body.strip().lower()
                if body.startswith(COMMAND_ACCEPT):
                    _apply_verdict(store, repo, c.gh_number, "accepted_risk", started)
                elif body.startswith(COMMAND_FP):
                    _apply_verdict(store, repo, c.gh_number, "false_positive", started)
        except RateLimitedError:
            stats.errors += 1
            break
        except Exception:  # noqa: BLE001
            stats.errors += 1

    # -- 4. outbound states + cooldowns ----------------------------------------
    for o in store.list_open_outbound():
        try:
            repo = store.get_repo(o.repo_id)
            if repo is None or repo.status != "active":
                continue
            ops = gh.repo(repo.full_name, repo.installation_id)
            if o.gh_number is None:
                continue
            if o.kind in ("onboarding_pr", "fix_pr"):
                st = ops.pr_state(o.gh_number)
                if st.merged:
                    store.update_outbound_state(o.id, "merged", started, merged=True)
                elif st.state == "closed":
                    store.update_outbound_state(o.id, "closed", started)
                    store.set_cooldown(
                        repo.id, started + dt.timedelta(days=CLOSED_PR_COOLDOWN_DAYS))
                    f = store.finding_for_outbound(o.id)
                    if f is not None:
                        store.set_finding_status(f.id, "open", started)
            elif (o.kind == "decision_issue"
                  and ops.issue_state(o.gh_number) == "closed"):
                store.update_outbound_state(o.id, "closed", started)
        except RateLimitedError:
            stats.errors += 1
            break
        except Exception:  # noqa: BLE001
            stats.errors += 1

    # -- 5. emit ----------------------------------------------------------------
    env = _jinja()
    for repo in store.list_active_repos():
        try:
            stats.prs_opened += _emit_for_repo(
                store, gh, repo, scanned_dirs.get(repo.id),
                gate_runner, env, started)
        except RateLimitedError:
            stats.errors += 1
            break
        except Exception:  # noqa: BLE001
            stats.errors += 1

    # -- 6. wrap up --------------------------------------------------------------
    cutoff = started - dt.timedelta(days=REMOVED_FINDINGS_RETENTION_DAYS)
    stats.extra["deleted"] = store.delete_stale_removed_findings(cutoff)
    finished = dt.datetime.now(dt.UTC)
    store.write_tick_run(started, finished, stats)
    if logger is not None:
        public_log(logger, tick=1, repos=stats.repos_checked, scans=stats.scans,
                   prs=stats.prs_opened, errors=stats.errors,
                   secs=int((finished - started).total_seconds()))
    tmp.cleanup()
    return stats


def _apply_verdict(store: Store, repo: RepoRow, gh_number: int,
                   verdict: str, now: dt.datetime) -> None:
    ob = _outbound_for(store, repo.id, gh_number)
    if ob is None or ob.finding_id is None:
        return
    f = store.finding_for_outbound(ob.id)
    if f is not None:
        store.set_finding_status(f.id, verdict, now)


def _outbound_for(store: Store, repo_id: int, gh_number: int):
    for o in store.list_open_outbound():
        if o.repo_id == repo_id and o.gh_number == gh_number:
            return o
    return None


def _in_cooldown(repo: RepoRow, now: dt.datetime) -> bool:
    return repo.cooldown_until is not None and repo.cooldown_until > now


def _emit_for_repo(store: Store, gh: GhOps, repo: RepoRow,
                   repo_dir: Path | None, runner: PgTapRunner | None,
                   env: Environment, now: dt.datetime) -> int:
    opened = 0
    ops = gh.repo(repo.full_name, repo.installation_id)
    open_fs = store.open_findings(repo.id)
    counts = Counter(f.severity for f in store.open_findings(
        repo.id, ("open", "fix_pr_open", "needs_decision")))

    budget = MAX_OUTBOUND_PER_REPO_PER_DAY - store.outbound_today(repo.id, now.date())

    # onboarding first
    if repo.onboarded_at is None and not _has_open_kind(store, repo.id, "onboarding_pr"):
        if budget <= 0:
            return 0
        body = env.get_template("onboarding_pr.md.j2").render(
            counts=dict(counts))
        ops.push_files(
            "vibeguard/onboarding",
            {".vibeguard.yml": ("# VibeGuard settings\nlive_probe: false\n"
                               "public_on_scoreboard: false\n")},
            "chore: add .vibeguard.yml")
        n = ops.open_pr("VibeGuard: security checks for this repo", body,
                        "vibeguard/onboarding", repo.default_branch)
        store.record_outbound(repo.id, None, "onboarding_pr", n, "open", now)
        store.mark_onboarded(repo.id, now)
        opened += 1
        budget -= 1

    if repo.onboarded_at is None or budget <= 0:
        return opened

    open_findings = sorted(open_fs,
                           key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    in_cooldown = _in_cooldown(repo, now)
    has_new_critical = any(
        f.severity == "critical" and not _has_outbound(store, f.id)
        for f in open_findings)
    if in_cooldown and not has_new_critical:
        return 0

    for f in open_findings:
        if budget <= 0:
            break
        if f.severity == "info":
            continue
        if _has_outbound(store, f.id):
            continue
        if f.status == "needs_decision":
            continue
        fix = _build_fix(f, repo_dir, now)
        if fix is None:
            if _open_decision_issue(store, ops, env, repo, f, now):
                opened += 1
                budget -= 1
            continue
        if store.repo_has_open_fix_pr(repo.id):
            continue  # max 1 open fix PR per repo (invariant 12)
        files_list = list(fix.files) + [f"- removed: {p}" for p in fix.deleted_paths]
        body = env.get_template("pr_body.md.j2").render(
            impact=_impact_line(f),
            proof_curl=_proof_curl(f, repo),
            files=files_list,
            rotate=f.rule_id in ("VG001", "VG008"),
        )
        allowed = {str(f.evidence.get("file"))}
        gate = review(fix.files, fix.deleted_paths, allowed, body, runner)
        if not gate.ok:
            store.set_finding_status(f.id, "needs_decision", now)
            continue
        branch = f"vibeguard/fix-{f.fingerprint[:8]}"
        ops.push_files(branch, fix.files, f"vibeguard: {fix.title}",
                       base_branch=repo.default_branch, deletes=fix.deleted_paths)
        n = ops.open_pr(fix.title, body, branch, repo.default_branch)
        store.record_outbound(repo.id, f.id, "fix_pr", n, "open", now)
        store.set_finding_status(f.id, "fix_pr_open", now)
        opened += 1
        budget -= 1
    return opened


def _has_open_kind(store: Store, repo_id: int, kind: str) -> bool:
    return any(o.repo_id == repo_id and o.kind == kind and o.state == "open"
               for o in store.list_open_outbound())


def _has_outbound(store: Store, finding_id: int) -> bool:
    return store.finding_has_outbound(finding_id)


def _open_decision_issue(store: Store, ops: RepoOps, env: Environment,
                         repo: RepoRow, f: FindingRow, now: dt.datetime) -> bool:
    body = env.get_template("decision_issue.md.j2").render(
        impact=_impact_line(f), table=f.evidence.get("table", "the table"))
    n = ops.open_issue(f"VibeGuard decision needed: {f.rule_id}", body)
    store.record_outbound(repo.id, f.id, "decision_issue", n, "open", now)
    store.set_finding_status(f.id, "needs_decision", now)
    return True


def _build_fix(f: FindingRow, repo_dir: Path | None, now: dt.datetime) -> fixer.Fix | None:
    if repo_dir is None:
        return None
    ts = now.strftime("%Y%m%d%H%M%S")
    owner_col = f.evidence.get("owner_col")
    if f.rule_id in ("VG002", "VG003"):
        if not owner_col:
            return None
        return fixer.rls_fix(str(f.evidence["table"]), str(owner_col), ts)
    if f.rule_id == "VG004":
        path = str(f.evidence.get("file", ""))
        if not owner_col or not path:
            return None
        fp = repo_dir / path
        if not fp.exists():
            return None
        return fixer.policy_fix(fp.read_text(errors="replace"), dict(f.evidence),
                                str(owner_col))
    if f.rule_id == "VG001":
        path = str(f.evidence.get("file", ""))
        fp = repo_dir / path
        if not fp.exists():
            return None
        return fixer.secret_fix(f, fp.read_text(errors="replace"), "")
    if f.rule_id == "VG008":
        path = str(f.evidence.get("file", ""))
        gi = repo_dir / ".gitignore"
        return fixer.env_fix(path, gi.read_text() if gi.exists() else None)
    return None


def _impact_line(f: FindingRow) -> str:
    table = f.evidence.get("table")
    match f.rule_id:
        case "VG002":
            return (f"Anyone on the internet can read and write every row in "
                    f"`{table}` right now.")
        case "VG003":
            n = f.evidence.get("row_count", "?")
            return (f"Anyone on the internet can read `{table}` — "
                    f"we counted {n} rows without logging in.")
        case "VG001":
            return ("A secret Supabase key is shipped to every visitor's browser; "
                    "anyone can use it to bypass all row-level security.")
        case "VG004":
            return f"Anyone can modify rows in `{table}` without logging in."
        case "VG008":
            return f"`{f.evidence.get('file')}` is committed to git and contains a Supabase key."
        case _:
            return "A security-relevant misconfiguration was found."


def _proof_curl(f: FindingRow, repo: RepoRow) -> str | None:
    if f.rule_id not in ("VG002", "VG003") or not repo.supabase_url:
        return None
    table = f.evidence.get("table", "TABLE")
    return (
        f'curl -sI "{repo.supabase_url}/rest/v1/{table}?select=*" \\\n'
        f'  -H "apikey: <your anon key>" \\\n'
        f'  -H "Prefer: count=exact" -H "Range: 0-0" | grep -i content-range'
    )


def main() -> None:  # pragma: no cover - exercised by the Actions workflow
    import base64
    import os

    from vibeguard.db.sql import SqlStore
    from vibeguard.fixer.gate import SupabaseCliRunner
    from vibeguard.gh.app import AppAuth
    from vibeguard.gh.client import Gh
    from vibeguard.logging_config import configure_logging

    logger = configure_logging()
    required = ("GH_APP_ID", "GH_APP_PRIVATE_KEY", "SUPABASE_DB_URL")
    if any(not os.environ.get(k) for k in required):
        public_log(logger, tick=1, skipped=1, reason="no_credentials")
        return
    pem = os.environ["GH_APP_PRIVATE_KEY"]
    if "BEGIN" not in pem:
        pem = base64.b64decode(pem).decode()
    auth = AppAuth(os.environ["GH_APP_ID"], pem)
    store = SqlStore.connect(os.environ["SUPABASE_DB_URL"])
    try:
        stats = run_tick(store, Gh(auth), logger=logger,
                         gate_runner=SupabaseCliRunner())
        raise SystemExit(0 if stats.errors == 0 else 1)
    finally:
        store.close()
        auth.close()


if __name__ == "__main__":
    main()
