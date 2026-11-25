from __future__ import annotations

import datetime as dt
from pathlib import Path

from tests.fake_gh import FakeGh
from vibeguard.db.fake import FakeStore
from vibeguard.tick import run_tick

FIXTURES = Path(__file__).parent / "fixtures"
NOW = dt.datetime(2026, 11, 25, 12, 0, 0, tzinfo=dt.UTC)
NO_PROBE = lambda *a, **k: {}  # noqa: E731


class PassGate:
    def run(self, m: str, t: str) -> bool:
        return True


class FailGate:
    def run(self, m: str, t: str) -> bool:
        return False


def make_gh(repos: list[dict]) -> FakeGh:
    return FakeGh([{"gh_installation_id": 1, "account_login": "owner-login",
                    "repos": repos}])


def lovable_repo(**over):
    r = {"gh_repo_id": 11, "full_name": "owner/vulnerable-lovable",
         "default_branch": "main", "sha": "sha1", "fixture": FIXTURES / "lovable_app"}
    r.update(over)
    return r


def test_first_tick_onboards_and_fixes():
    store = FakeStore()
    gh = make_gh([lovable_repo()])
    stats = run_tick(store, gh, now=NOW, gate_runner=PassGate(), prober=NO_PROBE)
    assert stats.errors == 0
    # onboarding PR + fix PR for fixable VG002
    kinds = [o.kind for o in store.outbound.values()]
    assert "onboarding_pr" in kinds
    assert stats.prs_opened >= 1


def test_second_tick_opens_nothing():
    store = FakeStore()
    gh = make_gh([lovable_repo()])
    run_tick(store, gh, now=NOW, gate_runner=PassGate(), prober=NO_PROBE)
    n_outbound = len(store.outbound)
    stats2 = run_tick(store, gh, now=NOW + dt.timedelta(minutes=15),
                      gate_runner=PassGate(), prober=NO_PROBE)
    assert len(store.outbound) == n_outbound
    assert stats2.scans == 0  # HEAD unchanged → no rescan


def test_decision_issue_when_no_owner_col():
    store = FakeStore()
    gh = make_gh([{"gh_repo_id": 12, "full_name": "owner/bolt-app",
                   "default_branch": "main", "sha": "s1",
                   "fixture": FIXTURES / "bolt_app"}])
    run_tick(store, gh, now=NOW, gate_runner=PassGate(), prober=NO_PROBE)
    kinds = [o.kind for o in store.outbound.values()]
    assert "decision_issue" in kinds
    # VG002 on orders is not fixable → never a fix PR for it
    for o in store.outbound.values():
        if o.kind == "fix_pr":
            f = store.findings[o.finding_id]
            assert f.evidence.get("table") != "orders"


def test_gate_failure_becomes_needs_decision():
    store = FakeStore()
    gh = make_gh([lovable_repo()])
    run_tick(store, gh, now=NOW, gate_runner=FailGate(), prober=NO_PROBE)
    # the migration-type fix (VG002) must not ship when pgTAP fails;
    # non-migration fixes (VG008 env file) have no pgTAP to fail
    for o in store.outbound.values():
        if o.kind == "fix_pr" and o.finding_id:
            assert store.findings[o.finding_id].rule_id != "VG002"
    nd = [f for f in store.findings.values()
          if f.status == "needs_decision" and f.rule_id == "VG002"]
    assert nd


def test_max_one_open_fix_pr():
    store = FakeStore()
    gh = make_gh([lovable_repo()])
    run_tick(store, gh, now=NOW, gate_runner=PassGate(), prober=NO_PROBE)
    open_fixes = [o for o in store.outbound.values()
                  if o.kind == "fix_pr" and o.state == "open"]
    assert len(open_fixes) <= 1


def test_uninstalled_repo_gets_zero_calls():
    store = FakeStore()
    gh = make_gh([lovable_repo()])
    run_tick(store, gh, now=NOW, gate_runner=PassGate(), prober=NO_PROBE)
    # owner uninstalls
    gh.installations = []
    run_tick(store, gh, now=NOW + dt.timedelta(minutes=15), gate_runner=PassGate(), prober=NO_PROBE)
    repo = next(iter(store.repos.values()))
    assert repo.status == "removed"
    calls_after = gh.repo_dict("owner/vulnerable-lovable").get("api_calls", [])
    # second tick made no calls on the removed repo
    assert calls_after.count("head_sha") == 1


def test_cooldown_after_unmerged_close():
    store = FakeStore()
    gh = make_gh([lovable_repo()])
    run_tick(store, gh, now=NOW, gate_runner=PassGate(), prober=NO_PROBE)
    repo_dict = gh.repo_dict("owner/vulnerable-lovable")
    for n in repo_dict.get("prs", {}):
        repo_dict["prs"][n]["state"] = "closed"  # owner closed unmerged
    later = NOW + dt.timedelta(hours=1)
    run_tick(store, gh, now=later, gate_runner=PassGate(), prober=NO_PROBE)
    repo = next(iter(store.repos.values()))
    assert repo.cooldown_until and repo.cooldown_until > later
    # a fix-pr emit inside cooldown does not open new ones (no new critical)
    repo_dict["sha"] = "sha2"  # new push → rescan happens
    run_tick(store, gh, now=later + dt.timedelta(minutes=15),
             gate_runner=PassGate(), prober=NO_PROBE)
    new_fix = [o for o in store.outbound.values()
               if o.kind == "fix_pr" and o.state == "open" and o.created_at > later]
    assert new_fix == []


def test_accept_command_marks_finding():
    store = FakeStore()
    gh = make_gh([lovable_repo()])
    run_tick(store, gh, now=NOW, gate_runner=PassGate(), prober=NO_PROBE)
    repo_dict = gh.repo_dict("owner/vulnerable-lovable")
    # find a decision issue if any, else use fix PR number
    ob = next(o for o in store.outbound.values() if o.gh_number)
    repo_dict.setdefault("comments", []).append(
        {"comment_id": 555, "gh_number": ob.gh_number, "body": "/vibeguard accept"})
    run_tick(store, gh, now=NOW + dt.timedelta(minutes=15), gate_runner=PassGate(), prober=NO_PROBE)
    if ob.finding_id:
        assert store.findings[ob.finding_id].status == "accepted_risk"


def test_check_run_posted_on_scan():
    store = FakeStore()
    gh = make_gh([lovable_repo()])
    run_tick(store, gh, now=NOW, gate_runner=PassGate(), prober=NO_PROBE)
    checks = gh.repo_dict("owner/vulnerable-lovable").get("check_runs", [])
    assert any("critical" in c for c in checks)


def test_new_push_triggers_rescan_and_fix_closure():
    store = FakeStore()
    gh = make_gh([lovable_repo()])
    run_tick(store, gh, now=NOW, gate_runner=PassGate(), prober=NO_PROBE)
    repo_dict = gh.repo_dict("owner/vulnerable-lovable")
    # owner merges fix & pushes — repo now secure
    repo_dict["fixture"] = FIXTURES / "nextjs_app"
    repo_dict["sha"] = "sha2"
    for n in repo_dict.get("prs", {}):
        repo_dict["prs"][n]["merged"] = True
    run_tick(store, gh, now=NOW + dt.timedelta(minutes=30), gate_runner=PassGate(), prober=NO_PROBE)
    vg002 = [f for f in store.findings.values() if f.rule_id == "VG002"]
    assert vg002 and all(f.status == "fixed" for f in vg002)


def test_secure_repo_no_fix_prs():
    store = FakeStore()
    gh = make_gh([{"gh_repo_id": 13, "full_name": "owner/secure",
                   "default_branch": "main", "sha": "s1",
                   "fixture": FIXTURES / "nextjs_app"}])
    run_tick(store, gh, now=NOW, gate_runner=PassGate(), prober=NO_PROBE)
    assert not any(o.kind == "fix_pr" for o in store.outbound.values())
