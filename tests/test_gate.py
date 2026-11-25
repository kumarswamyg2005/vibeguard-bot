from __future__ import annotations

import datetime as dt

from vibeguard import fixer
from vibeguard.fixer.gate import check_copy, check_diff_scope, review

NOW = dt.datetime(2026, 11, 25)


def test_rls_fix_generates_migration_and_test():
    fix = fixer.rls_fix("posts", "user_id", "20261125120000")
    assert fix is not None
    (mig_path, mig), (test_path, test) = fix.files.items()
    assert mig_path.startswith("supabase/migrations/20261125120000_vibeguard_rls_posts")
    assert "enable row level security" in mig
    assert "user_id" in mig
    assert test_path.startswith("supabase/tests/vibeguard_posts")
    assert "anon sees 0 rows" in test


def test_rls_fix_only_new_files():
    fix = fixer.rls_fix("posts", "user_id", "20261125120000")
    problems = check_diff_scope(fix.files, fix.deleted_paths, set())
    assert problems == []


def test_policy_fix_edits_flagged_line_only():
    content = 'create policy "x" on public.t\n  for update to public using (true);\n'
    fix = fixer.policy_fix(content, {"file": "supabase/migrations/001.sql", "line": 2,
                                     "table": "t"}, "user_id")
    assert fix is not None
    assert "auth.uid()) = user_id" in fix.files["supabase/migrations/001.sql"]
    assert "create policy" in fix.files["supabase/migrations/001.sql"]


def test_env_fix_deletes_and_ignores():
    fix = fixer.env_fix(".env.local", "node_modules\n")
    assert fix.deleted_paths == [".env.local"]
    assert ".env*" in fix.files[".gitignore"]


def test_copy_lint_catches_secret():
    assert check_copy("key: eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.sig")
    assert check_copy("use sb_secret_abcdefghijk")
    assert check_copy("postgres://user:pass@db.x.supabase.co/x")
    assert check_copy("clean body text") == []


def test_diff_scope_rejects_stray_file():
    problems = check_diff_scope({"src/random.ts": "x"}, [], {"src/flagged.ts"})
    assert problems


def test_gate_no_pr_when_pgtap_fails():
    class Fail:
        def run(self, m: str, t: str) -> bool:
            return False

    fix = fixer.rls_fix("t", "user_id", "20261125120000")
    res = review(fix.files, fix.deleted_paths, set(), "body", Fail())
    assert not res.ok
    assert any("pgTAP" in r for r in res.reasons)


def test_gate_passes_with_good_fix():
    class Ok:
        def run(self, m: str, t: str) -> bool:
            return True

    fix = fixer.rls_fix("t", "user_id", "20261125120000")
    res = review(fix.files, fix.deleted_paths, set(), "clean", Ok())
    assert res.ok


def test_gate_without_runner_skips_pgtap():
    fix = fixer.rls_fix("t", "user_id", "20261125120000")
    res = review(fix.files, fix.deleted_paths, set(), "clean", None)
    assert res.ok
