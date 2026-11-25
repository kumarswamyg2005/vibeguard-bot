"""Self-review gate (invariant 11). No fix PR leaves without:

(a) its generated migration passing its generated pgTAP test on an ephemeral
    `supabase start` database (skipped when the fix has no migration),
(b) the diff-scope check (invariant 8): only new files or flagged lines,
(c) the copy lint: no secret and no row data in the PR body.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from vibeguard.logging_config import SECRET_PATTERNS

MIGRATION_RE = re.compile(r"^supabase/migrations/\d+_vibeguard_.*\.sql$")
TEST_RE = re.compile(r"^supabase/tests/vibeguard_.*\.test\.sql$")


@dataclass
class GateResult:
    ok: bool
    reasons: list[str] = field(default_factory=list)


class PgTapRunner(Protocol):
    def run(self, migration_sql: str, test_sql: str) -> bool: ...


_SUPABASE = shutil.which("supabase") or "supabase"  # noqa: S607


class SupabaseCliRunner:
    """Applies a migration + pgTAP test on a throwaway local Supabase stack."""

    def run(self, migration_sql: str, test_sql: str) -> bool:
        with tempfile.TemporaryDirectory(prefix="vibeguard-gate-") as td:
            root = Path(td)
            subprocess.run([_SUPABASE, "init"], cwd=root, check=True,  # noqa: S603
                           capture_output=True)
            mig = root / "supabase" / "migrations" / "20990101000000_vibeguard_gate.sql"
            mig.write_text(migration_sql)
            tdir = root / "supabase" / "tests"
            tdir.mkdir(parents=True, exist_ok=True)
            (tdir / "gate.test.sql").write_text(test_sql)
            try:
                subprocess.run([_SUPABASE, "start"], cwd=root, check=True,  # noqa: S603
                               capture_output=True, timeout=600)
                r = subprocess.run([_SUPABASE, "test", "db"], cwd=root,  # noqa: S603
                                   capture_output=True, timeout=300)
                return r.returncode == 0
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                return False
            finally:
                subprocess.run([_SUPABASE, "stop", "--no-backup"], cwd=root,  # noqa: S603
                               capture_output=True, timeout=120)


def check_diff_scope(files: dict[str, str], deleted: list[str],
                     allowed_edit_paths: set[str]) -> list[str]:
    """Invariant 8: PR may add new files or edit flagged paths only."""
    problems: list[str] = []
    for path in files:
        if MIGRATION_RE.match(path) or TEST_RE.match(path):
            continue
        if path == ".gitignore" or path.startswith("supabase/functions/"):
            continue
        if path not in allowed_edit_paths:
            problems.append("file outside allowed scope")
    for path in deleted:
        # deletions are only ever the flagged committed env file
        if not Path(path).name.startswith(".env"):
            problems.append("deletion outside allowed scope")
    return problems


def check_copy(text: str) -> list[str]:
    """No secret-shaped strings and no row data in outbound text."""
    problems = []
    for pat in SECRET_PATTERNS:
        if pat.search(text):
            problems.append("secret-shaped content in copy")
            break
    if re.search(r"\bVALUES\s*\(", text, re.I) and re.search(r"\('[^']*@[^']*'", text):
        problems.append("possible row data in copy")
    return problems


def review(fix_files: dict[str, str], deleted: list[str],
           allowed_edit_paths: set[str], pr_body: str,
           runner: PgTapRunner | None) -> GateResult:
    reasons: list[str] = []
    reasons += check_diff_scope(fix_files, deleted, allowed_edit_paths)
    reasons += check_copy(pr_body)

    migrations = {p: c for p, c in fix_files.items() if MIGRATION_RE.match(p)}
    tests = {p: c for p, c in fix_files.items() if TEST_RE.match(p)}
    if migrations:
        if not tests:
            reasons.append("migration without pgTAP test")
        elif runner is not None:
            mig_sql = next(iter(migrations.values()))
            test_sql = next(iter(tests.values()))
            try:
                if not runner.run(mig_sql, test_sql):
                    reasons.append("pgTAP failed on ephemeral database")
            except Exception:  # noqa: BLE001 - gate failure => no PR
                reasons.append("pgTAP runner error")
    return GateResult(ok=not reasons, reasons=reasons)
