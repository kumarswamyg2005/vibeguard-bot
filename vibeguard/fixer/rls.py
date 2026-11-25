"""Deterministic fix generators. Invariant 8: one finding = one PR, files are
new or the exact flagged lines. Invariant 9: no owner column -> no PR at all
(the caller emits a decision issue instead)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from vibeguard.db.store import FindingRow


@dataclass
class Fix:
    files: dict[str, str]          # path -> full new content (new files) or edited content
    deleted_paths: list[str]       # paths to remove from the tree (e.g. committed .env)
    title: str
    summary: str


def rls_fix(table: str, owner_col: str, ts: str) -> Fix | None:
    """VG002/VG003: enable RLS + owner policies + pgTAP proof test."""
    safe = re.sub(r"[^a-zA-Z0-9_]", "_", table)
    migration = f"""-- VibeGuard fix: enable RLS on public.{safe}
alter table public.{safe} enable row level security;

create policy "{safe}_select_own" on public.{safe}
  for select to authenticated
  using ((select auth.uid()) = {owner_col});

create policy "{safe}_insert_own" on public.{safe}
  for insert to authenticated
  with check ((select auth.uid()) = {owner_col});

create policy "{safe}_update_own" on public.{safe}
  for update to authenticated
  using ((select auth.uid()) = {owner_col})
  with check ((select auth.uid()) = {owner_col});

create policy "{safe}_delete_own" on public.{safe}
  for delete to authenticated
  using ((select auth.uid()) = {owner_col});
"""
    test = f"""begin;
select plan(3);

-- anon sees 0 rows
set role anon;
select is(
  (select count(*)::int from public.{safe}),
  0, 'anon sees 0 rows on {safe}');

reset role;

-- user A cannot read or update user B's row; user A reads own row
insert into auth.users (id, email) values
  ('11111111-1111-1111-1111-111111111111', 'a@test.local'),
  ('22222222-2222-2222-2222-222222222222', 'b@test.local')
on conflict do nothing;

insert into public.{safe} ({owner_col}) values
  ('22222222-2222-2222-2222-222222222222'),
  ('11111111-1111-1111-1111-111111111111')
on conflict do nothing;

set role authenticated;
set request.jwt.claims to '{{"sub":"11111111-1111-1111-1111-111111111111","role":"authenticated"}}';

select is(
  (select count(*)::int from public.{safe}),
  1, 'user A sees only own rows');

update public.{safe} set {owner_col} = '11111111-1111-1111-1111-111111111111'
where {owner_col} = '22222222-2222-2222-2222-222222222222';
reset role;
select is(
  (select count(*)::int from public.{safe}
    where {owner_col} = '22222222-2222-2222-2222-222222222222'),
  1, 'user A cannot update user B row');

select * from finish();
rollback;
"""  # noqa: S608 - generated SQL; owner_col comes from validated schema catalog
    return Fix(
        files={
            f"supabase/migrations/{ts}_vibeguard_rls_{safe}.sql": migration,
            f"supabase/tests/vibeguard_{safe}.test.sql": test,
        },
        deleted_paths=[],
        title=f"Enable Row Level Security on {table}",
        summary=f"public.{table} was readable/writable by anyone. This adds RLS "
                f"policies keyed on {owner_col} plus a test that proves anon sees nothing.",
    )


def policy_fix(file_content: str, evidence: dict[str, object], owner_col: str) -> Fix | None:
    """VG004: replace USING (true)/WITH CHECK (true) on the flagged policy."""
    line_no = int(str(evidence.get("line", 0)))
    lines = file_content.split("\n")
    if not (1 <= line_no <= len(lines)):
        return None
    target = lines[line_no - 1]
    replacement = f"(select auth.uid()) = {owner_col}"
    fixed_line = re.sub(r"\btrue\b", replacement, target)
    if fixed_line == target:
        return None
    lines[line_no - 1] = fixed_line
    path = str(evidence["file"])
    return Fix(
        files={path: "\n".join(lines)},
        deleted_paths=[],
        title=f"Lock down policy on {evidence.get('table', 'table')}",
        summary=f"Policy allowed anyone to write. It now requires {owner_col} = auth.uid().",
    )


def secret_fix(finding: FindingRow, file_content: str, key_value_hint: str) -> Fix | None:
    """VG001: strip the secret literal from the flagged line; scaffold an edge
    function that reads the secret from server env. Rotation instructions go in
    the PR body."""
    path = str(finding.evidence["file"])
    line_no = int(finding.evidence.get("line", 0))
    lines = file_content.split("\n")
    if not (1 <= line_no <= len(lines)):
        return None
    line = lines[line_no - 1]
    # blank out any long literal on the flagged line
    fixed_line = re.sub(r"(['\"`])(eyJ|sb_|sbp_|postgres)[^'\"`]*\1",
                        r"\1REMOVED_ROTATE_ME\1", line)
    if fixed_line == line:
        return None
    lines[line_no - 1] = fixed_line
    edge = """// VibeGuard scaffold: perform the privileged call here instead of the client.
// Set the secret with:  supabase secrets set SUPABASE_SERVICE_ROLE_KEY=<new key>
const key = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

Deno.serve(async (req) => {
  // TODO: move the client-side call here and use `key`.
  return new Response('not implemented', { status: 501 })
})
"""
    return Fix(
        files={
            path: "\n".join(lines),
            "supabase/functions/vibeguard-server/index.ts": edge,
        },
        deleted_paths=[],
        title="Remove a leaked secret key from client code",
        summary="A service_role/secret key shipped in client code. It is removed "
                "here and a server-side scaffold is provided. Rotation is required.",
    )


def env_fix(path: str, gitignore_content: str | None) -> Fix:
    """VG008: git rm --cached the env file + ensure .env* is ignored."""
    gi = gitignore_content or ""
    if ".env*" not in gi:
        gi = (gi.rstrip("\n") + "\n.env*\n").lstrip("\n")
    files = {".gitignore": gi}
    return Fix(
        files=files,
        deleted_paths=[path],
        title="Stop tracking a committed env file",
        summary=f"{path} is committed and contains a Supabase key. It is removed "
                "from tracking and ignored. Rotation is required.",
    )
