"""VG001–VG010 rules applied to a scanned repo."""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from pathlib import Path

from vibeguard.policy import (
    env_name_is_client_exposed,
    is_client_reachable,
    key_hash,
)
from vibeguard.scanner.migrations import Catalog, PolicyInfo, build_catalog
from vibeguard.scanner.model import Evidence, Finding, RepoSignals, ScanResult
from vibeguard.scanner.secrets import KeyHit, scan_text, supabase_url_in

MIGRATIONS_DIR = "supabase/migrations"
GENERATED_TYPES_GLOBS = (
    "src/integrations/supabase/types.ts",
    "src/types/supabase.ts",
    "database.types.ts",
    "src/database.types.ts",
    "types/supabase.ts",
)
ENV_FILE_RE = re.compile(r"^\.env(\..+)?$")
ADMIN_CHECK_RE = re.compile(r"\bis_?admin\b|role\s*={0,2}={1,2}\s*['\"]admin['\"]", re.I)
SUPABASE_ANON_USAGE_RE = re.compile(r"createClient|supabase\.from|supabase-js", re.I)
SECRET_KEY_TYPES = ("secret", "service_role", "db_password", "access_token")

_TEXT_EXTS = {
    ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte",
    ".json", ".env", ".yaml", ".yml", ".toml", ".sql", ".py", ".md",
    ".html", ".css", ".txt", ".sh", ".example",
}
_SKIP_DIRS = {"node_modules", ".git", "dist", "build", ".next", ".vercel", "coverage"}


def _walk_files(root: Path) -> Iterator[tuple[str, Path]]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            rel = p.relative_to(root).as_posix()
            yield rel, p


def _read(p: Path) -> str | None:
    try:
        if p.suffix.lower() not in _TEXT_EXTS and p.name not in (
            ".env", ".env.local", ".env.production", ".env.development", ".env.example"
        ):
            return None
        return p.read_text(errors="replace")[:500_000]
    except OSError:
        return None


def _table_names_from_types(text: str) -> list[str]:
    # matches `      my_table: {\n        Row:` inside Tables: { ... }
    names = re.findall(r"^\s{2,8}([a-zA-Z_][a-zA-Z0-9_]*):\s*\{\s*$", text, re.M)
    return [n for n in names if n not in ("Tables", "Row", "Insert", "Update", "Relationships")]


def _is_env_file(rel: str) -> bool:
    base = rel.rsplit("/", 1)[-1]
    return bool(ENV_FILE_RE.match(base)) and "example" not in base and "sample" not in base


def scan_repo(root: Path) -> ScanResult:
    signals = RepoSignals()
    all_hits: list[KeyHit] = []
    migration_files: list[tuple[str, str]] = []
    files_text: dict[str, str] = {}

    for rel, p in sorted(_walk_files(root)):
        text = _read(p)
        if text is None:
            continue
        files_text[rel] = text
        all_hits.extend(scan_text(rel, text))
        if rel.startswith(MIGRATIONS_DIR + "/") and rel.endswith(".sql"):
            migration_files.append((rel, text))
        if signals.supabase_url is None:
            signals.supabase_url = supabase_url_in(text)

    migration_files.sort(key=lambda t: t[0])
    catalog = build_catalog(migration_files)
    signals.warnings.extend(catalog.warnings)
    signals.table_names = [t.name for t in catalog.public_tables()]

    for glob in GENERATED_TYPES_GLOBS:
        t = files_text.get(glob)
        if t:
            for n in _table_names_from_types(t):
                if n not in signals.table_names:
                    signals.table_names.append(n)

    # .vibeguard.yml (top-level only, on the checked-out default branch)
    cfg = files_text.get(".vibeguard.yml") or files_text.get(".vibeguard.yaml")
    if cfg is not None:
        signals.config_found = True
        import yaml

        try:
            data = yaml.safe_load(cfg) or {}
            signals.live_probe = bool(data.get("live_probe", False))
            signals.public_on_scoreboard = bool(data.get("public_on_scoreboard", False))
        except yaml.YAMLError:
            signals.warnings.append("unparseable .vibeguard.yml")

    # anon/publishable keys usable for probing (values never stored — invariant 6)
    seen_anon: set[str] = set()
    for h in all_hits:
        if h.key_type in ("anon", "publishable") and h.value not in seen_anon:
            seen_anon.add(h.value)
            signals.anon_key_values.append(h.value)

    findings: list[Finding] = []
    findings += _rule_secrets(all_hits)
    findings += _rule_rls(catalog)
    findings += _rule_client_side_admin(files_text, all_hits)
    return ScanResult(findings=findings, signals=signals)


def _rule_secrets(hits: list[KeyHit]) -> list[Finding]:
    out: list[Finding] = []
    env_files: set[str] = set()
    for h in hits:
        ev: Evidence = {
            "file": h.file,
            "line": h.line,
            "key_type": h.key_type,
            "key_hash": key_hash(h.value),
        }
        env_exposed = env_name_is_client_exposed(h.env_name or "")
        base = h.file.rsplit("/", 1)[-1]
        if _is_env_file(h.file):
            env_files.add(h.file)
            out.append(
                Finding(
                    rule_id="VG008",
                    severity="medium",
                    fingerprint=Finding.fingerprint_of("VG008", h.file, ev["key_hash"]),
                    evidence=ev,
                    fixable=True,
                    summary=f"Committed {base} contains a Supabase key",
                )
            )
        if h.key_type in SECRET_KEY_TYPES and (is_client_reachable(h.file) or env_exposed):
            out.append(
                Finding(
                    rule_id="VG001",
                    severity="critical",
                    fingerprint=Finding.fingerprint_of(
                        "VG001", h.file, str(h.line), ev["key_hash"]),
                    evidence=ev,
                    fixable=True,
                    summary="Secret Supabase key is reachable from client code",
                )
            )
        elif h.key_type in ("anon", "service_role"):
            out.append(
                Finding(
                    rule_id="VG010",
                    severity="info",
                    fingerprint=Finding.fingerprint_of("VG010", h.file, ev["key_hash"]),
                    evidence=ev,
                    fixable=False,
                    summary=f"Legacy {h.key_type} JWT key in use (deprecation: end of 2026)",
                )
            )
    return out


def _rule_rls(cat: Catalog) -> list[Finding]:
    out: list[Finding] = []
    policies_by_table: dict[str, list[PolicyInfo]] = {}
    for pol in cat.policies:
        policies_by_table.setdefault(f"{pol.table_schema}.{pol.table}", []).append(pol)

    for t in cat.public_tables():
        ev: Evidence = {"file": t.file, "line": t.line, "table": t.name}
        table_pols = policies_by_table.get(t.qualified, [])
        if not t.rls_enabled:
            fp = Finding.fingerprint_of("VG002", t.qualified)
            out.append(
                Finding(
                    rule_id="VG002",
                    severity="critical",
                    fingerprint=fp,
                    evidence=ev | {"owner_col": t.owner_col},
                    fixable=bool(t.owner_col and t.owner_col_refs_auth_users),
                    summary=f"public.{t.name} has no Row Level Security",
                )
            )
            if table_pols:
                out.append(
                    Finding(
                        rule_id="VG005",
                        severity="high",
                        fingerprint=Finding.fingerprint_of("VG005", t.qualified, "no-rls"),
                        evidence=ev,
                        fixable=False,
                        summary=f"public.{t.name} has a policy but RLS is disabled",
                    )
                )
        elif not table_pols:
            out.append(
                Finding(
                    rule_id="VG005",
                    severity="info",
                    fingerprint=Finding.fingerprint_of("VG005", t.qualified, "no-policy"),
                    evidence=ev,
                    fixable=False,
                    summary=f"public.{t.name}: RLS enabled with no policies (fully locked down)",
                )
            )

    # VG004: write-anything policies
    for pol in cat.policies:
        if pol.cmd not in ("insert", "update", "delete", "all"):
            continue
        if not pol.touches_public:
            continue
        bad_using = pol.cmd in ("all", "update", "delete") and pol.using_true
        bad_check = pol.cmd in ("all", "insert", "update") and pol.check_true
        if not (bad_using or bad_check):
            continue
        tinfo = cat.tables.get(f"{pol.table_schema}.{pol.table}")
        fixable = bool(tinfo and tinfo.owner_col and tinfo.owner_col_refs_auth_users)
        out.append(
            Finding(
                rule_id="VG004",
                severity="high",
                fingerprint=Finding.fingerprint_of("VG004", pol.file, str(pol.line), pol.name),
                evidence={
                    "file": pol.file,
                    "line": pol.line,
                    "table": pol.table,
                    "detail": f"policy {pol.name}: {pol.cmd} open to {','.join(pol.roles)}",
                },
                fixable=fixable,
                summary=f"Policy {pol.name} lets anyone {pol.cmd} rows in {pol.table}",
            )
        )

    # VG006: security definer functions
    for fn in cat.functions:
        if fn.schema != "public" or not fn.security_definer:
            continue
        if fn.has_set_search_path and cat.exec_revoked_from_public_anon:
            continue
        out.append(
            Finding(
                rule_id="VG006",
                severity="high",
                fingerprint=Finding.fingerprint_of("VG006", fn.schema + "." + fn.name),
                evidence={"file": fn.file, "line": fn.line, "detail": fn.name},
                fixable=False,
                summary=(
                    f"SECURITY DEFINER function {fn.name} "
                    + ("without set search_path" if not fn.has_set_search_path
                       else "still executable by anon")
                ),
            )
        )

    # VG007: public storage bucket + broad select policy on storage.objects
    if cat.public_buckets:
        for pol in cat.policies:
            if pol.table_schema == "storage" and pol.table == "objects" and pol.cmd in (
                "select",
                "all",
            ) and (pol.using_true or pol.touches_public):
                out.append(
                    Finding(
                        rule_id="VG007",
                        severity="high",
                        fingerprint=Finding.fingerprint_of("VG007", pol.file, str(pol.line)),
                        evidence={"file": pol.file, "line": pol.line, "detail": pol.name},
                        fixable=False,
                        summary=f"Public storage bucket listable via policy {pol.name}",
                    )
                )
                break
    return out


def _rule_client_side_admin(files: dict[str, str], hits: list[KeyHit]) -> list[Finding]:
    has_anon_usage = any(h.key_type in ("anon", "publishable") for h in hits)
    if not has_anon_usage:
        return []
    for rel, text in files.items():
        if not is_client_reachable(rel):
            continue
        m = ADMIN_CHECK_RE.search(text)
        if m:
            line = text.count("\n", 0, m.start()) + 1
            return [
                Finding(
                    rule_id="VG009",
                    severity="high",
                    fingerprint=Finding.fingerprint_of("VG009", rel, str(line)),
                    evidence={"file": rel, "line": line},
                    fixable=False,
                    summary="Admin authorization appears to happen only in client code",
                )
            ]
    return []


def probe_findings(rows: list[tuple[str, int]]) -> list[Finding]:
    """VG003: convert probe results (table, row_count>0) into findings."""
    out = []
    for table, count in rows:
        if count <= 0:
            continue
        out.append(
            Finding(
                rule_id="VG003",
                severity="critical",
                fingerprint=Finding.fingerprint_of("VG003", table),
                evidence={"table": table, "row_count": count},
                fixable=True,
                summary=f"public.{table}: {count} rows readable over the anon API",
            )
        )
    return out
