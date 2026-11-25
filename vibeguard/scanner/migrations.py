"""Parse supabase/migrations/*.sql with pglast into a schema catalog.

Order matters: files are applied in filename order; a later ALTER fixes an
earlier CREATE (e.g. RLS enabled in migration 003 on a table created in 001).
Unparseable files produce a warning and are skipped — nothing is guessed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import pglast
from pglast import ast, enums


@dataclass
class TableInfo:
    schema: str
    name: str
    file: str
    line: int
    rls_enabled: bool = False
    rls_forced: bool = False
    owner_col: str | None = None
    owner_col_refs_auth_users: bool = False

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.name}"


@dataclass
class PolicyInfo:
    name: str
    table_schema: str
    table: str
    cmd: str  # all|select|insert|update|delete
    roles: list[str]
    using_true: bool
    check_true: bool
    file: str
    line: int

    @property
    def touches_public(self) -> bool:
        return any(r.lower() in ("public", "anon", "authenticated") for r in self.roles)


@dataclass
class FunctionInfo:
    schema: str
    name: str
    security_definer: bool
    has_set_search_path: bool
    file: str
    line: int


@dataclass
class Catalog:
    tables: dict[str, TableInfo] = field(default_factory=dict)  # key: schema.name
    policies: list[PolicyInfo] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)
    public_buckets: set[str] = field(default_factory=set)
    exec_revoked_from_public_anon: bool = False
    warnings: list[str] = field(default_factory=list)

    def public_tables(self) -> list[TableInfo]:
        return [t for t in self.tables.values() if t.schema == "public"]


def _line_of(sql: str, location: int) -> int:
    return sql.count("\n", 0, max(location, 0)) + 1


def _rel(rel: ast.RangeVar | None) -> tuple[str, str]:
    if rel is None:
        return "public", ""
    return (rel.schemaname or "public"), rel.relname


def _const_true(node: Any) -> bool:
    """Is this expression the literal TRUE (allowing parens/casts)?"""
    if node is None:
        return False
    if isinstance(node, ast.A_Const):
        val = node.val
        if isinstance(val, ast.Boolean):
            return bool(val.boolval)
        if isinstance(val, ast.Integer):
            return bool(val.ival)
        return False
    if isinstance(node, ast.TypeCast):
        return _const_true(node.arg)
    return False


_ROLE_ATTR = "roles"


def _roles_of(stmt: ast.CreatePolicyStmt) -> list[str]:
    roles = getattr(stmt, _ROLE_ATTR, None) or ()
    out: list[str] = []
    for r in roles:
        if isinstance(r, ast.RoleSpec):
            if r.roletype == enums.RoleSpecType.ROLESPEC_PUBLIC:
                out.append("public")
            else:
                out.append(r.rolename or "public")
    return out or ["public"]


_AUTH_USERS_REF = re.compile(r"references\s+auth\.users|auth\.users\s*\(", re.I)
_SET_SEARCH_PATH = re.compile(r"set\s+(?:local\s+)?search_path", re.I)
_REVOKE_EXEC_PUBLIC = re.compile(
    r"revoke\s+(?:all|execute)[^;]*?from\s+(anon|public|authenticated)", re.I
)


def _owner_col(stmt: ast.CreateStmt, sql: str) -> tuple[str | None, bool]:
    """Find an ownership column: name matches AND refs auth.users."""
    from vibeguard.policy import OWNERSHIP_COLUMN_NAMES

    for elt in stmt.tableElts or ():
        if not isinstance(elt, ast.ColumnDef):
            continue
        name = (elt.colname or "").lower()
        if name not in OWNERSHIP_COLUMN_NAMES:
            continue
        # does its type/constraint reference auth.users?
        refs = False
        for c in elt.constraints or ():
            if isinstance(c, ast.Constraint) and c.contype == enums.ConstrType.CONSTR_FOREIGN:
                pk = c.pktable
                if pk is not None and pk.relname == "users" and (pk.schemaname or "") == "auth":
                    refs = True
        if not refs and elt.raw_expr is not None:
            refs = bool(_AUTH_USERS_REF.search(str(elt.raw_expr)))
        if not refs:
            # crude but useful: look at the CREATE TABLE statement text near the column
            m = re.search(rf"{name}[^,\)]*{_AUTH_USERS_REF.pattern}", sql, re.I)
            refs = bool(m)
        return name, refs
    return None, False


def build_catalog(migration_files: list[tuple[str, str]]) -> Catalog:
    """migration_files: list of (repo_relative_path, sql_text), already sorted."""
    cat = Catalog()
    for path, sql in migration_files:
        try:
            parsed = pglast.parse_sql(sql)
        except Exception:  # noqa: BLE001 - any parse error => skip file, warn
            cat.warnings.append("unparseable migration skipped")
            continue

        if _REVOKE_EXEC_PUBLIC.search(sql):
            cat.exec_revoked_from_public_anon = True

        for raw in parsed:
            stmt = raw.stmt
            loc = getattr(raw, "stmt_location", 0) or 0
            line = _line_of(sql, loc)

            if isinstance(stmt, ast.CreateStmt):
                schema, name = _rel(stmt.relation)
                owner_col, refs = _owner_col(stmt, sql)
                prev = cat.tables.get(f"{schema}.{name}")
                cat.tables[f"{schema}.{name}"] = TableInfo(
                    schema=schema,
                    name=name,
                    file=path,
                    line=line,
                    rls_enabled=prev.rls_enabled if prev else False,
                    owner_col=owner_col or (prev.owner_col if prev else None),
                    owner_col_refs_auth_users=refs
                    or (prev.owner_col_refs_auth_users if prev else False),
                )
            elif isinstance(stmt, ast.AlterTableStmt):
                schema, name = _rel(stmt.relation)
                key = f"{schema}.{name}"
                for cmd in stmt.cmds or ():
                    if not isinstance(cmd, ast.AlterTableCmd):
                        continue
                    t = cat.tables.get(key)
                    if t is None:
                        t = TableInfo(schema=schema, name=name, file=path, line=line)
                        cat.tables[key] = t
                    st = cmd.subtype
                    if st == enums.AlterTableType.AT_EnableRowSecurity:
                        t.rls_enabled = True
                    elif st == enums.AlterTableType.AT_DisableRowSecurity:
                        t.rls_enabled = False
                    elif st == enums.AlterTableType.AT_ForceRowSecurity:
                        t.rls_forced = True
                    elif st == enums.AlterTableType.AT_AddColumn and isinstance(
                        cmd.def_, ast.ColumnDef
                    ):
                        col = cmd.def_
                        cname = (col.colname or "").lower()
                        from vibeguard.policy import OWNERSHIP_COLUMN_NAMES

                        if cname in OWNERSHIP_COLUMN_NAMES and t.owner_col is None:
                            refs = False
                            for c in col.constraints or ():
                                if (
                                    isinstance(c, ast.Constraint)
                                    and c.contype == enums.ConstrType.CONSTR_FOREIGN
                                    and c.pktable is not None
                                    and c.pktable.relname == "users"
                                    and (c.pktable.schemaname or "") == "auth"
                                ):
                                    refs = True
                            t.owner_col = cname
                            t.owner_col_refs_auth_users = refs or t.owner_col_refs_auth_users
            elif isinstance(stmt, ast.CreatePolicyStmt):
                schema, name = _rel(stmt.table)
                cat.policies.append(
                    PolicyInfo(
                        name=stmt.policy_name or "",
                        table_schema=schema,
                        table=name,
                        cmd=(stmt.cmd_name or "all").lower(),
                        roles=_roles_of(stmt),
                        using_true=_const_true(stmt.qual),
                        check_true=_const_true(stmt.with_check),
                        file=path,
                        line=line,
                    )
                )
            elif isinstance(stmt, ast.CreateFunctionStmt):
                names = [n.sval for n in stmt.funcname or () if isinstance(n, ast.String)]
                schema = names[-2] if len(names) >= 2 else "public"
                fname = names[-1] if names else ""
                security_definer = False
                has_set = False
                for opt in stmt.options or ():
                    if not isinstance(opt, ast.DefElem):
                        continue
                    if opt.defname == "security":
                        arg = opt.arg
                        if isinstance(arg, ast.Boolean):
                            security_definer = bool(arg.boolval)
                        elif isinstance(arg, ast.Integer):
                            security_definer = bool(arg.ival)
                        elif isinstance(arg, ast.A_Const):
                            security_definer = _const_true(arg)
                    if opt.defname == "set":
                        has_set = True
                if not has_set:
                    seg = sql[loc : loc + (getattr(raw, "stmt_len", 0) or 0)]
                    has_set = bool(_SET_SEARCH_PATH.search(seg))
                cat.functions.append(
                    FunctionInfo(
                        schema=schema,
                        name=fname,
                        security_definer=security_definer,
                        has_set_search_path=has_set,
                        file=path,
                        line=line,
                    )
                )
            elif isinstance(stmt, ast.InsertStmt):
                schema, name = _rel(stmt.relation)
                if schema == "storage" and name == "buckets":
                    _bucket_inserts(cat, stmt, sql, loc)
            elif isinstance(stmt, ast.GrantStmt):
                pass  # EXECUTE grants handled via _REVOKE_EXEC_PUBLIC text check

        # storage policy on storage.objects gets picked up via CreatePolicyStmt already
    return cat


def _bucket_inserts(cat: Catalog, stmt: ast.InsertStmt, sql: str, loc: int) -> None:
    cols = [c.name for c in stmt.cols or () if isinstance(c, ast.ResTarget)]
    sel = stmt.selectStmt
    values_lists = getattr(sel, "valuesLists", None) or ()
    for row in values_lists:
        vals = list(row)
        rowmap = {cols[i]: vals[i] for i in range(min(len(cols), len(vals)))}
        pub = rowmap.get("public")
        bid = rowmap.get("id") or rowmap.get("name")
        if _const_true(pub) and isinstance(bid, ast.A_Const):
            v = bid.val
            if isinstance(v, ast.String):
                cat.public_buckets.add(v.sval)
    # fallback for `select ... union` forms
    if not values_lists:
        seg = sql[loc : loc + (getattr(stmt, "stmt_len", 0) or 0)]
        for m in re.finditer(
            r"insert\s+into\s+storage\.buckets[^;]*?['\"]([\w\-\.]+)['\"][^;]*?true", seg, re.I
        ):
            cat.public_buckets.add(m.group(1))
