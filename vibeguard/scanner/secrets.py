"""Secret detection (VG001, VG008, VG010).

Never stores or returns secret *values* in findings — only key_type and
sha256(value)[:12] (invariant 6). Raw values are kept only in a side channel
(RepoSignals.anon_key_values) so the prober can use an *anon/publishable* key
(invariant 4) without ever persisting it.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass

SB_SECRET_RE = re.compile(r"sb_secret_[A-Za-z0-9_\-]{8,}")
SB_PUBLISHABLE_RE = re.compile(r"sb_publishable_[A-Za-z0-9_\-]{8,}")
SBP_RE = re.compile(r"\bsbp_[A-Za-z0-9]{20,}\b")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{4,}")
PG_URI_RE = re.compile(r"postgres(?:ql)?://[^:\s'\"]+:[^@\s'\"]+@db\.[a-z0-9]+\.supabase\.co[^\s'\"]*")
SUPABASE_URL_RE = re.compile(r"https://[a-z0-9]{8,40}\.supabase\.co")
ASSIGN_RE = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]{2,60})\s*[=:]\s*['\"]?(?P<val>[^'\"\s,}]+)"
)

KeyType = str  # 'secret'|'service_role'|'publishable'|'anon'|'db_password'|'access_token'


@dataclass(frozen=True)
class KeyHit:
    key_type: KeyType
    value: str  # raw value — used only for hashing and (if anon) probing
    file: str
    line: int
    env_name: str | None


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def jwt_role(token: str) -> str | None:
    """Read only the `role` claim. Signature is never verified (by design)."""
    try:
        payload = token.split(".")[1]
        role = json.loads(_b64url_decode(payload)).get("role")
        return str(role) if role is not None else None
    except Exception:  # noqa: BLE001 - malformed token => not our finding
        return None


def _env_name_for(line_text: str, value: str) -> str | None:
    m = ASSIGN_RE.search(line_text)
    if m and m.group("val").strip("'\"") in value or (m and value in m.group("val")):
        return m.group("name")
    return None


def scan_text(path: str, text: str) -> list[KeyHit]:
    hits: list[KeyHit] = []
    lines = text.split("\n")
    for m in SB_SECRET_RE.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        v = m.group(0)
        hits.append(KeyHit("secret", v, path, line, _env_name_for(lines[line - 1], v)))
    for m in SB_PUBLISHABLE_RE.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        v = m.group(0)
        hits.append(KeyHit("publishable", v, path, line, _env_name_for(lines[line - 1], v)))
    for m in SBP_RE.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        v = m.group(0)
        hits.append(KeyHit("access_token", v, path, line, _env_name_for(lines[line - 1], v)))
    for m in PG_URI_RE.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        v = m.group(0)
        hits.append(KeyHit("db_password", v, path, line, _env_name_for(lines[line - 1], v)))
    for m in JWT_RE.finditer(text):
        v = m.group(0)
        role = jwt_role(v)
        if role is None:
            continue
        line = text.count("\n", 0, m.start()) + 1
        ktype = "service_role" if role == "service_role" else ("anon" if role == "anon" else None)
        if ktype:
            hits.append(KeyHit(ktype, v, path, line, _env_name_for(lines[line - 1], v)))
    return hits


def supabase_url_in(text: str) -> str | None:
    m = SUPABASE_URL_RE.search(text)
    return m.group(0) if m else None
