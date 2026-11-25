"""Scanner data model."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "info"]

# evidence keys allowed: file, line, table, key_type, key_hash, row_count, detail
Evidence = dict[str, Any]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: Severity
    fingerprint: str
    evidence: Evidence
    fixable: bool
    summary: str

    @staticmethod
    def fingerprint_of(*parts: str) -> str:
        h = hashlib.sha256("|".join(parts).encode()).hexdigest()
        return h[:24]


@dataclass
class RepoSignals:
    """Things the scan learned about the repo beyond findings."""

    supabase_url: str | None = None
    anon_key_values: list[str] = field(default_factory=list)  # usable for probes only
    live_probe: bool = False
    public_on_scoreboard: bool = False
    config_found: bool = False
    table_names: list[str] = field(default_factory=list)  # public tables, for probing
    warnings: list[str] = field(default_factory=list)  # safe summaries only, no paths


@dataclass
class ScanResult:
    findings: list[Finding]
    signals: RepoSignals
