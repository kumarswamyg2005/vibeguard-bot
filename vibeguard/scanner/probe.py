"""VG003 live proof: HEAD-only PostgREST row-count probes.

Invariants enforced here by construction:

- HEAD only: a custom httpx transport raises on any other method (inv. 3).
- Consent: probe() refuses unless live_probe is on in the repo's own
  .vibeguard.yml AND the request host equals the repo's Supabase URL (inv. 2).
- Only the anon/publishable key is ever sent; secret keys are refused (inv. 4).
- Max 1 req/s/host, max 50 tables, table names only from the repo (inv. 5).
- Only Content-Range counts are read; bodies are never touched (inv. 3).
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from vibeguard.policy import (
    PROBE_INTERVAL_SECONDS,
    PROBE_MAX_TABLES,
    ProbeConsent,
    host_of,
)

_CONTENT_RANGE_RE = re.compile(r"^\s*\d+-\d+/(\d+|\*)\s*$")
SECRET_KEY_HINTS = ("sb_secret_", "service_role")


class NonHeadRequestError(RuntimeError):
    pass


class ProbeRefusedError(RuntimeError):
    pass


class HeadOnlyTransport(httpx.BaseTransport):
    """Wrap another transport and permit HEAD requests only."""

    def __init__(self, inner: httpx.BaseTransport | None = None) -> None:
        self._inner = inner or httpx.HTTPTransport()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.method.upper() != "HEAD":
            raise NonHeadRequestError(f"probe attempted {request.method} — HEAD only")
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()


@dataclass
class RateLimiter:
    """1 request / PROBE_INTERVAL_SECONDS per host. Inject clock+sleep for tests."""

    clock: Callable[[], float] | None = None
    sleep: Callable[[float], None] | None = None
    interval: float = PROBE_INTERVAL_SECONDS
    _last: dict[str, float] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self._last is None:
            self._last = {}
        if self.clock is None:
            self.clock = time.time
        if self.sleep is None:
            self.sleep = time.sleep

    def wait(self, host: str) -> None:
        assert self.clock is not None and self.sleep is not None
        last = self._last.get(host)
        if last is not None:
            gap = self.clock() - last
            if gap < self.interval:
                self.sleep(self.interval - gap)
        self._last[host] = self.clock()


def parse_content_range(value: str | None) -> int | None:
    if not value:
        return None
    m = _CONTENT_RANGE_RE.match(value)
    if not m or m.group(1) == "*":
        return None
    return int(m.group(1))


def _is_safe_key(key: str) -> bool:
    """Invariant 4: only anon/publishable keys may be sent."""
    if key.startswith("sb_secret_"):
        return False
    if key.startswith("eyJ"):
        from vibeguard.scanner.secrets import jwt_role

        role = jwt_role(key)
        return role in ("anon", None) and role != "service_role"
    return key.startswith("sb_publishable_")


def probe(
    supabase_url: str,
    anon_key: str,
    tables: list[str],
    *,
    live_probe: bool,
    client: httpx.Client | None = None,
    limiter: RateLimiter | None = None,
    max_tables: int = PROBE_MAX_TABLES,
) -> dict[str, int | None]:
    """HEAD-probe each table's row count. Returns {table: count|None}.

    Raises ProbeRefusedError if consent/host checks fail (invariant 2).
    """
    if not live_probe:
        raise ProbeRefusedError("live_probe is off for this repo")
    host = host_of(supabase_url)
    consent = ProbeConsent(
        live_probe_flag=live_probe, repo_supabase_url=supabase_url, request_host=host or ""
    )
    if not consent.allowed or host is None:
        raise ProbeRefusedError("host mismatch or missing consent")
    if not _is_safe_key(anon_key):
        raise ProbeRefusedError("refusing to send a non-anon key")

    own_client = client is None
    client = client or httpx.Client(
        transport=HeadOnlyTransport(), base_url=supabase_url, timeout=10.0
    )
    limiter = limiter or RateLimiter()
    results: dict[str, int | None] = {}
    try:
        for table in tables[:max_tables]:
            limiter.wait(host)
            try:
                r = client.head(
                    f"/rest/v1/{table}",
                    params={"select": "*"},
                    headers={
                        "apikey": anon_key,
                        "Authorization": f"Bearer {anon_key}",
                        "Prefer": "count=exact",
                        "Range": "0-0",
                        "Range-Unit": "items",
                    },
                )
            except httpx.HTTPError:
                results[table] = None
                continue
            results[table] = parse_content_range(r.headers.get("Content-Range"))
    finally:
        if own_client:
            client.close()
    return results
