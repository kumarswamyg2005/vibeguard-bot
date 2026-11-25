from __future__ import annotations

import httpx
import pytest
import respx
from freezegun import freeze_time
from freezegun.api import FakeDatetime  # noqa: F401

from vibeguard.scanner.probe import (
    HeadOnlyTransport,
    NonHeadRequestError,
    ProbeRefusedError,
    RateLimiter,
    parse_content_range,
    probe,
)

BASE = "https://demoappabcdefghij12.supabase.co"
ANON = (
    "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9."
    "eyJpc3MiOiAic3VwYWJhc2UiLCAicmVmIjogImRlbW9hcHAiLCAicm9sZSI6ICJhbm9uIiwgImlhdCI6IDE3MDAwMDAwMDAsICJleHAiOiAyMDAwMDAwMDAwfQ."
    + "A" * 43
)
SVC = (
    "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9."
    "eyJpc3MiOiAic3VwYWJhc2UiLCAicmVmIjogImRlbW9hcHAiLCAicm9sZSI6ICJzZXJ2aWNlX3JvbGUiLCAiaWF0IjogMTcwMDAwMDAwMCwgImV4cCI6IDIwMDAwMDAwMDB9."
    + "A" * 43
)


def test_parse_content_range():
    assert parse_content_range("0-0/42") == 42
    assert parse_content_range("0-24/357") == 357
    assert parse_content_range("*/0") is None
    assert parse_content_range(None) is None


def test_transport_rejects_get():
    t = HeadOnlyTransport(inner=httpx.MockTransport(lambda r: httpx.Response(200)))
    c = httpx.Client(transport=t)
    with pytest.raises(NonHeadRequestError):
        c.get("https://x.example")


def test_probe_refuses_without_consent():
    with pytest.raises(ProbeRefusedError):
        probe(BASE, ANON, ["t"], live_probe=False)


def test_probe_refuses_secret_key():
    with pytest.raises(ProbeRefusedError):
        probe(BASE, SVC, ["t"], live_probe=True)
    with pytest.raises(ProbeRefusedError):
        probe(BASE, "sb_secret_abcdefghijkl", ["t"], live_probe=True)


def _recording_transport(count: int, requests: list[httpx.Request]):
    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.method == "HEAD", "probe must only ever send HEAD"
        return httpx.Response(200, headers={"Content-Range": f"0-0/{count}"})

    return HeadOnlyTransport(httpx.MockTransport(handler))


def test_probe_head_only_and_headers():
    requests: list[httpx.Request] = []
    with httpx.Client(transport=_recording_transport(42, requests), base_url=BASE) as client:
        out = probe(BASE, ANON, ["posts"], live_probe=True, client=client,
                    limiter=RateLimiter(interval=0))
    assert out == {"posts": 42}
    assert len(requests) == 1
    req = requests[0]
    assert req.method == "HEAD"
    assert req.headers["Prefer"] == "count=exact"
    assert req.headers["Range"] == "0-0"
    assert req.headers["apikey"] == ANON


@respx.mock
def test_probe_refusal_sends_zero_requests():
    route = respx.route().mock(return_value=httpx.Response(200))
    with pytest.raises(ProbeRefusedError):
        probe(BASE, ANON, ["t"], live_probe=False)
    assert not route.called


def test_probe_host_mismatch_not_consented():
    from vibeguard.policy import ProbeConsent

    c = ProbeConsent(
        live_probe_flag=True,
        repo_supabase_url=BASE,
        request_host="evil.example",
    )
    assert not c.allowed


def test_probe_max_50_tables():
    requests: list[httpx.Request] = []
    tables = [f"t{i}" for i in range(60)]
    with httpx.Client(transport=_recording_transport(1, requests), base_url=BASE) as client:
        out = probe(BASE, ANON, tables, live_probe=True, client=client,
                    limiter=RateLimiter(interval=0))
    assert len(out) == 50
    assert len(requests) == 50


def test_rate_limit_1_per_second():
    t = [1_000.0]
    sleeps: list[float] = []

    def fake_sleep(s: float) -> None:
        sleeps.append(s)
        t[0] += s

    limiter = RateLimiter(clock=lambda: t[0], sleep=fake_sleep)
    host = "h.example"
    for _ in range(10):
        limiter.wait(host)
    # 10 tables => 9 waits of 1s each (first is free)
    assert len(sleeps) == 9
    assert all(abs(s - 1.0) < 1e-6 for s in sleeps)


def test_rate_limit_with_freezegun_clock():
    with freeze_time("2026-11-25 12:00:00") as ft:
        sleeps: list[float] = []

        def fake_sleep(s: float) -> None:
            sleeps.append(s)
            ft.tick(s)

        limiter = RateLimiter(sleep=fake_sleep)  # clock defaults to time.time (frozen)
        for _ in range(10):
            limiter.wait("h.example")
        assert len(sleeps) == 9
