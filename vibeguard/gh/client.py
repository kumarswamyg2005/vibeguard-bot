"""Per-repo GitHub operations bound to an installation token.

Uses only REST + the Git Data API (multi-file commits without a checkout) and
`git clone --depth 1` for scanning. Tokens never appear in logs — clone uses
an http.extraheader, not a token-in-URL.
"""

from __future__ import annotations

import base64
import datetime as dt
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import httpx

API = "https://api.github.com"
BOT_BRANCH_PREFIX = "vibeguard/"


@dataclass
class RepoComment:
    comment_id: int
    gh_number: int  # PR/issue number
    body: str


@dataclass
class PrState:
    state: str  # open|closed
    merged: bool


class RateLimitedError(RuntimeError):
    pass


class GhRepo:
    def __init__(self, full_name: str, token: str,
                 client: httpx.Client | None = None) -> None:
        self.full_name = full_name
        self.token = token
        self._own = client is None
        self.client = client or httpx.Client(
            base_url=API,
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "Authorization": f"Bearer {token}",
            },
            timeout=30.0,
        )

    def _req(self, method: str, path: str, **kw) -> httpx.Response:
        r = self.client.request(method, f"/repos/{self.full_name}{path}", **kw)
        if r.status_code in (403, 429) and (
            "rate limit" in r.text.lower() or r.status_code == 429
        ):
            raise RateLimitedError(f"github {r.status_code}")
        r.raise_for_status()
        return r

    # -- reading -------------------------------------------------------------

    def head_sha(self, branch: str | None = None) -> str:
        if branch:
            r = self._req("GET", f"/branches/{branch}")
            return r.json()["commit"]["sha"]
        r = self._req("GET", "")
        default = r.json()["default_branch"]
        return self.head_sha(default)

    def clone(self, dest: Path) -> None:
        """Shallow clone of the default branch. Token goes via header, not URL."""
        basic = base64.b64encode(f"x-access-token:{self.token}".encode()).decode()
        subprocess.run(  # noqa: S603 - args are fixed-shape, no shell
            [
                shutil.which("git") or "git", "-c",
                f"http.https://github.com/.extraheader=AUTHORIZATION: basic {basic}",
                "clone", "--depth", "1", "--quiet",
                f"https://github.com/{self.full_name}.git", str(dest),
            ],
            check=True,
            capture_output=True,
        )

    def comments_since(self, since: dt.datetime) -> list[RepoComment]:
        out: list[RepoComment] = []
        for endpoint, number_key in (
            ("/issues/comments", "issue_url"),
            ("/pulls/comments", "pull_request_url"),
        ):
            page = 1
            while True:
                r = self._req(
                    "GET", endpoint,
                    params={"since": since.isoformat(), "per_page": 100, "page": page})
                batch = r.json()
                if not batch:
                    break
                for c in batch:
                    url = c.get(number_key, "")
                    try:
                        number = int(str(url).rstrip("/").rsplit("/", 1)[-1])
                    except (ValueError, IndexError):
                        continue
                    out.append(RepoComment(c["id"], number, c.get("body") or ""))
                if len(batch) < 100:
                    break
                page += 1
        return out

    def pr_state(self, number: int) -> PrState:
        r = self._req("GET", f"/pulls/{number}")
        d = r.json()
        return PrState(state=d["state"], merged=bool(d.get("merged_at")))

    def issue_state(self, number: int) -> str:
        r = self._req("GET", f"/issues/{number}")
        return r.json()["state"]

    # -- checks ----------------------------------------------------------------

    def create_check_run(self, sha: str, title: str, summary: str) -> None:
        self._req("POST", "/check-runs", json={
            "name": "VibeGuard",
            "head_sha": sha,
            "status": "completed",
            "conclusion": "neutral",
            "output": {"title": title, "summary": summary},
        })

    # -- writing ---------------------------------------------------------------

    def _blob(self, content: str) -> str:
        r = self._req("POST", "/git/blobs",
                      json={"content": content, "encoding": "utf-8"})
        return r.json()["sha"]

    def push_files(self, branch: str, files: dict[str, str], message: str,
                   base_branch: str | None = None,
                   deletes: list[str] | None = None) -> None:
        """Create branch (if needed) and commit `files` onto it via Git Data API.

        `deletes` lists paths to remove from the tree (sha=None entries).
        """
        base_sha = self.head_sha(base_branch)
        base = self._req("GET", f"/git/commits/{base_sha}").json()
        tree_items: list[dict] = [
            {"path": p, "mode": "100644", "type": "blob", "sha": self._blob(c)}
            for p, c in files.items()
        ]
        for p in deletes or []:
            tree_items.append({"path": p, "mode": "100644", "type": "blob", "sha": None})
        tree = self._req("POST", "/git/trees",
                         json={"base_tree": base["tree"]["sha"],
                               "tree": tree_items}).json()
        commit = self._req("POST", "/git/commits", json={
            "message": message,
            "tree": tree["sha"],
            "parents": [base_sha],
        }).json()
        ref = f"refs/heads/{branch}"
        try:
            self._req("POST", "/git/refs",
                      json={"ref": ref, "sha": commit["sha"]})
        except httpx.HTTPStatusError:
            self._req("PATCH", f"/git/{ref}", json={"sha": commit["sha"]})

    def open_pr(self, title: str, body: str, head: str,
                base: str | None = None) -> int:
        payload: dict = {"title": title, "body": body, "head": head}
        if base:
            payload["base"] = base
        r = self._req("POST", "/pulls", json=payload)
        return r.json()["number"]

    def open_issue(self, title: str, body: str) -> int:
        r = self._req("POST", "/issues", json={"title": title, "body": body})
        return r.json()["number"]

    def pr_files(self, number: int) -> list[str]:
        r = self._req("GET", f"/pulls/{number}/files", params={"per_page": 100})
        return [f["filename"] for f in r.json()]

    def comment(self, number: int, body: str) -> None:
        self._req("POST", f"/issues/{number}/comments", json={"body": body})

    def close(self) -> None:
        if self._own:
            self.client.close()


class Gh:
    """Factory: App credentials → per-repo clients."""

    def __init__(self, auth: AppAuth) -> None:  # noqa: F821
        from vibeguard.gh.app import AppAuth

        self.auth: AppAuth = auth

    def list_installations(self) -> list[dict]:
        return self.auth.list_installations()

    def repo(self, full_name: str, installation_id: int) -> GhRepo:
        token = self.auth.installation_token(installation_id)
        return GhRepo(full_name, token)
