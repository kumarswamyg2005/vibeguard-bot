"""FakeGh: in-memory GitHub for hermetic tick tests.

A fake repo is {gh_repo_id, full_name, default_branch, sha, files|fixture,
comments, prs, issues, api_calls}. `fixture` points at a directory copied on
clone; `files` is an inline {path: content} tree.
"""

from __future__ import annotations

import datetime as dt
import itertools
import shutil
from pathlib import Path

from vibeguard.gh.client import PrState, RepoComment


class FakeRepoOps:
    def __init__(self, gh: FakeGh, repo: dict) -> None:
        self._gh = gh
        self._repo = repo
        self.full_name = repo["full_name"]

    def _count(self, op: str) -> None:
        self._repo.setdefault("api_calls", []).append(op)

    def head_sha(self, branch: str | None = None) -> str:
        self._count("head_sha")
        return self._repo["sha"]

    def clone(self, dest: Path) -> None:
        self._count("clone")
        dest.mkdir(parents=True, exist_ok=True)
        if "fixture" in self._repo:
            src = Path(self._repo["fixture"])
            for p in src.rglob("*"):
                if p.is_file():
                    rel = p.relative_to(src)
                    (dest / rel).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy(p, dest / rel)
        for rel, content in self._repo.get("files", {}).items():
            fp = dest / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_text(content)

    def comments_since(self, since: dt.datetime) -> list[RepoComment]:
        self._count("comments_since")
        return [
            RepoComment(c["comment_id"], c["gh_number"], c["body"])
            for c in self._repo.get("comments", [])
        ]

    def pr_state(self, number: int) -> PrState:
        self._count("pr_state")
        pr = self._repo.setdefault("prs", {})[number]
        return PrState(state=pr["state"], merged=pr.get("merged", False))

    def issue_state(self, number: int) -> str:
        self._count("issue_state")
        return self._repo.setdefault("issues", {})[number]["state"]

    def create_check_run(self, sha: str, title: str, summary: str) -> None:
        self._count("create_check_run")
        self._repo.setdefault("check_runs", []).append(title)

    def push_files(self, branch: str, files: dict[str, str], message: str,
                   base_branch: str | None = None,
                   deletes: list[str] | None = None) -> None:
        self._count("push_files")
        tree = self._repo.setdefault("files", {})
        tree.update(files)
        for p in deletes or []:
            tree.pop(p, None)
        self._repo.setdefault("branches", {})[branch] = list(files) + [
            f"-{p}" for p in deletes or []]

    def open_pr(self, title: str, body: str, head: str,
                base: str | None = None) -> int:
        self._count("open_pr")
        n = next(self._gh._numbers)
        self._repo.setdefault("prs", {})[n] = {
            "state": "open", "merged": False, "title": title, "body": body,
            "head": head}
        return n

    def open_issue(self, title: str, body: str) -> int:
        self._count("open_issue")
        n = next(self._gh._numbers)
        self._repo.setdefault("issues", {})[n] = {
            "state": "open", "title": title, "body": body}
        return n

    def comment(self, number: int, body: str) -> None:
        self._count("comment")

    def pr_files(self, number: int) -> list[str]:
        return []


class FakeGh:
    def __init__(self, installations: list[dict]) -> None:
        self.installations = installations
        self._numbers = itertools.count(100)
        self._by_name = {
            r["full_name"]: r
            for inst in installations for r in inst.get("repos", [])
        }

    def list_installations(self) -> list[dict]:
        return self.installations

    def repo(self, full_name: str, installation_id: int) -> FakeRepoOps:
        return FakeRepoOps(self, self._by_name[full_name])

    def repo_dict(self, full_name: str) -> dict:
        return self._by_name[full_name]
