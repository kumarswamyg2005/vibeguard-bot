"""GitHub App authentication: App JWT + installation tokens (PyJWT + httpx)."""

from __future__ import annotations

import time

import httpx
import jwt

API = "https://api.github.com"


def mint_app_jwt(app_id: str, private_key_pem: str, now: int | None = None) -> str:
    now = now or int(time.time())
    return jwt.encode(
        {"iat": now - 60, "exp": now + 540, "iss": app_id},
        private_key_pem,
        algorithm="RS256",
    )


class AppAuth:
    def __init__(self, app_id: str, private_key_pem: str,
                 client: httpx.Client | None = None) -> None:
        self.app_id = app_id
        self.private_key_pem = private_key_pem
        self._own = client is None
        self.client = client or httpx.Client(
            base_url=API,
            headers={"Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28"},
            timeout=30.0,
        )

    def _jwt_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {mint_app_jwt(self.app_id, self.private_key_pem)}"}

    def list_installations(self) -> list[dict]:
        """All installations of the App, each with its repos."""
        out: list[dict] = []
        page = 1
        while True:
            r = self.client.get("/app/installations",
                                headers=self._jwt_headers(),
                                params={"per_page": 100, "page": page})
            r.raise_for_status()
            batch = r.json()
            if not batch:
                break
            for inst in batch:
                repos = self._installation_repos(inst["id"])
                out.append({
                    "gh_installation_id": inst["id"],
                    "account_login": inst["account"]["login"],
                    "repos": repos,
                })
            if len(batch) < 100:
                break
            page += 1
        return out

    def _installation_repos(self, installation_id: int) -> list[dict]:
        token = self.installation_token(installation_id)
        repos: list[dict] = []
        page = 1
        while True:
            r = self.client.get(
                "/installation/repositories",
                headers={"Authorization": f"Bearer {token}"},
                params={"per_page": 100, "page": page},
            )
            r.raise_for_status()
            data = r.json()
            for repo in data.get("repositories", []):
                repos.append({
                    "gh_repo_id": repo["id"],
                    "full_name": repo["full_name"],
                    "default_branch": repo["default_branch"],
                })
            if len(data.get("repositories", [])) < 100:
                break
            page += 1
        return repos

    def installation_token(self, installation_id: int) -> str:
        r = self.client.post(
            f"/app/installations/{installation_id}/access_tokens",
            headers=self._jwt_headers(),
        )
        r.raise_for_status()
        return r.json()["token"]

    def close(self) -> None:
        if self._own:
            self.client.close()
