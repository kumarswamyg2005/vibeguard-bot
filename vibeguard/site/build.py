"""Static site builder: Jinja2 → site/dist for GitHub Pages.

Renders the install page, the scoreboard (aggregates only — invariant 10) and
the /app-created/ code display page. When SUPABASE_DB_URL is unset the
scoreboard renders its empty state so the site still builds before the App
exists.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import shutil
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

ROOT = Path(__file__).parent.parent.parent
SITE = ROOT / "site"
DIST = SITE / "dist"
DEFAULT_INSTALL_URL = "https://github.com/apps/vibeguard-bot/installations/new"


def _median_fmt(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    s = int(seconds)
    if s < 3600:
        return f"{s // 60}m"
    return f"{s // 3600}h {s % 3600 // 60:02d}m"


def _scoreboard_rows(db_url: str | None) -> tuple[list[dict], list[str]]:
    if not db_url:
        return [], []
    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError:  # pragma: no cover
        return [], []
    try:
        with psycopg.connect(db_url, row_factory=dict_row) as conn, conn.cursor() as cur:
            cur.execute("select * from weekly_scoreboard order by week desc limit 8")
            rows = [
                {
                    "week": r["week"].strftime("%d %b %Y"),
                    "apps_protected": r["apps_protected"],
                    "criticals_closed": r["criticals_closed"],
                    "median_seconds": r["median_time_to_fix_seconds"],
                    "median_fmt": _median_fmt(r["median_time_to_fix_seconds"]),
                }
                for r in cur.fetchall()
            ]
            cur.execute(
                "select full_name from repos where public_on_scoreboard and status='active'"
            )
            public_repos = [r["full_name"] for r in cur.fetchall()]
            return rows, public_repos
    except Exception:  # noqa: BLE001 - site must still render without a DB
        return [], []


def build(db_url: str | None = None, install_url: str | None = None) -> Path:
    install_url = install_url or os.environ.get(
        "VIBEGUARD_INSTALL_URL", DEFAULT_INSTALL_URL)
    db_url = db_url or os.environ.get("SUPABASE_DB_URL")

    env = Environment(
        loader=FileSystemLoader(SITE / "templates"),
        undefined=StrictUndefined,
        autoescape=select_autoescape(("html", "j2")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    if DIST.exists():
        shutil.rmtree(DIST)
    (DIST / "scoreboard").mkdir(parents=True)
    (DIST / "app-created").mkdir(parents=True)
    (DIST / "assets").mkdir(parents=True)
    shutil.copy(SITE / "static" / "style.css", DIST / "assets" / "style.css")

    base = {"install_url": install_url, "root": "./"}
    (DIST / "index.html").write_text(
        env.get_template("index.html.j2").render(**base))

    rows, public_repos = _scoreboard_rows(db_url)
    current = rows[0] if rows else None
    has_data = bool(rows and (
        current["apps_protected"] or current["criticals_closed"]))
    sb_ctx = {
        **base,
        "root": "../",
        "rows": rows,
        "current": current or {"apps_protected": 0, "criticals_closed": 0},
        "median_fmt": _median_fmt(
            current["median_seconds"] if current else None),
        "current_week": current["week"] if current
        else dt.datetime.now(dt.UTC).strftime("%d %b %Y"),
        "has_data": has_data,
        "public_repos": public_repos,
    }
    (DIST / "scoreboard" / "index.html").write_text(
        env.get_template("scoreboard.html.j2").render(**sb_ctx))

    (DIST / "scoreboard.json").write_text(json.dumps({
        "week": sb_ctx["current_week"],
        "apps_protected": (current or {}).get("apps_protected", 0),
        "criticals_closed": (current or {}).get("criticals_closed", 0),
        "median_time_to_fix_seconds": (current or {}).get("median_seconds"),
        "weeks": [
            {"week": r["week"], "apps_protected": r["apps_protected"],
             "criticals_closed": r["criticals_closed"],
             "median_time_to_fix_seconds": r["median_seconds"]}
            for r in rows
        ],
    }, indent=2))

    (DIST / "app-created" / "index.html").write_text(
        env.get_template("app-created.html.j2").render(**{**base, "root": "../"}))
    return DIST


if __name__ == "__main__":
    out = build()
    print(f"built {out}")
