"""Tiny web server for the public Scam Radar page, run inside the bot process.

Routes
  /                 the Scam Radar page (static HTML, fetches the JSON below)
  /api/radar.json   aggregated, privacy-safe data (cached)
  /healthz          liveness check
  /favicon.svg, /og.png, /robots.txt
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import os
import re
import time
from pathlib import Path

from aiohttp import web

from .. import radar

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
GITHUB_URL = os.getenv("SCAMGUARD_GITHUB", "https://github.com/islomjonagzamov77/scamguard")
CACHE_SECONDS = 30

FAVICON = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 640"><defs><linearGradient id="s" x1="0" y1="0" '
    'x2="1" y2="1"><stop offset="0" stop-color="#3CF0B4"/><stop offset="1" stop-color="#1A9FE0"/></linearGradient>'
    '</defs><rect width="640" height="640" rx="140" fill="#07152B"/><path d="M320 132 L462 186 C462 330 420 430 '
    '320 492 C220 430 178 330 178 186 Z" fill="url(#s)"/><path d="M252 314 L302 364 L394 262" fill="none" '
    'stroke="#07152B" stroke-width="34" stroke-linecap="round" stroke-linejoin="round"/></svg>'
)


def render_page(bot_username: str) -> tuple[str, str]:
    """The page with placeholders filled in, and the CSP hash of its inline script."""
    page = (HERE / "radar.html").read_text(encoding="utf-8")
    page = page.replace("{{BOT}}", html.escape(bot_username or "scamguard_uzbbot"))
    page = page.replace("{{GITHUB}}", html.escape(GITHUB_URL))
    script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
    digest = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode()
    return page, f"'sha256-{digest}'"


def build_app(get_storage, get_bot_username, report_threshold: int) -> web.Application:
    cache: dict = {"at": 0.0, "body": b""}
    page_cache: dict = {}

    @web.middleware
    async def security_headers(request, handler):
        resp = await handler(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        return resp

    async def index(request):
        user = get_bot_username()
        if page_cache.get("user") != user:
            page_cache["user"] = user
            page_cache["page"], page_cache["hash"] = render_page(user)
        csp = ("default-src 'none'; img-src 'self' data:; connect-src 'self'; "
               f"script-src {page_cache['hash']}; style-src 'unsafe-inline'; base-uri 'none'; "
               # only Telegram may embed the page (Mini App on Telegram Web); everyone else is blocked
               "form-action 'none'; frame-ancestors https://web.telegram.org https://*.telegram.org")
        return web.Response(text=page_cache["page"], content_type="text/html", charset="utf-8",
                            headers={"Content-Security-Policy": csp, "Cache-Control": "public, max-age=300"})

    async def api(request):
        now = time.monotonic()
        if now - cache["at"] > CACHE_SECONDS:
            data = radar.build(get_storage(), report_threshold)
            cache["body"] = json.dumps(data, ensure_ascii=False).encode("utf-8")
            cache["at"] = now
        return web.Response(body=cache["body"], content_type="application/json", charset="utf-8",
                            headers={"Cache-Control": f"public, max-age={CACHE_SECONDS}",
                                     "Access-Control-Allow-Origin": "*"})

    async def healthz(request):
        return web.Response(text="ok")

    async def favicon(request):
        return web.Response(text=FAVICON, content_type="image/svg+xml", headers={"Cache-Control": "public, max-age=86400"})

    async def og_image(request):
        for name in ("description.png", "welcome_640x360.jpg"):
            path = ROOT / "assets" / name
            if path.exists():
                return web.FileResponse(path, headers={"Cache-Control": "public, max-age=86400"})
        raise web.HTTPNotFound()

    async def robots(request):
        return web.Response(text="User-agent: *\nAllow: /\n")

    app = web.Application(middlewares=[security_headers])
    app.router.add_get("/", index)
    app.router.add_get("/api/radar.json", api)
    app.router.add_get("/healthz", healthz)
    app.router.add_get("/favicon.svg", favicon)
    app.router.add_get("/og.png", og_image)
    app.router.add_get("/robots.txt", robots)
    return app


async def start(app: web.Application, port: int | None = None) -> web.AppRunner:
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", port or int(os.getenv("PORT", "8080"))).start()
    return runner
