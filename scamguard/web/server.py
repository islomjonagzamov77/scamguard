"""Tiny web server for the public Scam Radar page, run inside the bot process.

Routes
  /                     the Scam Radar page (static HTML, fetches the JSON below) with a message checker
  /api/radar.json       aggregated, privacy-safe data (cached)
  POST /api/v1/check    check a message: the same engine as the bot (rate-limited, nothing stored)
  /api/v1/feed.txt      threat feed: scam domains, one per line (Pi-hole / AdGuard / uBlock format)
  /api/v1/feed.json     threat feed with first/last seen, detections and reporters
  /healthz              liveness check
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
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Awaitable, Callable

from aiohttp import web

from .. import radar

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
GITHUB_URL = os.getenv("SCAMGUARD_GITHUB", "https://github.com/islomjonagzamov77/scamguard")
CACHE_SECONDS = 30
FEED_CACHE_SECONDS = 300
MAX_CHECK_CHARS = 4000                   # same order as a Telegram message (4096)
CHECK_LIMIT_PER_IP = (8, 60)             # checks per client per N seconds
CHECK_LIMIT_GLOBAL = (120, 60)           # all web checks together: protects the free API quotas the bot uses
LANGS = {"uz", "ru", "en"}

CheckFn = Callable[[str, str], Awaitable[dict]]


class RateLimiter:
    """Sliding-window limiter kept in memory (one bot process, so no shared store is needed)."""

    def __init__(self, limit: int, window: float, max_keys: int = 10_000):
        self.limit, self.window, self.max_keys = limit, window, max_keys
        self.hits: dict[str, deque] = defaultdict(deque)

    def retry_after(self, key: str, now: float | None = None) -> int:
        """0 if the call is allowed (and counts it), otherwise seconds to wait."""
        now = time.monotonic() if now is None else now
        hits = self.hits[key]
        while hits and now - hits[0] > self.window:
            hits.popleft()
        if len(hits) >= self.limit:
            return max(1, int(self.window - (now - hits[0])) + 1)
        hits.append(now)
        if len(self.hits) > self.max_keys:          # forget idle clients so memory stays bounded
            for k in [k for k, v in self.hits.items() if not v or now - v[-1] > self.window][: self.max_keys // 2]:
                del self.hits[k]
        return 0


def client_ip(request) -> str:
    """The visitor's address. Railway's edge proxy sets X-Real-IP / X-Forwarded-For; the last
    X-Forwarded-For entry is the one our own proxy added, so a client can't fake it."""
    real = request.headers.get("X-Real-IP", "").strip()
    if real:
        return real
    fwd = [p.strip() for p in request.headers.get("X-Forwarded-For", "").split(",") if p.strip()]
    return fwd[-1] if fwd else (request.remote or "unknown")


def api_error(status: int, code: str, message: str, headers: dict | None = None):
    return web.json_response({"error": code, "message": message}, status=status,
                             headers={"Cache-Control": "no-store", **(headers or {})})

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


def build_app(get_storage, get_bot_username, report_threshold: int, check: CheckFn | None = None) -> web.Application:
    """`check(text, lang)` runs the bot's full analysis and returns the verdict as a dict.
    Without it the checker endpoint answers 503 (the page then hides the checker)."""
    cache: dict = {"at": 0.0, "body": b""}
    feed_cache: dict = {"at": -1e9, "entries": [], "updated": ""}
    page_cache: dict = {}
    per_ip = RateLimiter(*CHECK_LIMIT_PER_IP)
    overall = RateLimiter(*CHECK_LIMIT_GLOBAL)

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

    async def check_message(request):
        if check is None:
            return api_error(503, "unavailable", "The checker is not available on this server.")
        # JSON only: a cross-site HTML form can't send it, so other sites can't use visitors' browsers for this.
        if request.content_type != "application/json":
            return api_error(415, "json_required", "Send JSON: {\"text\": \"...\", \"lang\": \"uz|ru|en\"}.")
        if (request.content_length or 0) > MAX_CHECK_CHARS * 4 + 1024:
            return api_error(413, "too_long", f"The text must be at most {MAX_CHECK_CHARS} characters.")
        try:
            body = await request.json()
        except (ValueError, UnicodeDecodeError):
            return api_error(400, "bad_json", "The body is not valid JSON.")
        if not isinstance(body, dict) or not isinstance(body.get("text"), str):
            return api_error(400, "text_required", "Send JSON with a \"text\" string.")
        text = body["text"].replace("\x00", "").strip()
        lang = body.get("lang") if body.get("lang") in LANGS else "en"
        if not text:
            return api_error(400, "empty", "The text is empty.")
        if len(text) > MAX_CHECK_CHARS:
            return api_error(413, "too_long", f"The text must be at most {MAX_CHECK_CHARS} characters.")
        wait = per_ip.retry_after(client_ip(request)) or overall.retry_after("*")
        if wait:
            return api_error(429, "rate_limited", "Too many checks. Please wait a moment.",
                             {"Retry-After": str(wait)})
        verdict = await check(text, lang)
        return web.json_response(verdict, headers={"Cache-Control": "no-store"},
                                 dumps=lambda o: json.dumps(o, ensure_ascii=False))

    def current_feed():
        now = time.monotonic()
        if now - feed_cache["at"] > FEED_CACHE_SECONDS:
            feed_cache["entries"] = radar.feed(get_storage(), report_threshold)
            feed_cache["updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            feed_cache["at"] = now
        return feed_cache["entries"], feed_cache["updated"]

    feed_headers = {"Cache-Control": f"public, max-age={FEED_CACHE_SECONDS}", "Access-Control-Allow-Origin": "*"}

    async def feed_txt(request):
        entries, updated = current_feed()
        return web.Response(text=radar.feed_text(entries, updated), content_type="text/plain", charset="utf-8",
                            headers=feed_headers)

    async def feed_json(request):
        entries, updated = current_feed()
        data = {"name": "ScamGuard threat feed", "updated": updated, "count": len(entries),
                "description": "Fake and scam websites targeting people in Uzbekistan. 'auto' = flagged by the "
                               "ScamGuard bot, 'community' = reported by at least "
                               f"{report_threshold} different users. Automatic detections can be wrong.",
                "license": "CC BY 4.0", "source": GITHUB_URL, "indicators": entries}
        return web.json_response(data, headers=feed_headers, dumps=lambda o: json.dumps(o, ensure_ascii=False))

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

    app = web.Application(middlewares=[security_headers], client_max_size=MAX_CHECK_CHARS * 4 + 1024)
    app.router.add_get("/", index)
    app.router.add_get("/api/radar.json", api)
    app.router.add_post("/api/v1/check", check_message)
    app.router.add_get("/api/v1/feed.txt", feed_txt)
    app.router.add_get("/api/v1/feed.json", feed_json)
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
