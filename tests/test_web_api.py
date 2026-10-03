"""Public web API: the message checker (POST /api/v1/check) and the threat feed (/api/v1/feed.*).

The checker must give the same verdict as the bot, refuse abuse (wrong content type, huge texts,
too many requests) and never store or publish what people paste. The feed must list fake sites
only: never official sites, phone numbers or Telegram accounts.
"""

import asyncio
import json
import sqlite3
import sys
from pathlib import Path

from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).parent))
from test_bot import OTHER_USER, SCAM, USER, env, msg, press_report  # noqa: E402,F401

from scamguard import radar  # noqa: E402
from scamguard.web import server  # noqa: E402

GRANT_SCAM = "Tabriklaymiz! El-yurt umidi grantini yutdingiz, 24 soat ichida to'lang: el-yurt-grant.xyz"


def app_for(botmod, check=True):
    return server.build_app(lambda: botmod.storage, lambda: "scamguard_test_bot", 2,
                            check=botmod.web_check if check else None)


def call(app, requests):
    """Run (method, path, kwargs) requests against the app; returns [(status, headers, body bytes)]."""
    async def run():
        out = []
        async with TestClient(TestServer(app)) as client:
            for method, path, kwargs in requests:
                r = await client.request(method, path, **kwargs)
                out.append((r.status, dict(r.headers), await r.read()))
        return out
    return asyncio.run(run())


def check(text, lang="en", **extra):
    return ("POST", "/api/v1/check", {"json": {"text": text, "lang": lang}, **extra})


# ---------------------------------------------------------------- checker

def test_check_gives_the_bot_verdict(env):
    botmod, session, feed = env
    (status, headers, body), = call(app_for(botmod), [check(GRANT_SCAM)])
    data = json.loads(body)
    assert status == 200 and headers["Cache-Control"] == "no-store"
    assert data["level"] == "dangerous" and data["risk"] >= 65
    assert any("el-yurt.uz" in r for r in data["reasons"])          # explained, with the real domain
    assert data["advice"] and "<" not in data["title"] + "".join(data["reasons"])   # plain text, no HTML
    bot_result = botmod.evaluate_text(GRANT_SCAM)
    assert data["level"] == bot_result.level.value                 # same engine as the bot


def test_check_safe_message_and_languages(env):
    botmod, session, feed = env
    (_, _, en), (_, _, uz), (_, _, ru) = call(app_for(botmod), [
        check("Hi! Shall we meet at the library tomorrow at 10?"),
        check("Kartangiz bloklandi, SMS kodni yuboring", "uz"),
        check("Ваша карта заблокирована! Для разблокировки сообщите код из SMS.", "ru"),
    ])
    en, uz, ru = json.loads(en), json.loads(uz), json.loads(ru)
    assert en["level"] == "safe" and en["risk"] is None and en["reasons"] == []
    assert uz["level"] != "safe" and "SMS" in " ".join(uz["reasons"]) and "kod" in " ".join(uz["reasons"])
    assert ru["level"] != "safe" and "Пугают" in " ".join(ru["reasons"])


def test_check_feeds_the_radar_but_stores_no_text(env, tmp_path):
    botmod, session, feed = env
    secret = "Ona, bu men, yangi raqamim +998 90 555 44 33, kartamga 8600 1234 5678 9012 pul tashla tezda"
    call(app_for(botmod), [check(GRANT_SCAM, "uz"), check(secret, "uz")])
    data = radar.build(botmod.storage, 2)
    assert data["daily"][-1]["checks"] == 2 and data["sites"][0]["site"] == "el-yurt-grant[.]xyz"
    dump = "\n".join(sqlite3.connect(tmp_path / "t.db").iterdump())
    for leak in ("555 44", "5678", "8600", "yangi raqamim", "grantini yutdingiz"):
        assert leak not in dump, f"stored: {leak}"


def test_check_rejects_bad_requests(env):
    botmod, session, feed = env
    results = call(app_for(botmod), [
        ("POST", "/api/v1/check", {"data": "text=hello"}),                        # a cross-site HTML form
        ("POST", "/api/v1/check", {"data": "{not json", "headers": {"Content-Type": "application/json"}}),
        ("POST", "/api/v1/check", {"json": {"message": "hi"}}),
        ("POST", "/api/v1/check", {"json": ["hi"]}),
        check("   "),
        check("a" * 4001),
        ("GET", "/api/v1/check", {}),
    ])
    assert [r[0] for r in results] == [415, 400, 400, 400, 400, 413, 405]
    for status, headers, body in results[:6]:
        assert "error" in json.loads(body)


def test_check_unknown_language_falls_back_to_english(env):
    botmod, session, feed = env
    (status, _, body), = call(app_for(botmod), [check(GRANT_SCAM, "fr")])
    assert status == 200 and json.loads(body)["title"].startswith("Dangerous")


def test_check_is_rate_limited_per_visitor(env):
    botmod, session, feed = env
    limit, _ = server.CHECK_LIMIT_PER_IP
    a = {"headers": {"X-Real-IP": "203.0.113.5"}}
    b = {"headers": {"X-Real-IP": "203.0.113.6"}}
    results = call(app_for(botmod), [check(f"salom {i}", "uz", **a) for i in range(limit + 1)] + [check("salom", "uz", **b)])
    statuses = [r[0] for r in results]
    assert statuses[:limit] == [200] * limit
    assert statuses[limit] == 429 and int(results[limit][1]["Retry-After"]) >= 1
    assert statuses[-1] == 200                                    # another visitor is not affected


def test_rate_limiter_window_and_memory():
    lim = server.RateLimiter(2, 60, max_keys=10)
    assert lim.retry_after("x", 0) == 0 and lim.retry_after("x", 1) == 0
    assert lim.retry_after("x", 2) > 0
    assert lim.retry_after("x", 62) == 0                           # the window slid
    for i in range(50):
        lim.retry_after(f"ip{i}", 200 + i * 100)
    assert len(lim.hits) <= 11                                     # idle visitors are forgotten


def test_client_ip_cannot_be_faked_with_forwarded_for():
    class Req:
        def __init__(self, headers, remote="10.0.0.1"):
            self.headers, self.remote = headers, remote
    assert server.client_ip(Req({"X-Real-IP": "1.2.3.4"})) == "1.2.3.4"
    # a client can put anything first; the last entry is added by the proxy in front of us
    assert server.client_ip(Req({"X-Forwarded-For": "6.6.6.6, 1.2.3.4"})) == "1.2.3.4"
    assert server.client_ip(Req({})) == "10.0.0.1"


def test_checker_unavailable_without_engine(env):
    botmod, session, feed = env
    (status, _, body), = call(app_for(botmod, check=False), [check("hi")])
    assert status == 503 and json.loads(body)["error"] == "unavailable"


def test_page_has_the_checker_and_strict_csp(env):
    botmod, session, feed = env
    (status, headers, body), = call(app_for(botmod), [("GET", "/", {})])
    page = body.decode()
    assert status == 200 and 'id="chk-text"' in page and "/api/v1/check" in page and "/api/v1/feed.txt" in page
    csp = headers["Content-Security-Policy"]
    assert "connect-src 'self'" in csp and "script-src 'sha256-" in csp and "form-action 'none'" in csp


# ---------------------------------------------------------------- threat feed

def test_feed_lists_fake_sites_only(env):
    botmod, session, feed = env
    botmod.storage.set_lang(USER.id, "en")
    botmod.storage.set_lang(OTHER_USER.id, "en")
    for user in (USER, OTHER_USER):                          # 2 people report the same scam -> community entry
        feed({"message": msg(SCAM)})
        press_report(feed, session, user)
    feed({"message": msg(GRANT_SCAM + " Rasmiy sayt: el-yurt.uz, batafsil: bit.ly/abc")})
    (s1, h1, txt), (s2, h2, js) = call(app_for(botmod), [("GET", "/api/v1/feed.txt", {}), ("GET", "/api/v1/feed.json", {})])
    assert s1 == 200 and h1["Content-Type"].startswith("text/plain") and h1["Access-Control-Allow-Origin"] == "*"
    lines = [l for l in txt.decode().splitlines() if l and not l.startswith("#")]
    assert "el-yurt-grant.xyz" in lines and "olx-pay-uz.top" in lines      # machine-readable, not defanged
    assert "el-yurt.uz" not in lines and "bit.ly" not in lines             # never a real site or a shortener
    data = json.loads(js)
    by = {e["indicator"]: e for e in data["indicators"]}
    assert s2 == 200 and data["count"] == len(data["indicators"])
    assert by["el-yurt-grant.xyz"]["source"] == "auto" and by["el-yurt-grant.xyz"]["type"] == "domain"
    assert by["olx-pay-uz.top"]["reporters"] == 2 and by["olx-pay-uz.top"]["source"] == "both"
    body = txt.decode() + js.decode()
    for secret in ("998", "901112233", "8600", "@", str(USER.id)):
        assert secret not in body, f"leaked: {secret}"


def test_feed_text_keeps_platform_pages_out_of_the_domain_list():
    entries = [{"indicator": "sites.google.com/view/olx-pay", "type": "url"},
               {"indicator": "scam.xyz", "type": "domain"}]
    text = radar.feed_text(entries, "2026-10-03T00:00:00+00:00")
    assert "scam.xyz" in text and "sites.google.com" not in text and "# Domains: 1" in text
