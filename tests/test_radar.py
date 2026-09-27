"""Scam Radar: categories, fake-site recording, the public JSON feed and — above all — privacy."""

import asyncio
import json
import sys
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

sys.path.insert(0, str(Path(__file__).parent))
from test_bot import GROUP, OTHER_USER, SCAM, USER, env, msg, press_report  # noqa: E402,F401

from scamguard import radar  # noqa: E402
from scamguard.analyzer import analyze  # noqa: E402
from scamguard.web import server  # noqa: E402


def get(make_app, path):
    async def run():
        async with TestClient(TestServer(make_app())) as client:
            r = await client.get(path)
            return r.status, dict(r.headers), await r.read()
    return asyncio.run(run())


@pytest.mark.parametrize("text,category", [
    ("Tabriklaymiz! El-yurt umidi grantini yutdingiz, to'lang: el-yurt-grant.xyz", "grant"),
    ("Kartangiz bloklandi, SMS kodni yuboring", "bank"),
    ("OLX: pulni o'tkazib berdim, to'lovni qabul qiling olx-pay.top", "marketplace"),
    ("Rasmlarni ko'ring: foto.apk", "apk"),
    ("Ona, bu men, yangi raqamimdan yozyapman, tezda pul tashla", "relative"),
    ("Click bonus: c1ick-bonus.online", "fake_site"),
])
def test_primary_category(text, category):
    assert radar.primary_category(analyze(text).signals) == category


def test_only_malicious_domains_are_recorded():
    v = analyze("Tabriklaymiz! yutdingiz: el-yurt-grant.xyz yoki bit.ly/abc, rasmiy sayt el-yurt.uz")
    assert radar.scam_domains(v.links) == ["el-yurt-grant.xyz"]


def test_bot_checks_feed_the_radar(env):
    botmod, session, feed = env
    botmod.storage.set_lang(USER.id, "uz")
    feed({"message": msg("Tabriklaymiz! El-yurt umidi grantini yutdingiz, 24 soat ichida to'lang: el-yurt-grant.xyz")})
    feed({"message": msg("Salom, ertaga uchrashamizmi?")})
    data = radar.build(botmod.storage, 2)
    assert data["daily"][-1] == {"day": data["daily"][-1]["day"], "checks": 2, "scams": 1}
    assert data["categories"] == [{"id": "grant", "count": 1}]
    assert data["sites"][0]["site"] == "el-yurt-grant[.]xyz"          # defanged
    assert data["totals"] is None                                    # hidden until 100 checks


def test_privacy_nothing_personal_is_published(env):
    botmod, session, feed = env
    botmod.storage.set_lang(USER.id, "en")
    botmod.storage.set_lang(OTHER_USER.id, "en")
    for user in (USER, OTHER_USER):                    # two people report the same scam -> it is "blocked"
        feed({"message": msg(SCAM)})
        press_report(feed, session, user)
    feed({"message": msg("Hi mom it's me, my new number, send money to 8600 1234 5678 9012, call +998 90 555 44 33")})
    body = json.dumps(radar.build(botmod.storage, 2), ensure_ascii=False)
    for secret in ("998", "90 111", "901112233", "8600", "5678", "555 44", "Pulni o'tkazib", "mom", str(USER.id)):
        assert secret not in body, f"leaked: {secret}"
    assert "olx-pay-uz[.]top" in body                                # the fake site is shown, defanged


def test_totals_appear_after_threshold(env, monkeypatch):
    botmod, session, feed = env
    monkeypatch.setattr(radar, "SHOW_TOTALS_FROM", 3)
    for _ in range(3):
        botmod.storage.record_check("safe")
    assert radar.build(botmod.storage, 2)["totals"]["checks"] == 3


def test_web_routes_and_security_headers(env):
    botmod, session, feed = env
    app = lambda: server.build_app(lambda: botmod.storage, lambda: "scamguard_uzbbot", 2)  # noqa: E731
    status, headers, body = get(app, "/")
    page = body.decode()
    assert status == 200 and "https://t.me/scamguard_uzbbot" in page and "{{" not in page
    csp = headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "script-src 'sha256-" in csp and "unsafe-inline" not in csp.split("style-src")[0]
    assert "frame-ancestors https://web.telegram.org https://*.telegram.org" in csp   # only Telegram may embed it
    assert headers["X-Content-Type-Options"] == "nosniff"
    status, headers, body = get(app, "/api/radar.json")
    assert status == 200 and headers["Content-Type"].startswith("application/json")
    assert set(json.loads(body)) >= {"daily", "categories", "sites", "guide", "totals", "updated"}
    assert get(app, "/healthz")[0] == 200 and get(app, "/favicon.svg")[0] == 200
