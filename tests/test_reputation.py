"""Tests for online link reputation, with fake services (no network)."""

import asyncio
import time
from datetime import datetime, timedelta, timezone

import pytest

from scamguard import reputation as rep
from scamguard.links import analyze_links

NOW = datetime.now(timezone.utc)


def rdap(days_old: int) -> dict:
    created = (NOW - timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"events": [{"eventAction": "last changed", "eventDate": "2026-01-01T00:00:00Z"},
                       {"eventAction": "registration", "eventDate": created}]}


class FakeWeb:
    """Stands in for rep.fetch_json and records what would have been sent."""

    def __init__(self, answers: dict, delay: float = 0.0):
        self.answers, self.delay, self.calls = answers, delay, []

    async def __call__(self, url, *, method="GET", headers=None, payload=None):
        self.calls.append((url, payload))
        if self.delay:
            await asyncio.sleep(self.delay)
        for part, answer in self.answers.items():
            if part in url:
                return answer
        return None


@pytest.fixture()
def online(monkeypatch):
    monkeypatch.setenv("SCAMGUARD_ONLINE_CHECKS", "1")
    monkeypatch.setattr(rep, "_cache", rep._Cache())

    def install(answers, delay=0.0):
        web = FakeWeb(answers, delay)
        monkeypatch.setattr(rep, "fetch_json", web)
        return web
    return install


def run(coro):
    return asyncio.run(coro)


@pytest.mark.parametrize("host,domain", [
    ("secure.uzum-help.top", "uzum-help.top"),
    ("www.click-bonus.xyz", "click-bonus.xyz"),
    ("pay.bank.co.uz", "bank.co.uz"),
    ("olx-dostavka.site", "olx-dostavka.site"),
])
def test_registrable_domain(host, domain):
    assert rep.registrable_domain(host) == domain


def test_public_url_drops_personal_parts():
    assert rep.public_url("https://x.top/pay?card=8600123&name=Ali#top") == "https://x.top/pay"
    assert rep.public_url("x.top") == "http://x.top/"


@pytest.mark.parametrize("days,signal", [(2, "domain_very_new"), (20, "domain_new"), (400, None)])
def test_domain_age(days, signal):
    f = rep.age_finding(rep.registration_date(rdap(days)), NOW)
    assert (f.signals[0] if f.signals else None) == signal
    if days == 2:
        assert "2 day" in f.reasons[0].text("en")


def test_unknown_age_adds_nothing():
    assert rep.age_finding(None).evidence == 0
    assert rep.registration_date({}) is None


def test_safe_browsing_and_virustotal_parsing():
    sb = rep.safe_browsing_finding({"matches": [{"threatType": "SOCIAL_ENGINEERING",
                                                  "threat": {"url": "http://login.click-uz.top/"}}]})
    assert sb.evidence >= 0.9 and "phishing" in sb.reasons[0].text("en")
    assert sb.confirmed_domains == ["click-uz.top"]
    assert rep.safe_browsing_finding({}).evidence == 0

    def vt(n):
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": n, "harmless": 60, "undetected": 10}}}}
    assert rep.virustotal_finding(vt(0)).evidence == 0
    assert 0 < rep.virustotal_finding(vt(1)).evidence < 0.5                  # one engine can be wrong
    strong = rep.virustotal_finding(vt(7), "site", "bad.top")
    assert strong.evidence >= 0.9 and strong.confirmed_domains == ["bad.top"]
    assert "7 of 77" in strong.reasons[0].text("en")


def test_new_domain_found_and_official_sites_skipped(online):
    web = online({"rdap.org/domain/uzum-help.top": rdap(3)})
    links = analyze_links("Kiring: https://uzum-help.top/login?id=123 yoki https://click.uz")
    found = run(rep.check_links(links))
    assert "domain_very_new" in found.signals
    assert not any("click.uz" in url for url, _ in web.calls)             # official sites are never looked up


def test_keys_enable_google_and_virustotal_and_strip_queries(online, monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_KEY", "k1")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k2")
    web = online({
        "safebrowsing": {"matches": [{"threatType": "MALWARE", "threat": {"url": "http://evil.xyz/a"}}]},
        "virustotal.com/api/v3/domains/evil.xyz": {"data": {"attributes": {"last_analysis_stats": {"malicious": 5}}}},
        "rdap.org": rdap(900),
    })
    found = run(rep.check_links(analyze_links("http://evil.xyz/a?token=SECRET")))
    assert {"google_safe_browsing", "virustotal"} <= set(found.signals)
    sent = str([payload for _, payload in web.calls])
    assert "SECRET" not in sent and "evil.xyz/a" in sent


def test_no_keys_means_no_google_or_virustotal_calls(online):
    web = online({"rdap.org": rdap(900)})
    run(rep.check_links(analyze_links("http://evil.xyz/a")))
    assert all("rdap.org" in url for url, _ in web.calls)


def test_answers_are_cached_but_failures_are_not(online):
    web = online({"rdap.org/domain/new-site.top": rdap(1)})
    links = analyze_links("new-site.top va boshqa-sayt.top")
    run(rep.check_links(links))
    first = len(web.calls)
    run(rep.check_links(links))
    asked_again = [url for url, _ in web.calls[first:]]
    assert asked_again == ["https://rdap.org/domain/boshqa-sayt.top"]   # only the failed one is retried


def test_slow_services_never_delay_the_answer(online, monkeypatch):
    monkeypatch.setattr(rep, "TIMEOUT_S", 0.2)
    online({"rdap.org": rdap(1)}, delay=5)
    start = time.time()
    found = run(rep.check_links(analyze_links("slow-site.top")))
    assert time.time() - start < 1.5 and found.evidence == 0


def test_switched_off(online, monkeypatch):
    monkeypatch.setenv("SCAMGUARD_ONLINE_CHECKS", "0")
    web = online({"rdap.org": rdap(1)})
    assert run(rep.check_links(analyze_links("any-site.top"))).evidence == 0
    assert web.calls == []


def test_app_hash_lookup(online, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
    online({"virustotal.com/api/v3/files/abc": {"data": {"attributes": {"last_analysis_stats": {"malicious": 30, "undetected": 40}}}}})
    found = run(rep.check_file_hash("abc"))
    assert found.evidence >= 0.9 and "this app" in found.reasons[0].text("en")
