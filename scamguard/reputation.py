"""Online link reputation: how old a domain is, and whether security services already know it.

These checks need the internet, so they live outside the offline analyzer and only add evidence:
  * Domain age (RDAP, free, no key): scam sites are usually days or weeks old.
  * Google Safe Browsing (free key: GOOGLE_SAFE_BROWSING_KEY): Google's list of phishing and malware sites.
  * VirusTotal (free key: VIRUSTOTAL_API_KEY): what dozens of antivirus engines say about the domain
    or about an app's SHA-256.

Privacy: only the link is sent, never the message. The part after "?" and "#" is removed first,
because it can carry personal tokens. VirusTotal gets only the domain name or a file hash.

Every check has a short timeout and a cache, and any failure is silently skipped:
a slow service must never delay or break the bot's answer.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .reasons import Reason

log = logging.getLogger(__name__)

TIMEOUT_S = 4.0                  # all checks together
CACHE_TTL_S = 6 * 3600
CACHE_MAX = 5000
NEW_DOMAIN_DAYS = 30             # younger than this is a red flag
VERY_NEW_DOMAIN_DAYS = 7
RDAP_URL = "https://rdap.org/domain/{}"
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={}"
VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{}"
VT_FILE_URL = "https://www.virustotal.com/api/v3/files/{}"

# second-level labels under which people register names (bank.co.uz -> bank.co.uz, not co.uz)
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac", "biz"}


def enabled() -> bool:
    return os.getenv("SCAMGUARD_ONLINE_CHECKS", "1") != "0"


@dataclass
class Finding:
    """What the online services said about one link or file. `evidence` is 0..1."""
    evidence: float = 0.0
    reasons: list[Reason] = field(default_factory=list)
    signals: list[str] = field(default_factory=list)
    confirmed_domains: list[str] = field(default_factory=list)   # flagged by Google or by 2+ antivirus engines

    def add(self, evidence: float, reason: Reason, signal: str) -> None:
        self.evidence = 1 - (1 - self.evidence) * (1 - evidence)
        self.reasons.append(reason)
        self.signals.append(signal)

    def merge(self, other: "Finding") -> None:
        self.evidence = 1 - (1 - self.evidence) * (1 - other.evidence)
        self.reasons += other.reasons
        self.signals += other.signals
        self.confirmed_domains += [d for d in other.confirmed_domains if d not in self.confirmed_domains]


# ---------- small helpers (pure, tested offline) ----------

def registrable_domain(host: str) -> str:
    host = host.lower().strip(".").removeprefix("www.")
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def public_url(url: str) -> str:
    """The link without query string and fragment (they can carry personal tokens)."""
    if "://" not in url:
        url = "http://" + url
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path or '/'}"


def registration_date(rdap: dict) -> datetime | None:
    for event in rdap.get("events") or []:
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            try:
                return datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                return None
    return None


def age_finding(created: datetime | None, now: datetime | None = None) -> Finding:
    f = Finding()
    if created is None:
        return f
    now = now or datetime.now(timezone.utc)
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    days = max(0, (now - created).days)
    if days < VERY_NEW_DOMAIN_DAYS:
        f.add(0.6, Reason(
            f"Sayt atigi {days} kun oldin ochilgan — firibgarlar saytlari odatda bir necha kun yashaydi",
            f"The site was registered only {days} day(s) ago — scam sites usually live for a few days",
            f"Сайт зарегистрирован всего {days} дн. назад — мошеннические сайты обычно живут несколько дней",
        ), "domain_very_new")
    elif days < NEW_DOMAIN_DAYS:
        f.add(0.4, Reason(
            f"Sayt yaqinda ochilgan ({days} kun oldin)",
            f"The site is very new (registered {days} days ago)",
            f"Сайт совсем новый (зарегистрирован {days} дн. назад)",
        ), "domain_new")
    return f


_THREAT_NAMES = {
    "SOCIAL_ENGINEERING": ("fishing (soxta sahifa)", "phishing (a fake page)", "фишинг (поддельная страница)"),
    "MALWARE": ("zararli dastur", "malware", "вредоносные программы"),
    "UNWANTED_SOFTWARE": ("keraksiz dastur", "unwanted software", "нежелательные программы"),
    "POTENTIALLY_HARMFUL_APPLICATION": ("xavfli ilova", "a harmful app", "вредоносное приложение"),
}


def safe_browsing_finding(response: dict) -> Finding:
    f = Finding()
    threats = sorted({m.get("threatType", "") for m in response.get("matches") or []})
    if threats:
        names = [_THREAT_NAMES.get(t, (t, t, t)) for t in threats]
        uz, en, ru = (", ".join(n[i] for n in names) for i in range(3))
        f.add(0.95, Reason(
            f"Google Safe Browsing bu saytni xavfli deb biladi: {uz}",
            f"Google Safe Browsing lists this site as dangerous: {en}",
            f"Google Safe Browsing считает этот сайт опасным: {ru}",
        ), "google_safe_browsing")
        for m in response.get("matches") or []:
            host = urlsplit((m.get("threat") or {}).get("url", "")).hostname
            if host and registrable_domain(host) not in f.confirmed_domains:
                f.confirmed_domains.append(registrable_domain(host))
    return f


def virustotal_finding(response: dict, what: str = "site", domain: str = "") -> Finding:
    f = Finding()
    stats = (((response.get("data") or {}).get("attributes") or {}).get("last_analysis_stats")) or {}
    bad = int(stats.get("malicious", 0))
    if bad <= 0:
        return f
    total = sum(int(v) for v in stats.values() if isinstance(v, int))
    item = {"site": ("saytni", "this site", "этот сайт"), "file": ("bu ilovani", "this app", "это приложение")}[what]
    f.add(0.95 if bad >= 2 else 0.4, Reason(
        f"VirusTotal: {total} ta antivirusdan {bad} tasi {item[0]} xavfli deb topgan",
        f"VirusTotal: {bad} of {total} antivirus engines flag {item[1]} as malicious",
        f"VirusTotal: {bad} из {total} антивирусов считают {item[2]} вредоносным",
    ), "virustotal")
    if domain and bad >= 2:
        f.confirmed_domains.append(domain)
    return f


# ---------- network ----------

class _Cache:
    def __init__(self):
        self.items: OrderedDict[str, tuple[float, Finding]] = OrderedDict()

    def get(self, key: str) -> Finding | None:
        hit = self.items.get(key)
        if hit and time.monotonic() - hit[0] < CACHE_TTL_S:
            self.items.move_to_end(key)
            return hit[1]
        return None

    def put(self, key: str, value: Finding) -> None:
        self.items[key] = (time.monotonic(), value)
        self.items.move_to_end(key)
        while len(self.items) > CACHE_MAX:
            self.items.popitem(last=False)


_cache = _Cache()


async def fetch_json(url: str, *, method: str = "GET", headers: dict | None = None, payload: dict | None = None) -> dict | None:
    """HTTP JSON request. Returns None on any problem (tests replace this function)."""
    import aiohttp

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=TIMEOUT_S)) as session:
            async with session.request(method, url, headers=headers, json=payload) as resp:
                if resp.status != 200:
                    return None
                return await resp.json(content_type=None)
    except Exception as e:                       # network errors, timeouts, bad JSON
        log.info("reputation lookup failed for %s: %s", url.split("?")[0], e)
        return None


async def _domain_age(domain: str) -> Finding | None:
    """None when the lookup failed (so the miss is not cached)."""
    data = await fetch_json(RDAP_URL.format(domain), headers={"Accept": "application/rdap+json"})
    return age_finding(registration_date(data)) if data else None


async def _safe_browsing(urls: list[str]) -> Finding:
    key = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "").strip()
    if not key or not urls:
        return Finding()
    body = {
        "client": {"clientId": "scamguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": list(_THREAT_NAMES),
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }
    data = await fetch_json(SAFE_BROWSING_URL.format(key), method="POST", payload=body)
    return safe_browsing_finding(data or {})


async def _virustotal_domain(domain: str) -> Finding:
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        return Finding()
    data = await fetch_json(VT_DOMAIN_URL.format(domain), headers={"x-apikey": key})
    return virustotal_finding(data or {}, "site", domain)


async def check_links(links) -> Finding:
    """Online evidence about the non-official links of a message (LinkReport objects)."""
    result = Finding()
    if not enabled():
        return result
    urls, domains = [], []
    for link in links:
        if link.official or not link.host or is_ip(link.host):
            continue
        urls.append(public_url(link.url))
        d = registrable_domain(link.host)
        if d not in domains:
            domains.append(d)
    urls, domains = urls[:5], domains[:3]
    if not urls:
        return result

    async def per_domain(d: str) -> Finding:
        cached = _cache.get("d:" + d)
        if cached is not None:
            return cached
        merged = Finding()
        age, vt = await asyncio.gather(_domain_age(d), _virustotal_domain(d))
        for part in (age, vt):
            if part is not None:
                merged.merge(part)
        if age is not None:                      # cache only answers, never failures
            _cache.put("d:" + d, merged)
        return merged

    try:
        found = await asyncio.wait_for(
            asyncio.gather(_safe_browsing(urls), *(per_domain(d) for d in domains)), TIMEOUT_S + 1)
    except asyncio.TimeoutError:
        return result
    for f in found:
        result.merge(f)
    return result


async def check_file_hash(sha256: str) -> Finding:
    """What VirusTotal knows about an app by its SHA-256 (the file itself is never uploaded)."""
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not enabled() or not key:
        return Finding()
    cached = _cache.get("f:" + sha256)
    if cached is not None:
        return cached
    data = await fetch_json(VT_FILE_URL.format(sha256), headers={"x-apikey": key})
    found = virustotal_finding(data or {}, "file")
    _cache.put("f:" + sha256, found)
    return found
