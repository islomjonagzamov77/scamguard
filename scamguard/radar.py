"""Scam Radar: public, aggregated view of what ScamGuard is catching.

Privacy rules (enforced here and in tests):
  * only counts, scam categories and fake-site domains are published;
  * never message text, user data, or phone numbers / Telegram accounts
    (publishing those could harm innocent people);
  * domains are "defanged" (example[.]com) so nobody clicks them by accident;
  * total counters appear only after SHOW_TOTALS_FROM checks.
"""

from __future__ import annotations

import os
from datetime import date, datetime, timedelta, timezone

from .i18n import SCAM_TYPES
from .links import SHORTENERS, _is_official, _registered_domain

SHOW_TOTALS_FROM = int(os.getenv("SCAMGUARD_SHOW_TOTALS_FROM", "100"))
TREND_DAYS = 30

# Public scam categories, checked in this order (most specific first).
CATEGORIES: list[tuple[str, set[str]]] = [
    ("grant", {"fake_admission", "brand:elyurt"}),
    ("apk", {"apk_file", "install_app", "apk_link", "file_program"}),
    ("marketplace", {"marketplace", "brand:olx"}),
    ("relative", {"relative_in_trouble"}),
    ("threat", {"threat_payment"}),
    ("bank", {"secret_code", "blocked_account", "bank_impersonation"}),
    ("prize", {"prize"}),
    ("money", {"easy_money"}),
    ("fee", {"advance_fee"}),
    ("fake_site", {"lookalike_site", "punycode", "ip_link", "at_trick", "risky_tld", "bait_domain",
                   "shortener", "subdomains"}),
    ("community", {"community"}),
]
CATEGORY_IDS = [c for c, _ in CATEGORIES] + ["other"]


def primary_category(signals) -> str:
    found = set(signals)
    for cat, names in CATEGORIES:
        if found & names:
            return cat
    return "other"


def scam_domains(links) -> list[str]:
    """Registered domains of clearly malicious links in a verdict (never official sites or shorteners)."""
    out = []
    for link in links:
        host = link.host.removeprefix("www.")
        if link.score >= 0.7 and host and not link.official and not _is_official(host) and host not in SHORTENERS:
            d = _registered_domain(host)
            if d and d not in out:
                out.append(d)
    return out


def defang(domain: str) -> str:
    return domain.replace(".", "[.]")


FEED_MAX = 500


def feed(storage, report_threshold: int, limit: int = FEED_MAX) -> list[dict]:
    """Threat-intelligence feed for banks, CERTs and filters: fake-site domains only.

    Unlike the page, the indicators are NOT defanged (machines read this, not people), and no
    phone numbers or Telegram accounts are ever included, same as the radar. A domain is listed
    when the bot itself flagged it as clearly malicious, or when enough different people reported it.
    """
    entries: dict[str, dict] = {}
    for domain, first_seen, last_seen, hits in storage.recent_domains(limit):
        if _is_official(domain) or domain in SHORTENERS:     # defence in depth: never list a real site
            continue
        entries[domain] = {"indicator": domain, "type": "domain", "first_seen": first_seen, "last_seen": last_seen,
                           "detections": hits, "reporters": 0, "source": "auto"}
    for preview, first_seen, reporters in storage.community_sites(report_threshold, limit):
        value = preview.lower().removeprefix("www.")
        host = value.split("/", 1)[0]
        if not value or _is_official(host) or value in SHORTENERS:
            continue
        # A page on a big platform (sites.google.com/view/…) is listed as that page, never the platform.
        kind = "url" if "/" in value else "domain"
        entry = entries.setdefault(value, {"indicator": value, "type": kind, "first_seen": first_seen,
                                           "last_seen": first_seen, "detections": 0, "reporters": 0,
                                           "source": "community"})
        entry["reporters"] = reporters
        entry["first_seen"] = min(entry["first_seen"], first_seen)
        if entry["source"] == "auto":
            entry["source"] = "both"
    return sorted(entries.values(), key=lambda e: (e["last_seen"], e["detections"] + e["reporters"]), reverse=True)[:limit]


def feed_text(entries: list[dict], updated: str) -> str:
    """Plain domain list (one per line, `#` comments): the format DNS filters such as Pi-hole,
    AdGuard and uBlock Origin import directly. Single pages on platforms are only in the JSON feed."""
    domains = [e for e in entries if e["type"] == "domain"]
    head = [
        "# ScamGuard threat feed: fake and scam websites targeting people in Uzbekistan",
        f"# Updated: {updated}",
        f"# Domains: {len(domains)}",
        "# Sources: detected by the ScamGuard bot (rules + link analysis + online reputation)",
        "#          or reported by at least 2 different users.",
        "# Automatic detections can be wrong. To report a false positive, open an issue on GitHub.",
        "# Do not open these sites.",
        "",
    ]
    return "\n".join(head + [e["indicator"] for e in domains]) + "\n"


def build(storage, report_threshold: int) -> dict:
    today = date.today()
    series = storage.daily_series(TREND_DAYS)
    since = (today - timedelta(days=TREND_DAYS - 1)).isoformat()
    stats = storage.stats(report_threshold)

    sites: dict[str, dict] = {}
    for domain, first_seen, last_seen, hits in storage.recent_domains(20):
        sites[domain] = {"site": defang(domain), "first_seen": first_seen, "last_seen": last_seen,
                         "hits": hits, "source": "auto"}
    for preview, first_seen, reporters in storage.community_sites(report_threshold, 20):
        entry = sites.setdefault(preview, {"site": defang(preview), "first_seen": first_seen,
                                           "last_seen": first_seen, "hits": 0, "source": "community"})
        entry["reporters"] = reporters
        if entry["source"] == "auto":
            entry["source"] = "both"
    site_list = sorted(sites.values(), key=lambda x: (x["last_seen"], x["hits"]), reverse=True)[:12]

    show_totals = stats["checks"] >= SHOW_TOTALS_FROM
    return {
        "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "since": storage.first_day(),
        "totals": {
            "checks": stats["checks"], "scams": stats["suspicious"] + stats["dangerous"],
            "blocked": stats["blocked"], "users": stats["users"],
        } if show_totals else None,
        "daily": [{"day": d, "checks": c, "scams": s} for d, c, s in series],
        "categories": [{"id": c, "count": n} for c, n in storage.category_counts(since) if n],
        "sites": site_list,
        "report_threshold": report_threshold,
        "guide": {lang: [{"id": i, "title": t, "how": h, "flag": f} for i, t, h, f in items]
                  for lang, items in SCAM_TYPES.items()},
    }
