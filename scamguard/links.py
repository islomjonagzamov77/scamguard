"""Link analysis: finds URLs in text and scores how suspicious each one is.

Everything here is offline and deterministic. Online reputation checks
(Google Safe Browsing, VirusTotal, domain age via WHOIS) belong in
`reputation.py` in phase 2 so the core stays fast and testable.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .reasons import Reason

# Brands scammers impersonate in Uzbekistan, mapped to their real domains.
OFFICIAL_DOMAINS: dict[str, set[str]] = {
    "click": {"click.uz"},
    "payme": {"payme.uz", "paycom.uz"},
    "uzum": {"uzum.uz", "uzumbank.uz"},
    "paynet": {"paynet.uz"},
    "humo": {"humocard.uz", "humo.uz"},
    "uzcard": {"uzcard.uz"},
    "olx": {"olx.uz"},
    "kapitalbank": {"kapitalbank.uz"},
    "anorbank": {"anorbank.uz"},
    "tbcbank": {"tbcbank.uz"},
    "hamkorbank": {"hamkorbank.uz"},
    "agrobank": {"agrobank.uz"},
    "ipotekabank": {"ipotekabank.uz"},
    "xalqbank": {"xb.uz"},
    "mygov": {"my.gov.uz"},
    "soliq": {"soliq.uz"},
    "telegram": {"telegram.org", "t.me", "telegram.me"},
    "instagram": {"instagram.com"},
    "google": {"google.com"},
}
_ALL_OFFICIAL = {d for ds in OFFICIAL_DOMAINS.values() for d in ds}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "cutt.ly", "clck.ru", "goo.su", "t.ly", "is.gd",
    "rb.gy", "shorturl.at", "ow.ly", "v.gd", "u.to", "tiny.cc", "rebrand.ly",
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "icu", "online", "site", "shop", "live", "buzz",
    "rest", "cfd", "sbs", "cyou", "monster", "quest", "fun", "vip", "win",
    "loan", "work", "gq", "tk", "ml", "cf", "ga",
}

# Digits and lookalike letters scammers swap into brand names.
_HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s"})

_URL_RE = re.compile(
    r"""(?xi)
    \b(
      (?:https?://|www\.)[^\s<>"']+                       # explicit URLs
      |
      (?:[a-z0-9-]+\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]+)      # bare domains like click-bonus.xyz
      (?:/[^\s<>"']*)?
    )""",
)
_TRAILING = ".,;:!?)]}»\"'"
# "report.pdf" is a file name, not a website. (.apk is handled by the rules instead.)
_FILE_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "jpg", "jpeg", "png",
    "gif", "heic", "mp3", "mp4", "mov", "zip", "rar", "7z", "apk", "exe", "py", "json",
}


@dataclass
class LinkReport:
    url: str
    host: str
    score: float = 0.0
    reasons: list[Reason] = field(default_factory=list)

    def add(self, weight: float, reason: Reason) -> None:
        self.score = min(1.0, self.score + weight)
        self.reasons.append(reason)


def extract_urls(text: str) -> list[str]:
    urls, seen = [], set()
    for match in _URL_RE.finditer(text):
        url = match.group(1).rstrip(_TRAILING)
        host = _host_of(url)
        # Skip things like "file.txt" or "v1.2" that only look like domains.
        if not host or "." not in host or host.split(".")[-1].isdigit() and not _is_ip(host):
            continue
        bare = not re.match(r"(?i)https?://|www\.", url)
        if bare and "/" not in url and host.rsplit(".", 1)[-1] in _FILE_EXTENSIONS:
            continue
        if url.lower() not in seen:
            seen.add(url.lower())
            urls.append(url)
    return urls


def _host_of(url: str) -> str:
    if not re.match(r"(?i)https?://", url):
        url = "http://" + url
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _registered_domain(host: str) -> str:
    """Rough eTLD+1 (good enough for .uz, .com, .co.uk style hosts)."""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "gov", "org", "net", "edu"}:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _is_official(host: str) -> bool:
    return any(host == d or host.endswith("." + d) for d in _ALL_OFFICIAL)


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _impersonated_brand(host: str) -> str | None:
    """Return the brand a non-official host seems to imitate, if any."""
    labels = re.split(r"[.-]", host.translate(_HOMOGLYPHS).replace("rn", "m"))
    joined = "".join(labels)
    for brand in OFFICIAL_DOMAINS:
        if brand in joined:
            return brand
        if len(brand) >= 5 and any(
            abs(len(lbl) - len(brand)) <= 1 and _levenshtein(lbl, brand) == 1 for lbl in labels
        ):
            return brand
    return None


def analyze_url(url: str) -> LinkReport:
    host = _host_of(url)
    report = LinkReport(url=url, host=host)
    if not host:
        return report

    if _is_official(host):
        return report  # exact official domain or its subdomain

    brand = _impersonated_brand(host)
    if brand:
        real = ", ".join(sorted(OFFICIAL_DOMAINS[brand]))
        report.add(0.75, Reason(
            f"'{host}' — {brand} ga o'xshatilgan soxta domen (asl manzil: {real})",
            f"'{host}' imitates {brand} (the real domain is {real})",
            f"«{host}» подделка под {brand} (настоящий сайт: {real})",
        ))

    if host.startswith("xn--") or ".xn--" in host:
        report.add(0.5, Reason(
            "Domen punycode (xn--) bilan yozilgan — harflar almashtirilgan bo'lishi mumkin",
            "Punycode (xn--) domain: letters may be swapped for lookalikes",
            "Домен в punycode (xn--): буквы могут быть подменены похожими",
        ))
    if _is_ip(host):
        report.add(0.5, Reason(
            "Havola domen emas, to'g'ridan-to'g'ri IP manzilga olib boradi",
            "Link points to a raw IP address instead of a domain",
            "Ссылка ведёт на IP-адрес вместо обычного домена",
        ))
    if host in SHORTENERS:
        report.add(0.3, Reason(
            f"Qisqartirilgan havola ({host}) — asl manzil yashirilgan",
            f"Shortened link ({host}) hides the real destination",
            f"Сокращённая ссылка ({host}) скрывает настоящий адрес",
        ))
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        report.add(0.3, Reason(
            f".{tld} domen zonasi firibgarlikda ko'p ishlatiladi",
            f"The .{tld} domain zone is common in scams",
            f"Доменная зона .{tld} часто используется мошенниками",
        ))
    if host.count(".") >= 4:
        report.add(0.2, Reason(
            "Domen juda ko'p qismdan iborat (subdomenlar zanjiri)",
            "Unusually long chain of subdomains",
            "Подозрительно длинная цепочка поддоменов",
        ))
    if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
        report.add(0.5, Reason(
            "Havolada '@' belgisi bor — haqiqiy manzil yashirilgan",
            "'@' in the link hides the real destination",
            "Символ «@» в ссылке скрывает настоящий адрес",
        ))
    if re.search(r"(?i)\.apk(?:$|[?#])", url):
        report.add(0.8, Reason(
            "Havola .apk faylga olib boradi — telefoningizga zararli ilova o'rnatilishi mumkin",
            "Link downloads an .apk file that may install malware",
            "Ссылка скачивает .apk-файл, который может установить вирус",
        ))
    if re.search(r"(?i)(login|verify|secure|bonus|prize|sovg|yutuq|karta|card|oplata|pay)", host):
        report.add(0.2, Reason(
            "Domen nomida 'bonus/karta/to'lov/verify' kabi so'zlar bor",
            "Domain name contains bait words like bonus/card/pay/verify",
            "В названии домена слова-приманки: bonus/card/pay/verify",
        ))
    if url.lower().startswith("http://") and report.score > 0:
        report.add(0.1, Reason(
            "Himoyalanmagan (http) ulanish",
            "Unencrypted (http) connection",
            "Незащищённое (http) соединение",
        ))
    return report


def analyze_links(text: str) -> list[LinkReport]:
    return [analyze_url(u) for u in extract_urls(text)]
