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
    "elyurt": {"el-yurt.uz"},
}

# Brands that are real companies in other countries too: olx.kz, olx.ua, google.ru are theirs, not fakes.
INTERNATIONAL_BRANDS = {"olx", "google", "telegram", "instagram"}
# Service domains of those brands (APIs, files, CDNs) that don't carry the brand as a whole label.
BRAND_SERVICE_DOMAINS = {
    "googleapis.com", "googleusercontent.com", "gstatic.com", "googlevideo.com", "googledrive.com",
    "googlesyndication.com", "googletagmanager.com", "telegram-cdn.org", "cdninstagram.com", "olxgroup.com",
}
# Words scammers glue to a brand name in one label ("clickuz", "paymebonus", "uzumbank").
BAIT_AFFIXES = {
    "uz", "uzb", "bonus", "pay", "pul", "login", "verify", "secure", "karta", "card", "bank", "gift", "prize",
    "sovga", "sovg'a", "yutuq", "aksiya", "promo", "support", "help", "online", "app", "my", "web", "id",
    "auth", "official", "rasmiy", "oplata", "cash", "money", "kabinet", "cabinet", "account", "premium",
    "grant", "nafaqa", "kredit", "tolov", "qaytarish", "subsidiya", "yordam", "free", "bepul",
}

BRAND_LABELS = {"olx": "OLX", "mygov": "my.gov.uz", "elyurt": "El-yurt umidi", "tbcbank": "TBC Bank",
                "xalqbank": "Xalq banki", "uzcard": "Uzcard", "kapitalbank": "Kapitalbank"}

# Well-known Uzbek organisations: never flagged, and shown as a ✅ trust signal.
# (Kept separate from the brand list above: short names like "kun" would cause
# false lookalike matches if they were treated as brands.)
TRUSTED_DOMAINS = {
    # foundations, government, education
    "el-yurt.uz", "cbu.uz", "soliq.uz", "edu.uz", "it-park.uz", "uzedu.uz", "president.uz",
    "inha.uz", "wiut.uz", "tuit.uz", "nuu.uz", "tdiu.uz",
    # news media
    "kun.uz", "daryo.uz", "gazeta.uz", "uza.uz", "podrobno.uz", "spot.uz", "xabar.uz", "anhor.uz",
    # banks, payments, telecom, marketplaces
    "nbu.uz", "sqb.uz", "asakabank.uz", "aloqabank.uz", "ofb.uz", "davrbank.uz", "trastbank.uz",
    "infinbank.uz", "turonbank.uz", "ipakyulibank.uz", "beeline.uz", "ucell.uz", "mobi.uz",
    "uzmobile.uz", "hh.uz", "uztelecom.uz",
}
TRUSTED_SUFFIXES = (".gov.uz",)   # government domains (my.gov.uz, lex.gov.uz ...)

_ALL_OFFICIAL = {d for ds in OFFICIAL_DOMAINS.values() for d in ds} | TRUSTED_DOMAINS

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
      (?:[a-z0-9-]{1,63}\.){1,10}(?:[a-z]{2,24}|xn--[a-z0-9-]+)   # bare domains like click-bonus.xyz (bounded: linear time)
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
    official: bool = False   # the link goes to a known official site
    signals: list[str] = field(default_factory=list)

    def add(self, weight: float, reason: Reason, signal: str = "link") -> None:
        self.score = min(1.0, self.score + weight)
        self.reasons.append(reason)
        self.signals.append(signal)


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
    return any(host == d or host.endswith("." + d) for d in _ALL_OFFICIAL) or host.endswith(TRUSTED_SUFFIXES) \
        or host == "gov.uz"


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


def _is_brand_abroad(host: str) -> bool:
    """A brand's own site in another country or its service domain (olx.kz, google.ru, googleapis.com)."""
    domain = _registered_domain(host)
    label, tld = domain.split(".", 1)[0], domain.rsplit(".", 1)[-1]
    return domain in BRAND_SERVICE_DOMAINS or (label in INTERNATIONAL_BRANDS and tld not in SUSPICIOUS_TLDS)


def _words(host: str) -> list[str]:
    """Words a reader sees in a host name: every label and hyphen part, plus adjacent hyphen parts
    joined ("el-yurt-grant" -> el, yurt, grant, elyurt, yurtgrant)."""
    words = []
    for label in host.translate(_HOMOGLYPHS).replace("rn", "m").split("."):
        parts = [p for p in label.split("-") if p]
        words += parts
        words += [a + b for a, b in zip(parts, parts[1:])]
    return words


def _imitates(word: str, brand: str) -> bool:
    """The word is the brand, a one-letter typo of it, or the brand glued to bait words on either
    side ("clickuz", "paymebonus", "myclickpay", "clickuzbonus"). Other words that merely contain
    it (clickhouse, humor, paymentwall, googleapis) are different names, not imitations."""
    if word == brand:
        return True
    if len(brand) >= 5 and abs(len(word) - len(brand)) <= 1 and _levenshtein(word, brand) == 1:
        return True
    start = word.find(brand)
    while start != -1:                  # bait words before and/or after: clickuz, myclick, myclickpay
        before, after = word[:start], word[start + len(brand):]
        if (not before or _bait_words(before)) and (not after or _bait_words(after)):
            return True
        start = word.find(brand, start + 1)
    return False


def _bait_words(rest: str, parts: int = 3) -> bool:
    """`rest` is made of 1 to `parts` bait words glued together: "uzbonus" = uz + bonus,
    "bonusuz" = bonus + uz. Scammers stack them ("clickuzbonus"); a real name like "house"
    or "ntwall" is not made of bait words, so clickhouse and paymentwall still don't match."""
    if not rest:
        return False
    if rest in BAIT_AFFIXES:
        return True
    return parts > 1 and any(rest.startswith(a) and _bait_words(rest[len(a):], parts - 1) for a in BAIT_AFFIXES)


def _impersonated_brand(host: str) -> str | None:
    """Return the brand a non-official host seems to imitate, if any."""
    if _is_brand_abroad(host):
        return None
    words = _words(host)
    for brand in OFFICIAL_DOMAINS:
        if any(_imitates(w, brand) for w in words):
            return brand
    return None


def analyze_url(url: str) -> LinkReport:
    host = _host_of(url)
    report = LinkReport(url=url, host=host)
    if not host:
        return report

    if _is_official(host):
        report.official = True
        return report  # exact official domain or its subdomain

    brand = _impersonated_brand(host)
    if brand:
        real = ", ".join(sorted(OFFICIAL_DOMAINS[brand]))
        report.signals.append(f"brand:{brand}")
        brand = BRAND_LABELS.get(brand, brand.capitalize())
        report.add(0.75, Reason(
            f"«{host}» — {brand} saytiga o'xshatib yasalgan soxta sayt (asl manzil: {real})",
            f"'{host}' imitates {brand} (the real domain is {real})",
            f"«{host}» подделка под {brand} (настоящий сайт: {real})",
        ), "lookalike_site")

    if host.startswith("xn--") or ".xn--" in host:
        report.add(0.5, Reason(
            "Domen punycode (xn--) bilan yozilgan — harflar almashtirilgan bo'lishi mumkin",
            "Punycode (xn--) domain: letters may be swapped for lookalikes",
            "Домен в punycode (xn--): буквы могут быть подменены похожими",
        ), "punycode")
    if _is_ip(host):
        report.add(0.5, Reason(
            "Havola domen emas, to'g'ridan-to'g'ri IP manzilga olib boradi",
            "Link points to a raw IP address instead of a domain",
            "Ссылка ведёт на IP-адрес вместо обычного домена",
        ), "ip_link")
    if host in SHORTENERS:
        report.add(0.3, Reason(
            f"Qisqartirilgan havola ({host}) — asl manzil yashirilgan",
            f"Shortened link ({host}) hides the real destination",
            f"Сокращённая ссылка ({host}) скрывает настоящий адрес",
        ), "shortener")
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        report.add(0.3, Reason(
            f".{tld} domen zonasi firibgarlikda ko'p ishlatiladi",
            f"The .{tld} domain zone is common in scams",
            f"Доменная зона .{tld} часто используется мошенниками",
        ), "risky_tld")
    if host.count(".") >= 4:
        report.add(0.2, Reason(
            "Domen juda ko'p qismdan iborat (subdomenlar zanjiri)",
            "Unusually long chain of subdomains",
            "Подозрительно длинная цепочка поддоменов",
        ), "subdomains")
    if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
        report.add(0.5, Reason(
            "Havolada '@' belgisi bor — haqiqiy manzil yashirilgan",
            "'@' in the link hides the real destination",
            "Символ «@» в ссылке скрывает настоящий адрес",
        ), "at_trick")
    if re.search(r"(?i)\.apk(?:$|[?#])", url):
        report.add(0.8, Reason(
            "Havola .apk faylga olib boradi — telefoningizga zararli ilova o'rnatilishi mumkin",
            "Link downloads an .apk file that may install malware",
            "Ссылка скачивает .apk-файл, который может установить вирус",
        ), "apk_link")
    if re.search(r"(?i)(login|verify|secure|bonus|prize|sovg|yutuq|karta|card|oplata|pay)", host):
        report.add(0.2, Reason(
            "Domen nomida 'bonus/karta/to'lov/verify' kabi so'zlar bor",
            "Domain name contains bait words like bonus/card/pay/verify",
            "В названии домена слова-приманки: bonus/card/pay/verify",
        ), "bait_domain")
    if url.lower().startswith("http://") and report.score > 0:
        report.add(0.1, Reason(
            "Himoyalanmagan (http) ulanish",
            "Unencrypted (http) connection",
            "Незащищённое (http) соединение",
        ), "http")
    return report


def analyze_links(text: str) -> list[LinkReport]:
    return [analyze_url(u) for u in extract_urls(text)]
