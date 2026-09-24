"""Community blocklist: extract scam indicators (sites, phone numbers, Telegram accounts).

Users report scams with the 🚩 button (or /report in groups). An indicator is
only used to warn others after REPORT_THRESHOLD *different* people reported it,
so one person cannot get an innocent number or account flagged on their own.

Indicators are stored as salted fingerprints (see Storage), with a masked
preview for display, so a database leak does not expose phone numbers.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .links import SHORTENERS, _host_of, _is_official, _registered_domain, extract_urls

REPORT_THRESHOLD = int(os.getenv("SCAMGUARD_REPORT_THRESHOLD", "2"))

# Big platforms: never blocklist the whole domain (a scam page there is reported by full URL instead).
PLATFORMS = {
    "t.me", "telegram.me", "telegram.org", "google.com", "youtube.com", "youtu.be", "instagram.com",
    "facebook.com", "fb.com", "tiktok.com", "x.com", "twitter.com", "vk.com", "ok.ru", "whatsapp.com",
    "wa.me", "apple.com", "microsoft.com", "github.com", "wikipedia.org", "gov.uz", "uz", "yandex.ru",
    "mail.ru", "docs.google.com", "drive.google.com", "forms.gle",
}
TG_RESERVED = {"joinchat", "share", "addstickers", "addemoji", "proxy", "socks", "iv", "c", "s", "login", "setlanguage"}

_TG_RE = re.compile(r"(?:(?<![\w.])@|(?:https?://)?(?:t|telegram)\.me/)([A-Za-z][A-Za-z0-9_]{3,31})\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?\s?998[\s-]?)?\(?([2-9]\d)\)?[\s-]?(\d{3})[\s-]?(\d{2})[\s-]?(\d{2})(?!\d)")
_UZ_MOBILE = {"20", "33", "50", "55", "61", "62", "65", "66", "67", "69", "70", "71", "72", "73", "74", "75",
              "76", "77", "78", "79", "88", "90", "91", "93", "94", "95", "97", "98", "99"}


@dataclass(frozen=True)
class Indicator:
    kind: str      # "site" | "phone" | "tg"
    value: str     # normalized, used for the fingerprint only
    preview: str   # safe to show


def _mask(s: str, keep_start: int, keep_end: int = 0) -> str:
    if len(s) <= keep_start + keep_end:
        return s
    return s[:keep_start] + "***" + (s[-keep_end:] if keep_end else "")


def extract(text: str, forward: tuple[str, str] | None = None, ignore_usernames: set[str] = frozenset()) -> list[Indicator]:
    """Find reportable indicators in a message. `forward` = (stable id, display name) of the original sender."""
    found: dict[tuple[str, str], Indicator] = {}

    for url in extract_urls(text):
        host = _host_of(url)
        if not host:
            continue
        # Platforms host other people's pages: report the exact page, never the whole platform.
        if host in SHORTENERS or host in PLATFORMS or _registered_domain(host) in PLATFORMS \
                or host.removeprefix("www.") in PLATFORMS:
            path = url.split(host, 1)[-1].split("?")[0].rstrip("/")
            if len(path) > 1 and not host.endswith(("t.me", "telegram.me")):
                value = (host.removeprefix("www.") + path).lower()
                found[("site", value)] = Indicator("site", value, value)
            continue
        if _is_official(host):
            continue
        domain = _registered_domain(host)
        found[("site", domain)] = Indicator("site", domain, domain)

    for m in _TG_RE.finditer(text):
        name = m.group(1).lower()
        if name in TG_RESERVED or name in ignore_usernames or name.endswith("bot") and name in ignore_usernames:
            continue
        found[("tg", "@" + name)] = Indicator("tg", "@" + name, "@" + _mask(name, 3))

    for m in _PHONE_RE.finditer(text):
        code = m.group(1)
        if code not in _UZ_MOBILE:
            continue
        number = "+998" + "".join(m.groups())
        found[("phone", number)] = Indicator("phone", number, _mask(number, 6, 2))

    if forward:
        fid, display = forward
        if display.startswith("@"):
            preview = "@" + _mask(display[1:].lower(), 3)
        else:
            preview = _mask(display, 3) if display else "Telegram"
        found[("tg", fid)] = Indicator("tg", fid, preview)

    return list(found.values())
