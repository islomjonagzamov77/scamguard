"""Static APK inspection: what an Android app would be allowed to do, read from its manifest.

The bot downloads an .apk into memory, reads AndroidManifest.xml and throws the bytes away.
Nothing is installed, executed or written to disk.

Why a small hand-written reader instead of a big library: Android banking trojans often
corrupt their own APK on purpose (fake "encrypted" flags, unknown compression methods,
wrong chunk sizes) so that analysis tools crash while Android still installs the app.
This reader is tolerant in the same places Android is, and it has hard limits on sizes
and loop counts so a hostile file can't make the bot hang or eat memory.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from dataclasses import dataclass, field

from .reasons import Reason

MAX_APK_BYTES = 20 * 1024 * 1024        # Telegram bots can't download more than 20 MB anyway
MAX_MANIFEST_BYTES = 2 * 1024 * 1024     # real manifests are a few KB; this stops zip bombs
MAX_STRINGS = 200_000
MAX_CHUNKS = 500_000

ANDROID_NS_NAME = 0x01010003             # resource id of android:name
ANDROID_NS_PERMISSION = 0x01010006       # resource id of android:permission
ATTR_NAME_IDS = {ANDROID_NS_NAME: "name", ANDROID_NS_PERMISSION: "permission"}


class NotAnApk(ValueError):
    """The bytes are not an Android app (no readable AndroidManifest.xml)."""


@dataclass
class ApkReport:
    sha256: str
    size: int
    package: str = ""
    permissions: set[str] = field(default_factory=set)
    services: set[str] = field(default_factory=set)       # permissions that protect services (e.g. accessibility)
    actions: set[str] = field(default_factory=set)        # intent-filter actions
    categories: set[str] = field(default_factory=set)     # intent-filter categories
    tolerated: list[str] = field(default_factory=list)    # tricks we noticed and read around

    @property
    def has_launcher_icon(self) -> bool:
        return "android.intent.category.LAUNCHER" in self.categories


# ---------------------------------------------------------------------------
# 1. Getting AndroidManifest.xml out of the zip, tolerating anti-analysis tricks
# ---------------------------------------------------------------------------

_LOCAL_SIG = b"PK\x03\x04"
_CENTRAL_SIG = b"PK\x01\x02"
_EOCD_SIG = b"PK\x05\x06"


def _inflate(raw: bytes) -> bytes:
    d = zlib.decompressobj(-15)
    out = d.decompress(raw, MAX_MANIFEST_BYTES)
    if d.unconsumed_tail:
        raise NotAnApk("manifest too large")
    return out


def _decode_entry(raw: bytes, method: int, report: ApkReport) -> bytes:
    """Android only knows 'stored' (0) and 'deflate' (8). Malware writes other numbers
    to break tools; Android then treats the entry as deflated or stored, so we try both."""
    if method == 8:
        return _inflate(raw)
    if method != 0:
        report.tolerated.append(f"fake compression method {method}")
        try:
            return _inflate(raw)
        except zlib.error:
            pass
    return raw[:MAX_MANIFEST_BYTES]


def _manifest_from_central_directory(data: bytes, report: ApkReport) -> bytes | None:
    eocd = data.rfind(_EOCD_SIG, max(0, len(data) - 65_557))
    if eocd < 0 or eocd + 22 > len(data):
        return None
    entries, cd_size, cd_offset = struct.unpack_from("<HII", data, eocd + 10)
    pos = cd_offset
    for _ in range(min(entries, 65_535)):
        if data[pos:pos + 4] != _CENTRAL_SIG:
            return None
        flags, method = struct.unpack_from("<HH", data, pos + 8)
        csize, usize, nlen, xlen, clen = struct.unpack_from("<IIHHH", data, pos + 20)
        local = struct.unpack_from("<I", data, pos + 42)[0]
        name = data[pos + 46:pos + 46 + nlen]
        pos += 46 + nlen + xlen + clen
        if name != b"AndroidManifest.xml":
            continue
        if flags & 1:
            report.tolerated.append("fake 'encrypted' flag")      # Android ignores it
        if data[local:local + 4] != _LOCAL_SIG:
            return None
        lnlen, lxlen = struct.unpack_from("<HH", data, local + 26)
        start = local + 30 + lnlen + lxlen
        if usize and csize == usize and method not in (0, 8):
            report.tolerated.append(f"fake compression method {method}")
            method = 0                                             # sizes say it is stored
        return _decode_entry(data[start:start + (csize or MAX_MANIFEST_BYTES)], method, report)
    return None


def _manifest_from_local_headers(data: bytes, report: ApkReport) -> bytes | None:
    """Fallback when the central directory is damaged: scan local file headers."""
    pos = data.find(_LOCAL_SIG)
    for _ in range(100_000):
        if pos < 0:
            return None
        if pos + 30 > len(data):
            return None
        method, = struct.unpack_from("<H", data, pos + 8)
        csize, usize, nlen, xlen = struct.unpack_from("<IIHH", data, pos + 18)
        name = data[pos + 30:pos + 30 + nlen]
        start = pos + 30 + nlen + xlen
        if name == b"AndroidManifest.xml":
            report.tolerated.append("damaged zip directory")
            return _decode_entry(data[start:start + (csize or MAX_MANIFEST_BYTES)], method, report)
        pos = data.find(_LOCAL_SIG, pos + 4)
    return None


def extract_manifest(data: bytes, report: ApkReport) -> bytes:
    try:
        manifest = _manifest_from_central_directory(data, report)
    except (struct.error, zlib.error):
        manifest = None
    if manifest is None:
        try:
            manifest = _manifest_from_local_headers(data, report)
        except (struct.error, zlib.error):
            manifest = None
    if not manifest:
        raise NotAnApk("no AndroidManifest.xml")
    return manifest


# ---------------------------------------------------------------------------
# 2. Reading the binary XML (AXML) manifest
# ---------------------------------------------------------------------------

def _read_string_pool(buf: bytes, start: int, header_size: int) -> list[str]:
    count, _styles, flags, strings_start = struct.unpack_from("<IIII", buf, start + 8)
    count = min(count, MAX_STRINGS)
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from(f"<{count}I", buf, start + header_size)
    base = start + strings_start
    out = []
    for off in offsets:
        p = base + off
        try:
            if utf8:
                p += 2 if buf[p] & 0x80 else 1                      # length in UTF-16 units
                n = buf[p]
                if n & 0x80:
                    n = ((n & 0x7F) << 8) | buf[p + 1]
                    p += 1
                p += 1
                out.append(buf[p:p + n].decode("utf-8", "replace"))
            else:
                n, = struct.unpack_from("<H", buf, p)
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", buf, p + 2)[0]
                    p += 2
                p += 2
                out.append(buf[p:p + 2 * n].decode("utf-16-le", "replace"))
        except (IndexError, struct.error):
            out.append("")
    return out


def parse_manifest(buf: bytes, report: ApkReport) -> None:
    """Walk the AXML chunks and collect permissions, services, intent actions and categories."""
    if len(buf) < 8:
        raise NotAnApk("manifest too small")
    strings: list[str] = []
    res_ids: list[int] = []
    stack: list[str] = []
    pos, chunks = 8, 0                                           # skip the file header
    while pos + 8 <= len(buf) and chunks < MAX_CHUNKS:
        chunks += 1
        ctype, hsize, csize = struct.unpack_from("<HHI", buf, pos)
        if csize < 8:                                            # broken size: never loop forever
            report.tolerated.append("broken chunk size")
            break
        if ctype == 0x0001 and not strings:                      # string pool
            strings = _read_string_pool(buf, pos, hsize)
        elif ctype == 0x0180:                                    # resource ids of attribute names
            n = (csize - hsize) // 4
            res_ids = list(struct.unpack_from(f"<{n}I", buf, pos + hsize))
        elif ctype == 0x0102:                                    # start of an element
            _, name_i, attr_start, attr_size, attr_count = struct.unpack_from("<IIHHH", buf, pos + 16)
            tag = strings[name_i] if name_i < len(strings) else ""
            attrs = {}
            a = pos + 16 + attr_start
            for _ in range(min(attr_count, 1000)):
                _ns, aname_i, raw_i, _sz, _r, dtype, data = struct.unpack_from("<IIIHBBI", buf, a)
                a += attr_size or 20
                key = ATTR_NAME_IDS.get(res_ids[aname_i]) if aname_i < len(res_ids) else None
                if key is None and aname_i < len(strings):
                    key = strings[aname_i]
                value = strings[raw_i] if raw_i < len(strings) else (strings[data] if dtype == 3 and data < len(strings) else "")
                if key:
                    attrs[key] = value
                if key == "package" and tag == "manifest":
                    report.package = value
            _collect(tag, attrs, stack, report)
            stack.append(tag)
        elif ctype == 0x0103 and stack:                          # end of an element
            stack.pop()
        pos += csize


def _collect(tag: str, attrs: dict, stack: list[str], report: ApkReport) -> None:
    name = attrs.get("name", "")
    if tag in ("uses-permission", "uses-permission-sdk-23") and name:
        report.permissions.add(name)
    elif tag in ("service", "receiver", "activity", "activity-alias") and attrs.get("permission"):
        report.services.add(attrs["permission"])
    elif tag == "action" and "intent-filter" in stack and name:
        report.actions.add(name)
    elif tag == "category" and "intent-filter" in stack and name:
        report.categories.add(name)


def inspect_apk(data: bytes) -> ApkReport:
    """Read what an APK may do. Raises NotAnApk when it isn't a readable Android app."""
    if len(data) > MAX_APK_BYTES:
        raise NotAnApk("file too large")
    report = ApkReport(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
    manifest = extract_manifest(data, report)
    try:
        parse_manifest(manifest, report)
    except (struct.error, IndexError) as e:
        if not (report.permissions or report.actions):
            raise NotAnApk(f"unreadable manifest: {e}") from e
        report.tolerated.append("truncated manifest")
    if not (report.package or report.permissions or report.actions):
        raise NotAnApk("empty manifest")
    return report


# ---------------------------------------------------------------------------
# 3. Turning permissions into explanations people understand
# ---------------------------------------------------------------------------

P = "android.permission."

# (signal name, test, explanation). Ordered from most to least dangerous.
CAPABILITIES: list[tuple[str, callable, Reason]] = [
    ("apk_reads_sms",
     lambda r: bool({P + "RECEIVE_SMS", P + "READ_SMS"} & r.permissions)
     or bool({"android.provider.Telephony.SMS_RECEIVED", "android.provider.Telephony.SMS_DELIVER"} & r.actions),
     Reason("SMS xabarlaringizni o'qiy oladi — bank kodlaringizni o'g'irlab, kartangizdan pul yechish uchun",
            "It can read your SMS messages — that's how bank codes get stolen and cards emptied",
            "Может читать ваши SMS — так крадут банковские коды и опустошают карты")),
    ("apk_accessibility",
     lambda r: P + "BIND_ACCESSIBILITY_SERVICE" in r.services,
     Reason("Maxsus imkoniyatlar (Accessibility) xizmati bor: ekraningizni ko'radi va siz uchun tugmalarni bosa oladi",
            "It has an Accessibility service: it can see your screen and press buttons for you",
            "Есть служба специальных возможностей: видит ваш экран и может нажимать кнопки за вас")),
    ("apk_notifications",
     lambda r: P + "BIND_NOTIFICATION_LISTENER_SERVICE" in r.services,
     Reason("Barcha bildirishnomalaringizni, jumladan bank kodlarini o'qiy oladi",
            "It can read all your notifications, including bank codes",
            "Может читать все уведомления, включая банковские коды")),
    ("apk_overlay",
     lambda r: P + "SYSTEM_ALERT_WINDOW" in r.permissions,
     Reason("Boshqa ilovalar ustidan oyna chiqara oladi — bank ilovasi ustiga soxta kirish oynasini qo'yish uchun",
            "It can draw over other apps — used to put a fake login screen on top of your bank app",
            "Может показывать окна поверх других приложений — фальшивый вход поверх банковского приложения")),
    ("apk_device_admin",
     lambda r: P + "BIND_DEVICE_ADMIN" in r.services,
     Reason("Qurilma administratori huquqini so'raydi — o'chirib tashlashni qiyinlashtiradi",
            "It asks for device-administrator rights, which make it hard to uninstall",
            "Просит права администратора устройства — его будет трудно удалить")),
    ("apk_sends_sms",
     lambda r: P + "SEND_SMS" in r.permissions,
     Reason("Sizning nomingizdan SMS yubora oladi (masalan, do'stlaringizga ham shu faylni)",
            "It can send SMS in your name (for example, this same file to your friends)",
            "Может отправлять SMS от вашего имени (например, этот же файл вашим друзьям)")),
    ("apk_calls",
     lambda r: bool({P + "CALL_PHONE", P + "READ_CALL_LOG", P + "ANSWER_PHONE_CALLS", P + "PROCESS_OUTGOING_CALLS"} & r.permissions),
     Reason("Qo'ng'iroqlaringizni boshqara oladi (bankning tasdiqlash qo'ng'irog'ini ushlab qolish mumkin)",
            "It can control your calls (it could intercept a bank's confirmation call)",
            "Может управлять звонками (перехватить подтверждающий звонок банка)")),
    ("apk_installs_apps",
     lambda r: P + "REQUEST_INSTALL_PACKAGES" in r.permissions,
     Reason("Boshqa ilovalarni o'rnata oladi — keyinroq yanada xavfli dasturni yuklab olishi mumkin",
            "It can install other apps — it may download something worse later",
            "Может устанавливать другие приложения — позже может скачать что-то опаснее")),
    ("apk_contacts",
     lambda r: P + "READ_CONTACTS" in r.permissions,
     Reason("Kontaktlaringizni o'qiy oladi — firibgarlar ularga ham yozishi mumkin",
            "It can read your contacts, so scammers can message them too",
            "Может читать контакты — мошенники напишут и им")),
    ("apk_sees_apps",
     lambda r: P + "QUERY_ALL_PACKAGES" in r.permissions,
     Reason("Telefoningizda qaysi bank ilovalari borligini ko'ra oladi",
            "It can see which banking apps you have installed",
            "Видит, какие банковские приложения у вас установлены")),
]

HIDDEN_ICON = Reason(
    "Ilovaning bosh ekranda belgisi yo'q — o'rnatilgandan keyin yashirinib ishlaydi",
    "It has no home-screen icon, so it would run hidden after installation",
    "У приложения нет значка на главном экране — после установки оно работает скрытно",
)
NOTHING_FOUND = Reason(
    "Xavfli ruxsatlar topilmadi, lekin chatda kelgan .apk baribir xavfli: ilovalarni faqat Play Marketdan o'rnating",
    "No dangerous permissions found, but an .apk sent in a chat is still risky: install apps only from Google Play",
    "Опасных разрешений не найдено, но .apk из чата всё равно опасен: ставьте приложения только из Google Play",
)
EVASION = Reason(
    "Fayl tahlil qilinmasligi uchun ataylab buzilgan — bu zararli dasturlarning odatiy usuli",
    "The file is deliberately damaged to block analysis — a typical malware trick",
    "Файл намеренно повреждён, чтобы помешать анализу — типичный приём вредоносных программ",
)


def capabilities(report: ApkReport) -> list[tuple[str, Reason]]:
    found = [(sig, reason) for sig, test, reason in CAPABILITIES if test(report)]
    launcher_matters = any(sig in {"apk_reads_sms", "apk_accessibility", "apk_notifications"} for sig, _ in found)
    if launcher_matters and not report.has_launcher_icon:
        found.append(("apk_hidden_icon", HIDDEN_ICON))
    if report.tolerated:
        found.append(("apk_evasion", EVASION))
    return found


def report_reasons(report: ApkReport) -> list[Reason]:
    """Explanations for the verdict, most dangerous first. Always non-empty."""
    found = capabilities(report)
    reasons = [r for _, r in found] or [NOTHING_FOUND]
    who = report.package or "?"
    reasons.append(Reason(
        f"Ilova nomi (paket): {who} · SHA-256: {report.sha256[:16]}…",
        f"App package: {who} · SHA-256: {report.sha256[:16]}…",
        f"Пакет приложения: {who} · SHA-256: {report.sha256[:16]}…",
    ))
    return reasons


def report_signals(report: ApkReport) -> list[str]:
    return [sig for sig, _ in capabilities(report)]


TOO_BIG = Reason(
    "Fayl 20 MB dan katta, ichidagi ilovani tekshira olmadim",
    "The file is larger than 20 MB, so I couldn't look inside the app",
    "Файл больше 20 МБ, проверить приложение внутри не удалось",
)
UNREADABLE = Reason(
    "Fayl .apk deb nomlangan, lekin ichini o'qib bo'lmadi — ochmang",
    "The file is named .apk but its contents couldn't be read — don't open it",
    "Файл назван .apk, но его содержимое прочитать не удалось — не открывайте",
)


def is_apk_name(file_name: str | None, mime_type: str | None = None) -> bool:
    return (file_name or "").strip().lower().endswith(".apk") or mime_type == "application/vnd.android.package-archive"
