"""File checks based on name and type. Nothing is downloaded here; for .apk files the bot also
looks inside the app in memory (see apk.py)."""

from __future__ import annotations

from dataclasses import dataclass, field

from .analyzer import Level
from .reasons import Reason

# Programs that run or install something when opened.
EXECUTABLE = {
    "apk", "xapk", "apks", "exe", "scr", "bat", "cmd", "com", "msi", "js", "jse",
    "vbs", "vbe", "wsf", "ps1", "jar", "hta", "lnk", "dmg", "pkg", "app", "sh",
}
# Office files with macros can run code.
MACRO = {"docm", "xlsm", "pptm", "dotm", "xltm"}
# Archives can hide any of the above inside.
ARCHIVE = {"zip", "rar", "7z", "tar", "gz", "iso"}
# Extensions that make a file look harmless.
DECOY = {"jpg", "jpeg", "png", "gif", "pdf", "doc", "docx", "mp4", "mp3", "txt", "xls", "xlsx", "heic"}

APK_MIME = "application/vnd.android.package-archive"

# General .apk warning, used when nobody looked inside the app (see scamguard/apk.py).
APK_REASON = Reason(
    ".apk — bu rasm yoki hujjat emas, telefonga o'rnatiladigan Android ilova. "
    "Bunday fayllar SMS kodlaringizni o'qib, kartangizdan pul yechishi mumkin",
    ".apk is an installable Android app, not a photo or document. "
    "These can read your SMS codes and drain your card",
    ".apk — это не фото и не документ, а устанавливаемое Android-приложение. "
    "Оно может читать ваши SMS-коды и списать деньги с карты",
)


@dataclass
class FileVerdict:
    level: Level
    kind: str
    reasons: list[Reason] = field(default_factory=list)


def check_file(file_name: str | None, mime_type: str | None = None) -> FileVerdict:
    name = (file_name or "").strip().lower()
    parts = name.split(".")
    ext = parts[-1] if len(parts) > 1 else ""
    prev_ext = parts[-2] if len(parts) > 2 else ""

    if ext in EXECUTABLE or mime_type == APK_MIME:
        reasons = []
        if prev_ext in DECOY:
            reasons.append(Reason(
                f"Ikki kengaytmali nom (.{prev_ext}.{ext}) — o'zini .{prev_ext} qilib ko'rsatyapti, aslida dastur",
                f"Double extension (.{prev_ext}.{ext}): it pretends to be a .{prev_ext} but is a program",
                f"Двойное расширение (.{prev_ext}.{ext}): притворяется .{prev_ext}, а на деле это программа",
            ))
        if ext in {"apk", "xapk", "apks"} or mime_type == APK_MIME:
            reasons.append(APK_REASON)
        else:
            reasons.append(Reason(
                f".{ext} — ochilganda ishga tushadigan dastur. Notanish odamdan kelgan bo'lsa, ochmang",
                f".{ext} is a program that runs when opened. Don't open it from strangers",
                f".{ext} — программа, которая запускается при открытии. Не открывайте от незнакомцев",
            ))
        return FileVerdict(Level.DANGEROUS, "program", reasons)

    if ext in MACRO:
        return FileVerdict(Level.SUSPICIOUS, "macro", [Reason(
            f".{ext} — makrosli hujjat, ichida dastur kodi bo'lishi mumkin. \"Enable macros\" tugmasini bosmang",
            f".{ext} is a macro-enabled document that can run code. Never click \"Enable macros\"",
            f".{ext} — документ с макросами, может запускать код. Не нажимайте «Включить макросы»",
        )])

    if ext in ARCHIVE:
        return FileVerdict(Level.SUSPICIOUS, "archive", [Reason(
            f".{ext} arxiv — ichida .apk yoki .exe yashiringan bo'lishi mumkin. Notanish odamdan bo'lsa, ochmang",
            f".{ext} archive: it may hide an .apk or .exe inside. Don't open it from strangers",
            f"Архив .{ext} может скрывать внутри .apk или .exe. Не открывайте от незнакомцев",
        )])

    return FileVerdict(Level.SAFE, "document", [])


# ---------- looking inside a file (archives and files with no or unknown type) ----------
# Name checks miss two favourite tricks: an .apk hidden inside a .zip ("photos.zip" with
# "foto.apk" inside, often password-protected so scanners can't open it - the file *names* stay
# readable anyway) and an app renamed to something harmless ("document", "video.dat").

MAX_SNIFF_BYTES = 20 * 1024 * 1024      # Telegram bots can't download more than 20 MB
MAX_ENTRIES = 5000                      # names read from one archive, so a hostile file can't stall us
# Common file types that are what they say; anything else gets a look inside.
KNOWN_TYPES = DECOY | {"webp", "ppt", "pptx", "csv", "ogg", "oga", "opus", "m4a", "wav", "mov", "avi", "mkv",
                       "webm", "epub", "djvu", "rtf", "odt", "ods", "tgs", "json", "xml", "html", "srt", "psd"}

_LOCAL = b"PK\x03\x04"


def needs_look_inside(file_name: str | None) -> bool:
    parts = (file_name or "").strip().lower().split(".")
    ext = parts[-1] if len(parts) > 1 else ""
    return ext in ARCHIVE or ext not in KNOWN_TYPES and ext not in EXECUTABLE and ext not in MACRO


def zip_names(data: bytes) -> list[str]:
    """File names inside a zip, read from its local headers (works on damaged zips too).
    Nothing is decompressed."""
    names, pos = [], data.find(_LOCAL)
    while pos != -1 and len(names) < MAX_ENTRIES:
        header = data[pos:pos + 30]
        if len(header) < 30:
            break
        name_len = int.from_bytes(header[26:28], "little")
        extra_len = int.from_bytes(header[28:30], "little")
        name = data[pos + 30:pos + 30 + name_len].decode("utf-8", "replace")
        if name:
            names.append(name)
        pos = data.find(_LOCAL, pos + 30 + name_len + extra_len)
    return names


def look_inside(data: bytes, file_name: str | None) -> FileVerdict | None:
    """A verdict from the file's contents, or None when they show nothing worse than its name."""
    shown = (file_name or "").strip().lower()
    if data[:2] == b"MZ" and not shown.endswith((".exe", ".dll", ".scr", ".com")):
        return FileVerdict(Level.DANGEROUS, "program", [Reason(
            "Bu fayl aslida Windows dasturi (.exe), boshqa nom bilan yashirilgan — ochmang",
            "This file is really a Windows program (.exe) under another name — don't open it",
            "Этот файл на самом деле программа Windows (.exe) под другим именем — не открывайте",
        )])
    if not data.startswith(_LOCAL):
        return None
    names = zip_names(data)
    lower = {n.lower().rsplit("/", 1)[-1] for n in names}
    if "androidmanifest.xml" in lower and ("classes.dex" in lower or "resources.arsc" in lower):
        if shown.endswith((".apk", ".xapk", ".apks")):
            return None                                   # an app that says it is one: the name check covers it
        return FileVerdict(Level.DANGEROUS, "program", [Reason(
            "Bu fayl aslida Android ilova (.apk), boshqa nom bilan yashirilgan. Bunday ilovalar SMS "
            "kodlaringizni o'qib, kartangizdan pul yechishi mumkin",
            "This file is really an Android app (.apk) renamed to look harmless. Apps like this can read "
            "your SMS codes and drain your card",
            "Этот файл на самом деле Android-приложение (.apk) под безобидным именем. Такие приложения "
            "читают SMS-коды и списывают деньги с карты",
        )])
    hidden = sorted({n.rsplit("/", 1)[-1] for n in names if "." in n and n.lower().rsplit(".", 1)[-1] in EXECUTABLE})
    if hidden:
        listed = ", ".join(hidden[:3]) + ("…" if len(hidden) > 3 else "")
        return FileVerdict(Level.DANGEROUS, "program", [Reason(
            f"Arxiv ichida dastur yashirilgan: {listed}. Arxivni ochmang",
            f"A program is hidden inside the archive: {listed}. Don't open it",
            f"В архиве спрятана программа: {listed}. Не открывайте его",
        )])
    return None
