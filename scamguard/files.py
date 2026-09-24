"""File checks based on name and type only. Files are never downloaded or opened."""

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
            reasons.append(Reason(
                ".apk — bu rasm yoki hujjat emas, telefonga o'rnatiladigan Android ilova. "
                "Bunday fayllar SMS kodlaringizni o'qib, kartangizdan pul yechishi mumkin",
                ".apk is an installable Android app, not a photo or document. "
                "These can read your SMS codes and drain your card",
                ".apk — это не фото и не документ, а устанавливаемое Android-приложение. "
                "Оно может читать ваши SMS-коды и списать деньги с карты",
            ))
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
