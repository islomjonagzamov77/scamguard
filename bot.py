"""ScamGuard Telegram bot.

Private chat: forward a suspicious message, link or file and get an explained
verdict in Uzbek, Russian or English. Menu: how-to, SOS guide, scam types,
statistics, language, share.

Screenshots: text in photos is read with OCR (Uzbek Latin/Cyrillic, Russian,
English) and checked like any message. Images are never saved.

Apps: an .apk is loaded into memory and its manifest is read to explain what the app could do
(read SMS codes, control the screen, draw fake login windows...). It is never installed or run.

Online checks: links get a domain-age lookup and, when API keys are set, Google Safe Browsing
and VirusTotal (scamguard/reputation.py). They only add risk and are skipped when slow.

Community blocklist: the 🚩 button (or /report in groups) records scam sites,
phone numbers and Telegram accounts. Once REPORT_THRESHOLD different people
report the same one, everyone who meets it gets a warning.

Inline mode: in any chat, "@bot <link or text>" shows a verdict card; tapping it
posts the verdict into the chat, signed by the bot (a built-in growth loop).

Groups and channel comments (scamguard/guard.py): as an admin with the "Delete messages" right,
the bot removes dangerous messages (scam links, .apk/.exe files, blocklisted numbers) and posts a
short notice with the reason; admins can undo a mistake from that notice. Admins and the group's
own channel are never touched, edited messages are checked too, and admins pick the mode, strict
mode and muting of repeat offenders with /settings. Without the right it only warns.
/check and /report as a reply work on a specific message.

Run:  python bot.py      (token in .env as BOT_TOKEN=...)
"""

from __future__ import annotations

import asyncio
import contextlib
import html
import logging
import os
import re
import secrets
import time
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from urllib.parse import quote

from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ChatAction, ChatType, MessageEntityType, ParseMode
from aiogram.exceptions import TelegramAPIError, TelegramBadRequest, TelegramNotFound, TelegramUnauthorizedError
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    BotCommand, BotCommandScopeAllGroupChats, BotCommandScopeDefault, CallbackQuery, ChatMemberUpdated, ChatPermissions,
    ChosenInlineResult, ErrorEvent, InlineKeyboardButton, InlineKeyboardMarkup, InlineQuery, MenuButtonWebApp, WebAppInfo,
    InlineQueryResultArticle, InputTextMessageContent, KeyboardButton, Message, ReplyKeyboardMarkup,
)

import scamguard
from scamguard import apk, blocklist, community, guard, ocr, radar, reputation, semantic
from scamguard.analyzer import DANGEROUS_AT, SUSPICIOUS_AT, Level, analyze
from scamguard.files import APK_REASON, check_file
from scamguard.reasons import Reason
from scamguard.i18n import LANG_NAMES, LANGS, SCAM_TYPES, all_variants, guess_lang, t
from scamguard.storage import Storage
from scamguard.web import server as radar_web

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("scamguard")

LEVEL_ORDER = [Level.SAFE, Level.SUSPICIOUS, Level.DANGEROUS]
RATE_LIMIT = (15, 60)  # max checks per user per N seconds
MAX_CACHE = 2000

storage = Storage()
memory = community.CommunityMemory(storage)
dp = Dispatcher()
private = Router(name="private")
groups = Router(name="groups")
private.message.filter(F.chat.type == ChatType.PRIVATE)
groups.message.filter(F.chat.type.in_({ChatType.GROUP, ChatType.SUPERGROUP}))
groups.edited_message.filter(F.chat.type.in_({ChatType.GROUP, ChatType.SUPERGROUP}))



@dataclass
class Pending:
    """What we remember about a verdict so its buttons can work (in memory only)."""
    text: str
    level: str
    forward: tuple[str, str] | None = None
    feedback_done: bool = False
    reported: bool = False


@dataclass
class Result:
    level: Level
    reasons: list = field(default_factory=list)
    score: float = 0.0
    file_level: Level | None = None
    text: str = ""
    forward: tuple[str, str] | None = None
    trust: list = field(default_factory=list)
    signals: list = field(default_factory=list)   # for the public radar (scam category)
    domains: list = field(default_factory=list)   # fake-site domains found (for the radar)
    links: list = field(default_factory=list)     # LinkReports, for the online checks (memory only)
    app_sha256: str = ""                          # hash of an inspected .apk, for VirusTotal


def record(r: "Result") -> None:
    """Count a check in the anonymous stats and the public radar (category + fake-site domains only)."""
    if "needs_context" in r.signals:        # a "can't tell" question is not a detected scam on the radar
        storage.record_check("safe")
        return
    storage.record_check(r.level.value)
    if r.level != Level.SAFE:
        storage.record_category(radar.primary_category(r.signals))
        for d in r.domains:
            storage.record_domain(d)


_pending: OrderedDict[str, Pending] = OrderedDict()           # button key -> Pending
_hits: dict[int, deque] = defaultdict(deque)                   # user id -> recent check times
BOT_USERNAME = ""
# Public Scam Radar address. Railway sets RAILWAY_PUBLIC_DOMAIN automatically once a domain is generated.
_domain = os.getenv("RAILWAY_PUBLIC_DOMAIN", "").strip()
RADAR_URL = (os.getenv("SCAMGUARD_RADAR_URL") or (f"https://{_domain}" if _domain else "")).rstrip("/")


# ======================= helpers =======================

def lang_of(user) -> str:
    if user is None:
        return "uz"
    return storage.get_lang(user.id) or guess_lang(user.language_code)


def rate_limited(user_id: int) -> bool:
    limit, window = RATE_LIMIT
    now, hits = time.monotonic(), _hits[user_id]
    while hits and now - hits[0] > window:
        hits.popleft()
    if len(hits) >= limit:
        return True
    hits.append(now)
    return False


def main_menu(lang: str) -> ReplyKeyboardMarkup:
    b = lambda key: KeyboardButton(text=t(key, lang))  # noqa: E731
    last_row = [b("btn_lang")]
    if RADAR_URL:   # opens the Scam Radar website inside Telegram as a Mini App
        last_row.insert(0, KeyboardButton(text=t("btn_radar", lang), web_app=WebAppInfo(url=f"{RADAR_URL}/?lang={lang}")))
    return ReplyKeyboardMarkup(
        keyboard=[[b("btn_check"), b("btn_types")], [b("btn_sos"), b("btn_share")], last_row],
        resize_keyboard=True,
        input_field_placeholder="📩 Forward…",
    )


def lang_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=LANG_NAMES[code], callback_data=f"lang:{code}") for code in LANGS
    ]])


def verdict_keyboard(key: str, lang: str, feedback: bool = True, report: bool = True) -> InlineKeyboardMarkup | None:
    rows = []
    if feedback:
        rows.append([InlineKeyboardButton(text=t("fb_ok", lang), callback_data=f"fb:ok:{key}"),
                     InlineKeyboardButton(text=t("fb_no", lang), callback_data=f"fb:no:{key}")])
    if report:
        rows.append([InlineKeyboardButton(text=t("report_btn", lang), callback_data=f"rep:{key}")])
    return InlineKeyboardMarkup(inline_keyboard=rows) if rows else None


def remember(result: Result) -> str:
    key = secrets.token_urlsafe(8)
    _pending[key] = Pending(result.text, result.level.value, result.forward)
    while len(_pending) > MAX_CACHE:
        _pending.popitem(last=False)
    return key


def full_text(message: Message) -> str:
    """Message text plus URLs hidden behind text links and inline buttons (favourite scam tricks)."""
    text = message.text or message.caption or ""
    entities = message.entities or message.caption_entities or []
    hidden = [e.url for e in entities if e.type == MessageEntityType.TEXT_LINK and e.url]
    buttons = []
    markup = message.reply_markup
    if markup is not None and getattr(markup, "inline_keyboard", None):
        buttons = [b.url for row in markup.inline_keyboard for b in row if b.url]
    return " ".join([text, *hidden, *buttons]).strip()


def forward_source(message: Message) -> str | None:
    origin = message.forward_origin
    if origin is None:
        return None
    chat = getattr(origin, "chat", None) or getattr(origin, "sender_chat", None)
    if chat is not None:
        return chat.title or chat.username
    user = getattr(origin, "sender_user", None)
    if user is not None:
        return user.full_name + (" (bot)" if user.is_bot else "")
    return getattr(origin, "sender_user_name", None)


def forward_id(message: Message) -> tuple[str, str] | None:
    """Stable id + display name of the original sender of a forwarded message (for reports)."""
    origin = message.forward_origin
    if origin is None:
        return None
    chat = getattr(origin, "chat", None) or getattr(origin, "sender_chat", None)
    if chat is not None:
        return f"id:{chat.id}", ("@" + chat.username) if chat.username else (chat.title or "")
    user = getattr(origin, "sender_user", None)
    if user is not None and user.username != BOT_USERNAME:
        return f"id:{user.id}", ("@" + user.username) if user.username else user.full_name
    return None


def is_image(message: Message) -> bool:
    doc = message.document
    return bool(message.photo) or bool(doc and (doc.mime_type or "").startswith("image/"))


async def download_image(message: Message) -> bytes:
    """Download a photo or image file into memory (never to disk)."""
    target = message.photo[-1] if message.photo else message.document
    if target.file_size and target.file_size > ocr.MAX_BYTES:
        return b""
    buf = await message.bot.download(target)
    return buf.read() if buf else b""


_ocr_slots = asyncio.Semaphore(2)   # at most 2 screenshots processed at once (protects the server)


async def read_image(message: Message) -> str:
    """OCR text of the image in `message`, or "" if none / OCR unavailable."""
    if not is_image(message) or not ocr.available():
        return ""
    await message.bot.send_chat_action(message.chat.id, ChatAction.TYPING)
    data = await download_image(message)
    async with _ocr_slots:
        return await asyncio.to_thread(ocr.image_to_text, data)


_apk_slots = asyncio.Semaphore(2)   # at most 2 apps inspected at once
APK_TIMEOUT_S = 15


@dataclass
class AppCheck:
    """Result of looking inside an .apk (the file itself is never kept)."""
    reasons: list = field(default_factory=list)
    signals: list = field(default_factory=list)
    looked_inside: bool = False                      # True when the manifest was actually read
    sha256: str = ""


async def download_file(message: Message) -> bytes:
    """Download a document into memory (never to disk)."""
    buf = await message.bot.download(message.document)
    return buf.read() if buf else b""


async def inspect_app(message: Message) -> AppCheck | None:
    """Download an .apk into memory and read what it is allowed to do. Never installs or runs it.
    Any failure falls back to the name-based check, so a broken download never breaks the reply."""
    doc = message.document
    if doc is None or not apk.is_apk_name(doc.file_name, doc.mime_type):
        return None
    if doc.file_size and doc.file_size > apk.MAX_APK_BYTES:
        return AppCheck([apk.TOO_BIG])
    try:
        await message.bot.send_chat_action(message.chat.id, ChatAction.TYPING)
        data = await download_file(message)
        async with _apk_slots:
            report = await asyncio.wait_for(asyncio.to_thread(apk.inspect_apk, data), APK_TIMEOUT_S)
    except apk.NotAnApk:
        return AppCheck([apk.UNREADABLE])
    except Exception as e:                            # network, Telegram or timeout problems
        log.warning("APK check failed: %s", e)
        return None
    finally:
        data = b""                                    # drop the bytes as soon as possible
    return AppCheck(apk.report_reasons(report), apk.report_signals(report), looked_inside=True, sha256=report.sha256)


def level_for(score: float) -> Level:
    return Level.DANGEROUS if score >= DANGEROUS_AT else Level.SUSPICIOUS if score >= SUSPICIOUS_AT else Level.SAFE


BLOCKLIST_WEIGHT = 0.8   # a site, number or account that enough people reported


def community_reasons(text: str, forward) -> list[tuple[Reason, float]]:
    """Warnings (with their weight) for indicators, and for messages like this one, that enough
    different people have reported."""
    indicators = blocklist.extract(text, forward, {BOT_USERNAME.lower()})
    hits = []
    for ind, n in storage.report_counts(indicators).items():
        if n >= blocklist.REPORT_THRESHOLD:
            key = f"hit_{ind.kind}"
            hits.append((Reason(t(key, "uz", n=n, preview=ind.preview), t(key, "en", n=n, preview=ind.preview),
                                t(key, "ru", n=n, preview=ind.preview)), BLOCKLIST_WEIGHT))
    n = memory.reporters_of_similar(text)
    if n >= blocklist.REPORT_THRESHOLD:
        hits.append((Reason(t("hit_similar", "uz", n=n), t("hit_similar", "en", n=n), t("hit_similar", "ru", n=n)),
                     community.COMMUNITY_WEIGHT))
    return hits


def with_community(score: float, hits: list[tuple[Reason, float]]) -> float:
    for _, weight in hits:
        score = 1 - (1 - score) * (1 - weight)
    return score


def evaluate_text(text: str) -> Result:
    """Check plain text (inline mode): rules, links, AI model and the community blocklist."""
    verdict = analyze(text)
    reasons, score, level = list(verdict.reasons), verdict.score, verdict.level
    hits = community_reasons(text, None)
    if hits:
        reasons = [r for r, _ in hits] + reasons
        score = with_community(score, hits)
        level = max(level, level_for(score), key=LEVEL_ORDER.index)
    trust = verdict.trust if level == Level.SAFE else []
    signals = list(verdict.signals) + (["community"] if hits else [])
    return Result(level, reasons, score, None, text, None, trust, signals, radar.scam_domains(verdict.links))


def evaluate(message: Message, extra_text: str = "", app: AppCheck | None = None) -> Result | None:
    """Full check of a message: text, hidden links, file (and what an .apk may do), OCR text
    and the community blocklist."""
    text = "\n".join(filter(None, [full_text(message), extra_text]))
    file_level, reasons, score = None, [], 0.0
    doc = message.document
    if doc is not None:
        fv = check_file(doc.file_name, doc.mime_type)
        file_level, reasons = fv.level, list(fv.reasons)
        if app is not None and app.looked_inside:
            # We know what the app can do, so the general ".apk" warnings would only repeat it.
            reasons = list(app.reasons) + [r for r in reasons if r is not APK_REASON]
        else:
            reasons = (list(app.reasons) if app else []) + reasons
            text = " ".join(filter(None, [text, doc.file_name]))
    forward = forward_id(message)
    if not text and doc is None and forward is None:
        return None
    verdict = analyze(text) if text else None
    levels = [lv for lv in (file_level, verdict.level if verdict else None) if lv is not None] or [Level.SAFE]
    level = max(levels, key=LEVEL_ORDER.index)
    if verdict:
        reasons += verdict.reasons
        score = verdict.score
    if file_level == Level.DANGEROUS:
        score = max(score, 0.95)
    elif file_level == Level.SUSPICIOUS:
        score = max(score, 0.5)
    hits = community_reasons(text, forward)
    if hits:
        reasons = [r for r, _ in hits] + reasons
        score = with_community(score, hits)
        level = max(level, level_for(score), key=LEVEL_ORDER.index)
    trust = verdict.trust if (verdict and level == Level.SAFE) else []
    signals = list(verdict.signals) if verdict else []
    if file_level == Level.DANGEROUS:
        signals.insert(0, "file_program")
    if app is not None:
        signals = list(app.signals) + signals
    if hits:
        signals.append("community")
    domains = radar.scam_domains(verdict.links) if verdict else []
    return Result(level, reasons, score, file_level, text, forward, trust, signals, domains,
                  links=list(verdict.links) if verdict else [], app_sha256=app.sha256 if app else "")


async def add_online_checks(result: Result) -> Result:
    """Domain age, Google Safe Browsing and VirusTotal (when keys are set). Only ever adds risk,
    and any failure or slowness is skipped (see scamguard/reputation.py)."""
    if not reputation.enabled() or not (result.links or result.app_sha256):
        return result
    found = await reputation.check_links(result.links)
    if result.app_sha256:
        found.merge(await reputation.check_file_hash(result.app_sha256))
    if found.evidence <= 0:
        return result
    result.reasons = found.reasons + result.reasons
    result.score = 1 - (1 - result.score) * (1 - found.evidence)
    result.level = max(result.level, level_for(result.score), key=LEVEL_ORDER.index)
    result.signals = list(result.signals) + found.signals
    result.domains = list(result.domains) + [d for d in found.confirmed_domains if d not in result.domains]
    if result.level != Level.SAFE:
        result.trust = []
    return result


def plain(text: str) -> str:
    """Telegram HTML -> plain text for the website (the page inserts it as text, never as HTML)."""
    return html.unescape(re.sub(r"<[^>]+>", "", text)).strip()


def verdict_json(r: Result, lang: str) -> dict:
    """A verdict for the website and the public API: the same words the bot would send."""
    title = plain(t(f"v_{r.level.value}", lang))
    if title[:1] in "🟢🟡🔴":
        title = title[1:].strip()
    return {
        "level": r.level.value,
        "risk": None if r.level == Level.SAFE else round(r.score * 100),
        "title": title,
        "reasons": [plain(x.text(lang)) for x in r.reasons[:8]],
        "trust": [plain(x.text(lang)) for x in r.trust] if r.level == Level.SAFE else [],
        "advice": plain(t(f"a_{r.level.value}", lang)),
        "signals": list(dict.fromkeys(r.signals)),
        "engine": f"scamguard {scamguard.__version__}",
    }


async def web_check(text: str, lang: str) -> dict:
    """A check from the Scam Radar website or the public API: the same pipeline as the bot (rules, links,
    AI model, community blocklist, online reputation). The text is not stored; like every bot check,
    only the anonymous counts, the scam category and fake-site domains reach the radar."""
    result = await add_online_checks(evaluate_text(text))
    record(result)
    return verdict_json(result, lang)


def render(lang: str, r: Result, file_name: str | None = None, source: str | None = None, ocr_text: str = "") -> str:
    level, reasons, score, file_level = r.level, r.reasons, r.score, r.file_level
    risk = t("risk_low", lang) if level == Level.SAFE else f"{round(score * 100)}%"
    lines = [t(f"v_{level.value}", lang), f"{t('risk', lang)}: <b>{risk}</b>"]
    if ocr_text:
        snippet = " ".join(ocr_text.split())
        snippet = snippet[:160] + ("…" if len(snippet) > 160 else "")
        lines.append(f"{t('ocr_read', lang)}: <i>«{html.escape(snippet)}»</i>")
    if file_name:
        lines.append(f"{t('file', lang)}: <code>{html.escape(file_name)}</code>")
    if source:
        lines.append(f"{t('source', lang)}: {html.escape(source)}")
    if reasons:
        lines.append(f"\n<b>{t('why', lang)}</b>")
        lines += [f"• {html.escape(r.text(lang))}" for r in reasons[:8]]
    if r.trust and level == Level.SAFE:
        lines.append(f"\n<b>{t('trust', lang)}</b>")
        lines += [f"✅ {html.escape(x.text(lang))}" for x in r.trust]
    advice = f"fa_{level.value}" if file_level is not None and level == file_level else f"a_{level.value}"
    lines.append(f"\n💡 {t(advice, lang)}")
    return "\n".join(lines)


def types_keyboard(lang: str) -> InlineKeyboardMarkup:
    items = SCAM_TYPES[lang]
    rows = [[InlineKeyboardButton(text=title, callback_data=f"type:{tid}") for tid, title, *_ in items[i:i + 2]]
            for i in range(0, len(items), 2)]
    return InlineKeyboardMarkup(inline_keyboard=rows)


# ======================= private chat =======================

@private.message(CommandStart())
async def cmd_start(message: Message) -> None:
    if storage.get_lang(message.from_user.id) is None:
        await message.answer("🌐 Tilni tanlang · Выберите язык · Choose language", reply_markup=lang_keyboard())
        return
    lang = lang_of(message.from_user)
    await message.answer(t("welcome", lang, name=html.escape(message.from_user.first_name)),
                         reply_markup=main_menu(lang))


LEGACY_LANG_BUTTONS = {"🌐 Til", "🌐 Язык", "🌐 Language"}   # labels from older menus still work


@private.message(Command("lang"))
@private.message(F.text.in_(all_variants("btn_lang") | LEGACY_LANG_BUTTONS))
async def cmd_lang(message: Message) -> None:
    await message.answer(t("choose_lang", lang_of(message.from_user)), reply_markup=lang_keyboard())


@private.message(Command("help", "check"))
@private.message(F.text.in_(all_variants("btn_check")))
async def cmd_help(message: Message) -> None:
    await message.answer(t("how_to_check", lang_of(message.from_user)))


@private.message(Command("sos"))
@private.message(F.text.in_(all_variants("btn_sos")))
async def cmd_sos(message: Message) -> None:
    await message.answer(t("sos", lang_of(message.from_user)))


@private.message(Command("types"))
@private.message(F.text.in_(all_variants("btn_types")))
async def cmd_types(message: Message) -> None:
    lang = lang_of(message.from_user)
    await message.answer(t("types_title", lang), reply_markup=types_keyboard(lang))


@private.message(Command("stats"))
@private.message(F.text.in_(all_variants("btn_stats")))
async def cmd_stats(message: Message) -> None:
    await message.answer(t("stats", lang_of(message.from_user), **storage.stats(blocklist.REPORT_THRESHOLD)))


@private.message(F.text.in_(all_variants("btn_share")))
async def cmd_share(message: Message) -> None:
    lang = lang_of(message.from_user)
    link = f"https://t.me/{BOT_USERNAME}"
    share_url = f"https://t.me/share/url?url={quote(link)}&text={quote(t('share_msg', lang))}"
    kb = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text=t("share_btn", lang), url=share_url)]])
    await message.answer(t("share", lang), reply_markup=kb)


@private.message(Command("privacy"))
async def cmd_privacy(message: Message) -> None:
    await message.answer(t("privacy", lang_of(message.from_user)))


@private.message(F.text | F.caption | F.document | F.photo)
async def on_check(message: Message) -> None:
    lang = lang_of(message.from_user)
    if rate_limited(message.from_user.id):
        await message.reply(t("rate_limited", lang))
        return
    ocr_text = ""
    if is_image(message):
        if not ocr.available():
            if not (message.caption or message.document):
                await message.reply(t("ocr_off", lang))
                return
        else:
            ocr_text = await read_image(message)
            if not ocr_text and not message.caption and forward_id(message) is None:
                await message.reply(t("ocr_empty", lang))
                return
    result = evaluate(message, ocr_text, await inspect_app(message))
    if result is None:
        await message.reply(t("empty", lang))
        return
    result = await add_online_checks(result)
    record(result)
    doc = message.document
    reply = render(lang, result, doc.file_name if doc else None, forward_source(message), ocr_text)
    markup = verdict_keyboard(remember(result), lang) if (result.text or result.forward) else None
    await message.reply(reply, reply_markup=markup, disable_web_page_preview=True)


@private.message()
async def on_other(message: Message) -> None:
    await message.reply(t("other_media", lang_of(message.from_user)))


# ======================= groups =======================

@groups.message(Command("check"))
async def group_check(message: Message) -> None:
    lang = lang_of(message.from_user)
    target = message.reply_to_message
    if target is None:
        await message.reply(t("check_hint", lang))
        return
    result = evaluate(target, await read_image(target), await inspect_app(target))
    if result is None:
        await message.reply(t("empty", lang))
        return
    result = await add_online_checks(result)
    record(result)
    doc = target.document
    await target.reply(render(lang, result, doc.file_name if doc else None), disable_web_page_preview=True)


@groups.message(Command("report"))
async def group_report(message: Message) -> None:
    lang = lang_of(message.from_user)
    target = message.reply_to_message
    if target is None:
        await message.reply(t("report_hint", lang))
        return
    if rate_limited(message.from_user.id):
        return
    result = evaluate(target, await read_image(target))
    if result is None:
        await message.reply(t("empty", lang))
        return
    await message.reply(record_report(Pending(result.text, result.level.value, result.forward),
                                      message.from_user.id, lang) or t("report_dup", lang))


@groups.message(Command("help", "start"))
async def group_help(message: Message) -> None:
    await message.reply(t("group_hello", lang_of(message.from_user)))


ADMIN_CACHE_S = 600          # how long the admin list and the bot's own rights are trusted
NOTICE_TTL_S = int(os.getenv("SCAMGUARD_NOTICE_TTL", "300"))   # removal notices disappear after this (0 = keep)
RIGHTS_HINT_S = 24 * 3600    # without the delete right, remind admins at most once a day per group
NOTICE_GAP_S = 20            # a spam wave gets one notice per group per 20 s, not one per message


@dataclass
class ChatInfo:
    admins: set = field(default_factory=set)
    can_delete: bool = False
    can_restrict: bool = False
    linked: int | None = None     # the channel whose comments this group holds
    at: float = 0.0


@dataclass
class Removed:
    """A removed message, kept in memory only so an admin can undo the removal."""
    chat_id: int
    name: str
    sender_id: int
    text: str
    level: str
    file: tuple[str, str] | None = None   # ("document" | "photo" | "video", file_id)


_chats: dict[int, ChatInfo] = {}
_removed: OrderedDict[str, Removed] = OrderedDict()
_rights_hint: dict[int, float] = {}
_last_notice: dict[int, float] = {}
_tasks: set = set()
offenses = guard.Offenses()


async def chat_info(bot: Bot, chat_id: int) -> ChatInfo:
    cached = _chats.get(chat_id)
    if cached and time.monotonic() - cached.at < ADMIN_CACHE_S:
        return cached
    info = ChatInfo(at=time.monotonic())
    try:
        for member in await bot.get_chat_administrators(chat_id):
            info.admins.add(member.user.id)
            if member.user.id == bot.id:
                info.can_delete = bool(getattr(member, "can_delete_messages", False))
                info.can_restrict = bool(getattr(member, "can_restrict_members", False))
        info.linked = (await bot.get_chat(chat_id)).linked_chat_id
    except Exception as e:   # no rights, or Telegram is slow: act as a plain member until next time
        log.warning("Could not read the admins of %s: %s", chat_id, e)
    _chats[chat_id] = info
    return info


def is_exempt(message: Message, info: ChatInfo) -> bool:
    """Admins, anonymous admins and the group's own channel are never moderated."""
    if message.is_automatic_forward:           # a channel post copied into its comments group
        return True
    if message.sender_chat is not None:         # sent "as" a group or channel
        return message.sender_chat.id in (message.chat.id, info.linked)
    user = message.from_user
    return user is None or user.is_bot or user.id in info.admins


def sender_of(message: Message) -> tuple[int, str]:
    if message.sender_chat is not None:
        return message.sender_chat.id, message.sender_chat.title or "?"
    return message.from_user.id, message.from_user.full_name


_HOST = re.compile(r"\b((?:[\w-]+\.)+[a-z]{2,})\b", re.IGNORECASE)


def defang_text(text: str) -> str:
    """uzum-sovga.xyz -> uzum-sovga[.]xyz, so a notice never carries a tappable scam link."""
    return _HOST.sub(lambda m: m.group(1).replace(".", "[.]"), text)


def delete_later(bot: Bot, chat_id: int, message_id: int, delay: int = NOTICE_TTL_S, forget: str = "") -> None:
    """Delete the bot's notice after `delay` seconds; its undo button goes with it, so the removed
    message it could restore (`forget`) is dropped from memory too."""
    if delay <= 0:
        return

    async def run() -> None:
        await asyncio.sleep(delay)
        _removed.pop(forget, None)
        with contextlib.suppress(TelegramAPIError):
            await bot.delete_message(chat_id, message_id)

    task = asyncio.create_task(run())
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)


def attached_file(message: Message) -> tuple[str, str] | None:
    if message.document:
        return "document", message.document.file_id
    if message.photo:
        return "photo", message.photo[-1].file_id
    if message.video:
        return "video", message.video.file_id
    return None


async def remove(bot: Bot, message: Message, result: Result, settings: guard.GroupSettings, info: ChatInfo) -> bool:
    try:
        await message.delete()
    except TelegramAPIError as e:              # rights were taken away since the last check
        log.warning("Could not delete a message in %s: %s", message.chat.id, e)
        _chats.pop(message.chat.id, None)
        return False
    storage.count_group_deletion(message.chat.id)
    sender_id, name = sender_of(message)
    lang = settings.lang
    now = time.monotonic()
    if now - _last_notice.get(message.chat.id, -NOTICE_GAP_S) >= NOTICE_GAP_S:
        _last_notice[message.chat.id] = now
        key = secrets.token_urlsafe(8)
        _removed[key] = Removed(message.chat.id, name, sender_id, message.text or message.caption or "",
                                result.level.value, attached_file(message))
        while len(_removed) > MAX_CACHE:
            _removed.popitem(last=False)
        reason = result.reasons[0].text(lang) if result.reasons else re.sub(r"<[^>]+>", "", t("v_dangerous", lang))
        undo = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text=t("g_undo_btn", lang),
                                                                           callback_data=f"gu:{key}")]])
        notice = await bot.send_message(
            message.chat.id, t("g_deleted", lang, name=html.escape(name), reason=html.escape(defang_text(reason))),
            reply_markup=undo, disable_web_page_preview=True)
        delete_later(bot, message.chat.id, notice.message_id, forget=key)

    if settings.mute and info.can_restrict and offenses.add(message.chat.id, sender_id) >= guard.OFFENSES_TO_MUTE:
        await mute(bot, message, name, lang)
    return True


async def mute(bot: Bot, message: Message, name: str, lang: str) -> None:
    sender_id, _ = sender_of(message)
    try:
        if message.sender_chat is not None:     # a channel identity can't be muted, only banned from posting
            await bot.ban_chat_sender_chat(message.chat.id, sender_id)
        else:
            await bot.restrict_chat_member(message.chat.id, sender_id, ChatPermissions(can_send_messages=False),
                                           until_date=int(time.time()) + guard.MUTE_S)
    except TelegramAPIError as e:
        log.warning("Could not mute %s in %s: %s", sender_id, message.chat.id, e)
        return
    offenses.clear(message.chat.id, sender_id)
    note = await bot.send_message(message.chat.id, t("g_muted", lang, name=html.escape(name), n=guard.OFFENSES_TO_MUTE))
    delete_later(bot, message.chat.id, note.message_id)


async def warn(bot: Bot, message: Message, result: Result, settings: guard.GroupSettings, info: ChatInfo) -> None:
    lang = settings.lang
    lines = [t("group_warn", lang)] + [f"• {html.escape(r.text(lang))}" for r in result.reasons[:3]]
    lines.append(f"\n💡 {t('group_warn_tail', lang)}")
    now = time.time()
    if settings.mode == "delete" and not info.can_delete and now - _rights_hint.get(message.chat.id, 0) > RIGHTS_HINT_S:
        _rights_hint[message.chat.id] = now
        lines.append(t("g_need_rights", lang))
    await message.reply("\n".join(lines), disable_web_page_preview=True)


async def guard_message(message: Message, bot: Bot, edited: bool = False) -> None:
    """Check a group message; remove it, warn, or stay silent (see guard.py)."""
    result = evaluate(message)
    if result is None:
        return
    if not edited:
        record(result)
    settings = storage.group_settings(message.chat.id)
    if guard.decide(result.level, result.signals, settings, can_delete=True) == guard.NONE:
        return                                   # nothing to do: no admin lookup for normal messages
    info = await chat_info(bot, message.chat.id)
    if is_exempt(message, info):
        return
    action = guard.decide(result.level, result.signals, settings, info.can_delete)
    if action == guard.DELETE and await remove(bot, message, result, settings, info):
        return
    if action != guard.NONE and result.level == Level.DANGEROUS:
        await warn(bot, message, result, settings, info)


# ---- admin settings ----

def settings_view(settings: guard.GroupSettings, info: ChatInfo) -> tuple[str, InlineKeyboardMarkup]:
    lang = settings.lang
    onoff = lambda v: t("g_on" if v else "g_off", lang)  # noqa: E731
    rights = t("g_can_delete" if info.can_delete else "g_cannot_delete", lang)
    if settings.mute and info.can_delete and not info.can_restrict:
        rights += "\n" + t("g_cannot_mute", lang)
    text = t("g_settings", lang, mode=t(f"g_mode_{settings.mode}", lang), strict=onoff(settings.strict),
             mute=onoff(settings.mute), deleted=settings.deleted, rights=rights)
    b = InlineKeyboardButton
    markup = InlineKeyboardMarkup(inline_keyboard=[
        [b(text=f"{t('g_btn_mode', lang)}: {t(f'g_mode_{settings.mode}', lang)}", callback_data="gs:mode")],
        [b(text=f"{t('g_btn_strict', lang)}: {onoff(settings.strict)}", callback_data="gs:strict"),
         b(text=f"{t('g_btn_mute', lang)}: {onoff(settings.mute)}", callback_data="gs:mute")],
        [b(text=f"{t('g_btn_lang', lang)}: {LANG_NAMES[lang]}", callback_data="gs:lang")],
    ])
    return text, markup


async def is_group_admin(bot: Bot, chat_id: int, user) -> bool:
    if user is None:
        return False
    info = await chat_info(bot, chat_id)
    if user.id in info.admins:
        return True
    _chats.pop(chat_id, None)                 # maybe just promoted: look again once
    return user.id in (await chat_info(bot, chat_id)).admins


@groups.message(Command("settings"))
async def group_settings_cmd(message: Message, bot: Bot) -> None:
    settings = storage.group_settings(message.chat.id)
    anonymous_admin = message.sender_chat is not None and message.sender_chat.id == message.chat.id
    if not anonymous_admin and not await is_group_admin(bot, message.chat.id, message.from_user):
        await message.reply(t("g_admins_only", settings.lang))
        return
    text, markup = settings_view(settings, await chat_info(bot, message.chat.id))
    await message.reply(text, reply_markup=markup)


# The catch-all scanners come after every group command, so commands reach their own handlers.
@groups.message(F.text | F.caption | F.document)
async def group_scan(message: Message, bot: Bot) -> None:
    await guard_message(message, bot)


@groups.edited_message(F.text | F.caption)
async def group_edit(message: Message, bot: Bot) -> None:
    """Spammers post something harmless and edit a link in later."""
    await guard_message(message, bot, edited=True)


@dp.callback_query(F.data.startswith("gs:"))
async def on_group_setting(callback: CallbackQuery, bot: Bot) -> None:
    if callback.message is None:
        return
    chat_id = callback.message.chat.id
    settings = storage.group_settings(chat_id)
    if not await is_group_admin(bot, chat_id, callback.from_user):
        await callback.answer(t("g_admins_only", settings.lang), show_alert=True)
        return
    what = callback.data.split(":", 1)[1]
    if what == "mode":
        settings.mode = guard.MODES[(guard.MODES.index(settings.mode) + 1) % len(guard.MODES)]
    elif what == "strict":
        settings.strict = not settings.strict
    elif what == "mute":
        settings.mute = not settings.mute
    elif what == "lang":
        settings.lang = LANGS[(LANGS.index(settings.lang) + 1) % len(LANGS)]
    storage.save_group_settings(chat_id, settings)
    await callback.answer()
    text, markup = settings_view(settings, await chat_info(bot, chat_id))
    with contextlib.suppress(TelegramBadRequest):
        await callback.message.edit_text(text, reply_markup=markup)


@dp.callback_query(F.data.startswith("gu:"))
async def on_group_undo(callback: CallbackQuery, bot: Bot) -> None:
    """An admin says a removal was a mistake: put the message back and learn from it."""
    if callback.message is None:
        return
    chat_id = callback.message.chat.id
    lang = storage.group_settings(chat_id).lang
    if not await is_group_admin(bot, chat_id, callback.from_user):
        await callback.answer(t("g_admins_only", lang), show_alert=True)
        return
    item = _removed.pop(callback.data.split(":", 1)[1], None)
    if item is None or item.chat_id != chat_id:
        await callback.answer(t("g_undo_gone", lang), show_alert=True)
        return
    head = t("g_restored", lang, name=html.escape(item.name))
    body = f"{head}\n\n{html.escape(item.text)}" if item.text else head
    if item.file:
        kind, file_id = item.file
        send = {"document": bot.send_document, "photo": bot.send_photo, "video": bot.send_video}[kind]
        await send(chat_id, file_id, caption=body[:1024])
    else:
        await bot.send_message(chat_id, body[:4096], disable_web_page_preview=True)
    if item.text:
        storage.add_feedback(item.text, 0, item.level, False)   # a false alarm: training data for the model
    offenses.clear(chat_id, item.sender_id)
    await callback.answer()
    with contextlib.suppress(TelegramAPIError):
        await callback.message.delete()


@dp.my_chat_member()
async def on_bot_status(event: ChatMemberUpdated) -> None:
    """Added to a group, promoted or demoted: forget the cached rights, greet on joining."""
    _chats.pop(event.chat.id, None)
    if event.chat.type not in (ChatType.GROUP, ChatType.SUPERGROUP):
        return
    gone = ("left", "kicked")
    if event.old_chat_member.status in gone and event.new_chat_member.status not in gone:
        settings = storage.group_settings(event.chat.id)
        settings.lang = lang_of(event.from_user)    # the person who added the bot picks the language
        storage.save_group_settings(event.chat.id, settings)
        await event.bot.send_message(event.chat.id, t("group_hello", settings.lang))


# ======================= inline mode =======================

@dp.inline_query()
async def on_inline(query: InlineQuery) -> None:
    lang = lang_of(query.from_user)
    text = query.query.strip()
    open_bot = InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=t("inline_btn", lang), url=f"https://t.me/{BOT_USERNAME}?start=inline")]])
    if len(text) < 4:
        result = InlineQueryResultArticle(
            id="help", title=t("inline_help_title", lang),
            description=t("inline_help_desc", lang, bot=BOT_USERNAME),
            input_message_content=InputTextMessageContent(message_text=t("inline_help_msg", lang, bot=BOT_USERNAME)),
            reply_markup=open_bot,
        )
        await query.answer([result], cache_time=300, is_personal=True)
        return

    r = evaluate_text(text)
    headline = t(f"v_{r.level.value}", lang).replace("<b>", "").replace("</b>", "")
    top_reason = r.reasons[0].text(lang) if r.reasons else (r.trust[0].text(lang) if r.trust else t("inline_safe_desc", lang))
    snippet = " ".join(text.split())
    snippet = snippet[:120] + ("…" if len(snippet) > 120 else "")
    body = render(lang, r).split("\n", 1)          # verdict header + details
    message = (f"{body[0]}\n{t('inline_checked', lang)}: <code>{html.escape(snippet)}</code>\n{body[1]}"
               f"\n\n<i>{t('inline_by', lang, bot=BOT_USERNAME)}</i>")
    result = InlineQueryResultArticle(
        id=f"v{abs(hash(text)) % 10**12}",
        title=headline if r.level == Level.SAFE else f"{headline} · {round(r.score * 100)}%",
        description=top_reason[:120],
        input_message_content=InputTextMessageContent(message_text=message, link_preview_options={"is_disabled": True}),
        reply_markup=open_bot,
    )
    await query.answer([result], cache_time=30, is_personal=True)


@dp.chosen_inline_result()
async def on_inline_chosen(chosen: ChosenInlineResult) -> None:
    """Counts inline checks in the stats (needs /setinlinefeedback in @BotFather)."""
    if chosen.result_id != "help":
        record(evaluate_text(chosen.query))


# ======================= callbacks =======================

@dp.callback_query(F.data.startswith("lang:"))
async def on_lang(callback: CallbackQuery) -> None:
    lang = callback.data.split(":", 1)[1]
    if lang not in LANGS:
        return
    storage.set_lang(callback.from_user.id, lang)
    await callback.answer(t("lang_set", lang))
    if callback.message:
        await callback.message.edit_text(t("lang_set", lang))
        await callback.message.answer(t("welcome", lang, name=html.escape(callback.from_user.first_name)),
                                      reply_markup=main_menu(lang))


@dp.callback_query(F.data.startswith("type:"))
async def on_type(callback: CallbackQuery) -> None:
    lang = lang_of(callback.from_user)
    tid = callback.data.split(":", 1)[1]
    item = next((x for x in SCAM_TYPES[lang] if x[0] == tid), None)
    await callback.answer()
    if item is None or callback.message is None:
        return
    _, title, how, flag = item
    back = InlineKeyboardMarkup(inline_keyboard=[[InlineKeyboardButton(text=t("back", lang), callback_data="types:back")]])
    await callback.message.edit_text(f"<b>{title}</b>\n\n🎭 {how}\n\n🚩 {flag}", reply_markup=back)


@dp.callback_query(F.data == "types:back")
async def on_types_back(callback: CallbackQuery) -> None:
    lang = lang_of(callback.from_user)
    await callback.answer()
    if callback.message:
        await callback.message.edit_text(t("types_title", lang), reply_markup=types_keyboard(lang))


async def _update_buttons(callback: CallbackQuery, key: str, p: Pending, lang: str) -> None:
    if callback.message is None:
        return
    try:
        await callback.message.edit_reply_markup(
            reply_markup=verdict_keyboard(key, lang, feedback=not p.feedback_done, report=not p.reported))
    except TelegramBadRequest:
        pass


def record_report(p: Pending, reporter_id: int, lang: str) -> str | None:
    """Save a scam report. Returns the confirmation text, or None if this person already reported all of it."""
    if not p.feedback_done and p.text:
        storage.add_feedback(p.text, 1, p.level, p.level != Level.SAFE.value)
        p.feedback_done = True
    first_report = not p.reported
    p.reported = True
    remembered = first_report and memory.add(p.text, reporter_id)
    indicators = blocklist.extract(p.text, p.forward, {BOT_USERNAME.lower()})
    if not indicators:
        if remembered:
            return t("report_none", lang, threshold=blocklist.REPORT_THRESHOLD)
        return t("report_none_plain", lang) if first_report else None
    if storage.add_reports(indicators, reporter_id) == 0:
        return None
    items = "\n".join(f"• {html.escape(i.preview)}" for i in indicators)
    return t("report_done", lang, items=items, threshold=blocklist.REPORT_THRESHOLD)


@dp.callback_query(F.data.startswith("fb:"))
async def on_feedback(callback: CallbackQuery) -> None:
    lang = lang_of(callback.from_user)
    _, answer, key = callback.data.split(":", 2)
    p = _pending.get(key)
    if p is None:
        await callback.answer(t("fb_expired", lang))
        return
    if not p.feedback_done:
        predicted_scam = p.level != Level.SAFE.value
        label = int(predicted_scam if answer == "ok" else not predicted_scam)
        storage.add_feedback(p.text, label, p.level, answer == "ok")
        p.feedback_done = True
        if label == 1 and not predicted_scam and not p.reported:   # "you said safe, but it's a scam"
            memory.add(p.text, callback.from_user.id)
    await callback.answer(t("fb_thanks", lang))
    await _update_buttons(callback, key, p, lang)


@dp.callback_query(F.data.startswith("rep:"))
async def on_report(callback: CallbackQuery) -> None:
    lang = lang_of(callback.from_user)
    key = callback.data.split(":", 1)[1]
    p = _pending.get(key)
    if p is None:
        await callback.answer(t("fb_expired", lang))
        return
    if rate_limited(callback.from_user.id):
        await callback.answer(t("rate_limited", lang))
        return
    confirmation = record_report(p, callback.from_user.id, lang)
    if confirmation is None:
        await callback.answer(t("report_dup", lang))
    else:
        await callback.answer()
        if callback.message:
            await callback.message.reply(confirmation)
    await _update_buttons(callback, key, p, lang)


@dp.errors()
async def on_error(event: ErrorEvent) -> bool:
    log.exception("Error while handling an update: %s", event.exception)
    return True  # keep the bot running


# ======================= startup =======================

async def setup_profile(bot: Bot) -> None:
    """Set the description, short description and command menu in every language."""
    private_cmds = ["start", "help", "sos", "types", "lang", "privacy"]
    for code in (None, *LANGS):
        lang = code or "uz"
        try:
            await bot.set_my_commands(
                [BotCommand(command=c, description=t(f"cmd_{c}", lang)) for c in private_cmds],
                scope=BotCommandScopeDefault(), language_code=code,
            )
            await bot.set_my_commands(
                [BotCommand(command=c, description=t(f"cmd_{c}", lang)) for c in ("check", "report", "settings", "help")],
                scope=BotCommandScopeAllGroupChats(), language_code=code,
            )
            # The bio is shown in Uzbek to everyone, whatever language their Telegram app uses.
            description = bot_description()
            if (await bot.get_my_description(language_code=code)).description != description:
                await bot.set_my_description(description, language_code=code)
            if (await bot.get_my_short_description(language_code=code)).short_description != t("bot_short", "uz"):
                await bot.set_my_short_description(t("bot_short", "uz"), language_code=code)
        except TelegramBadRequest as e:
            log.warning("Could not update bot profile for %s: %s", lang, e)
    if RADAR_URL:
        try:   # the chat's Menu button opens the Scam Radar Mini App
            await bot.set_chat_menu_button(menu_button=MenuButtonWebApp(
                text=t("menu_radar", "uz"), web_app=WebAppInfo(url=RADAR_URL)))
        except TelegramBadRequest as e:
            log.warning("Could not set the Mini App menu button: %s", e)


def bot_description() -> str:
    """Uzbek bio, with the Scam Radar link when there is room (Telegram limit: 512 characters)."""
    text = t("bot_description", "uz")
    if RADAR_URL:
        head, sep, tail = text.rpartition("\n\n")
        with_link = f"{head}\n🌐 Radar: {RADAR_URL.removeprefix('https://')}{sep}{tail}"
        if len(with_link) <= 512:
            return with_link
    return text


async def main() -> None:
    global BOT_USERNAME
    token = (os.getenv("BOT_TOKEN") or "").strip().strip('"').strip("'")
    if not token:
        raise SystemExit("❌ No token found. Put BOT_TOKEN=... in the .env file, or add a BOT_TOKEN variable on your server "
            "(Railway → Variables). Get the token from @BotFather.")
    if not re.fullmatch(r"\d{6,}:[A-Za-z0-9_-]{30,}", token):
        raise SystemExit(
            f"❌ That doesn't look like a bot token (got {len(token)} characters starting with '{token[:3]}...').\n"
            "   A real token looks like 1234567890:AAH... (numbers, a colon, then ~35 letters).\n"
            "   Copy it again from @BotFather and retry."
        )
    bot = Bot(token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    try:
        me = await bot.get_me()
    except (TelegramUnauthorizedError, TelegramNotFound):
        await bot.session.close()
        raise SystemExit(
            "❌ Telegram rejected this token. It was probably revoked or copied wrong.\n"
            "   Open @BotFather, send /revoke (or /token), copy the NEWEST token and run again."
        )
    BOT_USERNAME = me.username
    if semantic.available():   # load the transformer now, so the first user doesn't wait for it
        await asyncio.to_thread(semantic.predict_proba, "salom")
        log.info("Semantic AI model loaded (%s)", semantic.HF_REPO)
    else:
        log.warning("Semantic AI model not available: using the char n-gram model only")
    await setup_profile(bot)
    dp.include_routers(private, groups)
    # Public Scam Radar website on $PORT (Railway: Settings -> Networking -> Generate Domain)
    web_app = radar_web.build_app(lambda: storage, lambda: BOT_USERNAME, blocklist.REPORT_THRESHOLD, check=web_check)
    await radar_web.start(web_app)
    log.info("Scam Radar website listening on port %s", os.getenv("PORT", "8080"))
    log.info("ScamGuard bot started as @%s", me.username)
    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())


if __name__ == "__main__":
    asyncio.run(main())
