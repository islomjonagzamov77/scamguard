"""ScamGuard Telegram bot.

Private chat: forward a suspicious message, link or file and get an explained
verdict in Uzbek, Russian or English. Menu: how-to, SOS guide, scam types,
statistics, language, share.

Groups: silently scans every message (when the bot is an admin or privacy
mode is off) and warns only about dangerous ones. /check as a reply scans
a specific message.

Run:  python bot.py      (token in .env as BOT_TOKEN=...)
"""

from __future__ import annotations

import asyncio
import html
import logging
import os
import re
import secrets
import time
from collections import OrderedDict, defaultdict, deque
from urllib.parse import quote

from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ChatType, MessageEntityType, ParseMode
from aiogram.exceptions import TelegramBadRequest, TelegramNotFound, TelegramUnauthorizedError
from aiogram.filters import JOIN_TRANSITION, ChatMemberUpdatedFilter, Command, CommandStart
from aiogram.types import (
    BotCommand, BotCommandScopeAllGroupChats, BotCommandScopeDefault, CallbackQuery, ChatMemberUpdated,
    ErrorEvent, InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, Message, ReplyKeyboardMarkup,
)

from scamguard.analyzer import Level, analyze
from scamguard.files import check_file
from scamguard.i18n import LANG_NAMES, LANGS, SCAM_TYPES, all_variants, guess_lang, t
from scamguard.storage import Storage

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
dp = Dispatcher()
private = Router(name="private")
groups = Router(name="groups")
private.message.filter(F.chat.type == ChatType.PRIVATE)
groups.message.filter(F.chat.type.in_({ChatType.GROUP, ChatType.SUPERGROUP}))

_pending: OrderedDict[str, tuple[str, str]] = OrderedDict()   # feedback key -> (text, predicted level)
_hits: dict[int, deque] = defaultdict(deque)                   # user id -> recent check times
BOT_USERNAME = ""


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
    return ReplyKeyboardMarkup(
        keyboard=[[b("btn_check"), b("btn_types")], [b("btn_sos"), b("btn_stats")], [b("btn_share"), b("btn_lang")]],
        resize_keyboard=True,
        input_field_placeholder="📩 Forward…",
    )


def lang_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=LANG_NAMES[code], callback_data=f"lang:{code}") for code in LANGS
    ]])


def feedback_keyboard(key: str, lang: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[[
        InlineKeyboardButton(text=t("fb_ok", lang), callback_data=f"fb:ok:{key}"),
        InlineKeyboardButton(text=t("fb_no", lang), callback_data=f"fb:no:{key}"),
    ]])


def remember(text: str, level: Level) -> str:
    key = secrets.token_urlsafe(8)
    _pending[key] = (text, level.value)
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


def evaluate(message: Message):
    """Return (level, reasons, score, file_level, text) for any text/caption/document message."""
    text = full_text(message)
    file_level, reasons, score = None, [], 0.0
    doc = message.document
    if doc is not None:
        fv = check_file(doc.file_name, doc.mime_type)
        file_level, reasons = fv.level, list(fv.reasons)
        text = " ".join(filter(None, [text, doc.file_name]))
    if not text and doc is None:
        return None
    verdict = analyze(text) if text else None
    levels = [lv for lv in (file_level, verdict.level if verdict else None) if lv is not None]
    level = max(levels, key=LEVEL_ORDER.index)
    if verdict:
        reasons += verdict.reasons
        score = verdict.score
    if file_level == Level.DANGEROUS:
        score = max(score, 0.95)
    elif file_level == Level.SUSPICIOUS:
        score = max(score, 0.5)
    return level, reasons, score, file_level, text


def render(lang: str, level: Level, reasons, score: float, file_name: str | None = None,
           file_level: Level | None = None, source: str | None = None) -> str:
    lines = [t(f"v_{level.value}", lang), f"{t('risk', lang)}: <b>{round(score * 100)}%</b>"]
    if file_name:
        lines.append(f"{t('file', lang)}: <code>{html.escape(file_name)}</code>")
    if source:
        lines.append(f"{t('source', lang)}: {html.escape(source)}")
    if reasons:
        lines.append(f"\n<b>{t('why', lang)}</b>")
        lines += [f"• {html.escape(r.text(lang))}" for r in reasons[:8]]
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


@private.message(Command("lang"))
@private.message(F.text.in_(all_variants("btn_lang")))
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
    await message.answer(t("stats", lang_of(message.from_user), **storage.stats()))


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


@private.message(F.text | F.caption | F.document)
async def on_check(message: Message) -> None:
    lang = lang_of(message.from_user)
    if rate_limited(message.from_user.id):
        await message.reply(t("rate_limited", lang))
        return
    result = evaluate(message)
    if result is None:
        await message.reply(t("empty", lang))
        return
    level, reasons, score, file_level, text = result
    storage.record_check(level.value)
    doc = message.document
    reply = render(lang, level, reasons, score, doc.file_name if doc else None, file_level, forward_source(message))
    key = remember(text, level) if text else None
    await message.reply(reply, reply_markup=feedback_keyboard(key, lang) if key else None,
                        disable_web_page_preview=True)


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
    result = evaluate(target)
    if result is None:
        await message.reply(t("empty", lang))
        return
    level, reasons, score, file_level, _ = result
    storage.record_check(level.value)
    doc = target.document
    await target.reply(render(lang, level, reasons, score, doc.file_name if doc else None, file_level),
                       disable_web_page_preview=True)


@groups.message(Command("help", "start"))
async def group_help(message: Message) -> None:
    await message.reply(t("group_hello", lang_of(message.from_user)))


@groups.message(F.text | F.caption | F.document)
async def group_scan(message: Message) -> None:
    """Silent guard: speak up only when a message is dangerous."""
    if message.from_user and message.from_user.is_bot:
        return
    result = evaluate(message)
    if result is None:
        return
    level, reasons, *_ = result
    storage.record_check(level.value)
    if level != Level.DANGEROUS:
        return
    lang = lang_of(message.from_user)
    lines = [t("group_warn", lang)] + [f"• {html.escape(r.text(lang))}" for r in reasons[:3]]
    lines.append(f"\n💡 {t('group_warn_tail', lang)}")
    await message.reply("\n".join(lines), disable_web_page_preview=True)


@dp.my_chat_member(ChatMemberUpdatedFilter(member_status_changed=JOIN_TRANSITION))
async def on_added_to_group(event: ChatMemberUpdated) -> None:
    if event.chat.type in (ChatType.GROUP, ChatType.SUPERGROUP):
        await event.bot.send_message(event.chat.id, t("group_hello", lang_of(event.from_user)))


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


@dp.callback_query(F.data.startswith("fb:"))
async def on_feedback(callback: CallbackQuery) -> None:
    lang = lang_of(callback.from_user)
    _, answer, key = callback.data.split(":", 2)
    item = _pending.pop(key, None)
    if item is None:
        await callback.answer(t("fb_expired", lang))
        return
    text, predicted = item
    predicted_scam = predicted != Level.SAFE.value
    label = int(predicted_scam if answer == "ok" else not predicted_scam)
    storage.add_feedback(text, label, predicted, answer == "ok")
    await callback.answer(t("fb_thanks", lang))
    if callback.message:
        try:
            await callback.message.edit_reply_markup(reply_markup=None)
        except TelegramBadRequest:
            pass


@dp.errors()
async def on_error(event: ErrorEvent) -> bool:
    log.exception("Error while handling an update: %s", event.exception)
    return True  # keep the bot running


# ======================= startup =======================

async def setup_profile(bot: Bot) -> None:
    """Set the description, short description and command menu in every language."""
    private_cmds = ["start", "help", "sos", "types", "stats", "lang", "privacy"]
    for code in (None, *LANGS):
        lang = code or "uz"
        try:
            await bot.set_my_commands(
                [BotCommand(command=c, description=t(f"cmd_{c}", lang)) for c in private_cmds],
                scope=BotCommandScopeDefault(), language_code=code,
            )
            await bot.set_my_commands(
                [BotCommand(command=c, description=t(f"cmd_{c}", lang)) for c in ("check", "help")],
                scope=BotCommandScopeAllGroupChats(), language_code=code,
            )
            if (await bot.get_my_description(language_code=code)).description != t("bot_description", lang):
                await bot.set_my_description(t("bot_description", lang), language_code=code)
            if (await bot.get_my_short_description(language_code=code)).short_description != t("bot_short", lang):
                await bot.set_my_short_description(t("bot_short", lang), language_code=code)
        except TelegramBadRequest as e:
            log.warning("Could not update bot profile for %s: %s", lang, e)


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
    await setup_profile(bot)
    dp.include_routers(private, groups)
    log.info("ScamGuard bot started as @%s", me.username)
    await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())


if __name__ == "__main__":
    asyncio.run(main())
