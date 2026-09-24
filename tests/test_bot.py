"""End-to-end bot tests with a fake Telegram server (no network, no real token)."""

import asyncio
import importlib
from datetime import datetime

import pytest
from aiogram import Bot
from aiogram.client.session.base import BaseSession
from aiogram.methods import GetMe, TelegramMethod
from aiogram.types import CallbackQuery, Chat, Document, Message, Update, User


class FakeSession(BaseSession):
    """Records every API call and returns a plausible response."""

    def __init__(self):
        super().__init__()
        self.calls: list[TelegramMethod] = []

    async def make_request(self, bot, method, timeout=None):
        self.calls.append(method)
        if isinstance(method, GetMe):
            return User(id=1, is_bot=True, first_name="ScamGuard", username="scamguard_test_bot")
        name = type(method).__name__
        if name.startswith("Send") or name.startswith("Edit"):
            return Message(message_id=999, date=datetime.now(), chat=Chat(id=getattr(method, "chat_id", 1) or 1,
                           type="private"), text=getattr(method, "text", ""))
        return True

    async def close(self):
        pass

    async def stream_content(self, *a, **k):  # pragma: no cover
        yield b""

    def sent_texts(self):
        return [getattr(c, "text", "") for c in self.calls if getattr(c, "text", None)]


USER = User(id=42, is_bot=False, first_name="Islom", language_code="uz")
PRIVATE = Chat(id=42, type="private")
GROUP = Chat(id=-100, type="supergroup", title="Test group")
_uid = iter(range(1, 10_000))


def msg(text=None, chat=PRIVATE, document=None, reply_to=None):
    return Message(message_id=next(_uid), date=datetime.now(), chat=chat, from_user=USER,
                   text=text, document=document, reply_to_message=reply_to)


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMGUARD_SALT", "test")
    import scamguard.storage as st
    monkeypatch.setattr(st, "DATA_DIR", tmp_path)
    import bot as botmod
    botmod = importlib.reload(botmod)
    botmod.storage = st.Storage(tmp_path / "t.db")
    botmod.BOT_USERNAME = "scamguard_test_bot"
    botmod.dp.include_routers(botmod.private, botmod.groups)
    session = FakeSession()
    bot = Bot("123456:" + "A" * 35, session=session)

    def feed(obj):
        update = Update(update_id=next(_uid), **obj)
        asyncio.run(botmod.dp.feed_update(bot, update))
        return session.sent_texts()[-1] if session.sent_texts() else ""

    return botmod, session, feed


def test_first_start_asks_language_then_welcomes(env):
    botmod, session, feed = env
    assert "Choose language" in feed({"message": msg("/start")})
    cb = CallbackQuery(id="1", from_user=USER, chat_instance="x", data="lang:ru", message=msg("x"))
    feed({"callback_query": cb})
    assert "Привет" in session.sent_texts()[-1]
    assert "Привет" in feed({"message": msg("/start")})


def test_scam_text_in_russian(env):
    botmod, session, feed = env
    botmod.storage.set_lang(USER.id, "ru")
    reply = feed({"message": msg("Kartangiz bloklandi! SMS kodni yuboring")})
    assert "Опасно" in reply or "Подозрительно" in reply
    assert "SMS" in reply


def test_menu_buttons(env):
    botmod, session, feed = env
    botmod.storage.set_lang(USER.id, "uz")
    assert "102" in feed({"message": msg("🆘 Aldandim — nima qilay?")})
    assert "Firibgarlik turlari" in feed({"message": msg("📚 Firibgarlik turlari")})
    assert "statistikasi" in feed({"message": msg("📊 Statistika")})
    assert "Forward" in feed({"message": msg("🔍 Qanday tekshiraman?")})
    feed({"message": msg("📤 Do'stlarga ulashish")})
    markup = session.calls[-1].reply_markup
    assert markup.inline_keyboard[0][0].url.startswith("https://t.me/share/url")


def test_scam_type_detail(env):
    botmod, session, feed = env
    botmod.storage.set_lang(USER.id, "en")
    cb = CallbackQuery(id="2", from_user=USER, chat_instance="x", data="type:apk", message=msg("x"))
    feed({"callback_query": cb})
    assert "Play Store" in session.sent_texts()[-1]


def test_pdf_and_apk_files(env):
    botmod, session, feed = env
    botmod.storage.set_lang(USER.id, "uz")
    pdf = Document(file_id="a", file_unique_id="a", file_name="EL YURT 1-xona ANSWERS.pdf", mime_type="application/pdf")
    assert "🟢" in feed({"message": msg(document=pdf)})
    apk = Document(file_id="b", file_unique_id="b", file_name="Rasm.jpg.apk")
    reply = feed({"message": msg(document=apk)})
    assert "🔴" in reply and ".jpg.apk" in reply


def test_stats_count_checks(env):
    botmod, session, feed = env
    botmod.storage.set_lang(USER.id, "en")
    feed({"message": msg("Hello, how are you?")})
    feed({"message": msg("You won a prize! Claim your prize at c1ick-bonus.xyz")})
    s = botmod.storage.stats()
    assert s["checks"] == 2 and s["dangerous"] == 1 and s["users"] == 1


def test_feedback_is_masked(env):
    botmod, session, feed = env
    botmod.storage.set_lang(USER.id, "uz")
    feed({"message": msg("Kartangiz bloklandi 8600 1234 5678 9012 SMS kodni yuboring")})
    data = session.calls[-1].reply_markup.inline_keyboard[0][0].callback_data
    cb = CallbackQuery(id="3", from_user=USER, chat_instance="x", data=data, message=msg("x"))
    feed({"callback_query": cb})
    row = botmod.storage.db.execute("SELECT text, label FROM feedback").fetchone()
    assert "8600" not in row[0] and row[1] == 1


def test_group_silent_on_normal_warns_on_scam(env):
    botmod, session, feed = env
    n = len(session.calls)
    feed({"message": msg("Salom hammaga, ertaga dars bormi?", chat=GROUP)})
    assert len(session.calls) == n  # stayed silent
    reply = feed({"message": msg("Tabriklaymiz! iPhone yutdingiz, 24 soat ichida click-uz-bonus.xyz ga kiring", chat=GROUP)})
    assert "Diqqat" in reply


def test_group_check_command(env):
    botmod, session, feed = env
    target = msg("Вы выиграли приз! Срочно bit.ly/abc", chat=GROUP)
    reply = feed({"message": msg("/check", chat=GROUP, reply_to=target)})
    assert "🔴" in reply or "🟡" in reply


def test_rate_limit(env):
    botmod, session, feed = env
    botmod.storage.set_lang(USER.id, "en")
    for _ in range(botmod.RATE_LIMIT[0]):
        feed({"message": msg("hello")})
    assert "Too fast" in feed({"message": msg("hello")})
