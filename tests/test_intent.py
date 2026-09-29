"""Intent: request vs warning vs report vs quote.

These are development examples. The frozen test set in data/eval/ is never used to
write or tune the intent rules (see data/eval/LABELING_GUIDE.md).
"""

import pytest

from scamguard.analyzer import Level, analyze
from scamguard.intent import detect

CASES = [
    # --- scams that hide behind warning words: the ask must win -------------------------
    ("Diqqat! Firibgarlardan ehtiyot bo'ling. Kartangizni himoya qilish uchun havolaga kiring: payme-himoya.site",
     "request", "flag"),
    ("Hurmatli mijoz, hisobingiz bloklandi. Kodni hech kimga aytmang, faqat operatorimizga ayting.", "request", "flag"),
    ("Bank xodimlari hech qachon kod so'ramaydi. Lekin hozir tasdiqlash uchun kelgan kodni shu botga yuboring.",
     "request", "flag"),
    ("Beware of scammers! To protect your account, send the code we just texted you.", "request", "flag"),
    ("Ona, hech kimga aytma, menga zudlik bilan pul kerak, keyin hammasini tushuntiraman", "request", "flag"),
    ("Мама, это я, попал в беду, срочно нужны деньги, никому не говори", "request", "flag"),
    # --- a story that still carries a live scam link: the link is judged on its own -------
    ("Kecha menga shu sayt keldi: click-bonus.xyz", "report", "flag"),
    # --- someone pastes a scam and asks about it: judge the pasted message --------------
    ("Menga shunday SMS keldi: \"Siz 5 mln yutdingiz, olish uchun kartangiz raqamini yuboring\". Bu rostmi?",
     "quote", "flag"),
    # --- real warnings and stories: safe, and no "asks for your code" claim ---------------
    ("Payme: kodni hech kimga bermang. Kod: 4821", "warning", "safe"),
    ("Ehtiyot bo'ling: \"Siz iPhone yutdingiz, kartangizni kiriting\" degan xabarlar firibgarlik.", "warning", "safe"),
    ("Agar kimdir kodni yuboring desa, bermang.", "warning", "safe"),
    ("Никогда не сообщайте код из СМС, банк никогда не просит его по телефону.", "warning", "safe"),
    ("Мне вчера написали, что я выиграл приз и надо назвать код из смс, я не поверил.", "report", "safe"),
    ("Onamga \"kartangiz bloklandi, kodni yuboring\" deb SMS kelibdi, biz bankka bordik.", "report", "safe"),
    # --- stories told with single quotes or about other people --------------------------
    ("Opamga 'hisobingiz bloklandi, kodni ayting' deb qo'ng'iroq qilishibdi, u go'shakni qo'yibdi.", "report", "safe"),
    ("Jiyanim soxta saytga karta ma'lumotini kiritibdi, keyin kartadan pul yechilibdi.", "report", "safe"),
    ("Коллеге написали, что посылка на таможне, она перешла по ссылке и ввела данные карты.", "report", "safe"),
    # --- secrecy is a red flag, not advice -------------------------------------------------
    ("Aksiya: 500$ qo'shsangiz, bir haftada 1500$ qaytaramiz. Hech kimga aytmang, joy kam.", "request", "flag"),
    ("I need only $600 for the customs fee. Please send it today and don't tell your parents.", "request", "flag"),
    ("Мама, я в беде, срочно отдай деньги человеку, который придёт, никому не говори.", "request", "flag"),
    # --- a story first, then the ask -------------------------------------------------------
    ("Aka, men hozir Toshkentda emasman, telefonim o'chib qoldi. 500 ming tashlab tur, ertaga qaytaraman.",
     "request", "flag"),
    # --- safe advice phrased as a request ----------------------------------------------------
    ("Ofisga .apk fayl kelsa ochmanglar, darhol IT bo'limga xabar beringlar.", "warning", "safe"),
    # --- nothing to decide -------------------------------------------------------------
    ("Ertaga soat 10 da uchrashamiz.", "info", "safe"),
]


@pytest.mark.parametrize("text,intent,expect", CASES, ids=[c[0][:40] for c in CASES])
def test_intent_and_verdict(text, intent, expect):
    v = analyze(text)
    assert v.intent.kind == intent
    if expect == "flag":
        assert v.level != Level.SAFE, f"missed ({v.score:.2f})"
    else:
        assert v.level == Level.SAFE, f"false alarm ({v.score:.2f}): {[r.en for r in v.reasons]}"
        assert not v.reasons


def test_explanation_quotes_the_ask():
    v = analyze("Hisobingiz bloklandi. Tasdiqlash uchun SMS kodni shu botga yuboring.")
    assert v.reasons[0].en == "The message asks you to do this: «Tasdiqlash uchun SMS kodni shu botga yuboring.»"


def test_warning_is_explained_with_its_own_words():
    v = analyze("Eslatma: SMS kodni hech kimga aytmang, bank uni hech qachon so'ramaydi.")
    assert v.level == Level.SAFE
    assert "doesn't ask you for anything" in v.trust[0].en and "hech kimga aytmang" in v.trust[0].en


def test_warning_about_a_link_does_not_hide_the_link():
    v = analyze("Ehtiyot bo'ling, bu sayt soxta, unga kirmang: c1ick-bonus.online")
    assert v.intent.kind == "warning" and v.level != Level.SAFE
    assert not any("SMS" in r.en for r in v.reasons)        # only the link is blamed


def test_evidence_never_echoes_card_numbers():
    ev = detect("Pulni 8600 1234 5678 9012 kartaga hoziroq tashlang").evidence
    assert "1234" not in ev and "<CARD>" in ev


@pytest.mark.parametrize("text", [
    "Buyurtmangiz uchun 80 000 so'mni shu kartaga o'tkazing.",
    "Oldindan 30% to'lov qilsangiz, ertaga yetkazib beramiz.",
    "Please pay the $40 deposit to book the room.",
])
def test_money_request_without_scam_signs_asks_a_question(text):
    """Could be a real shop or a scammer: 🟡 plus a question, never a confident 🟢 or 🔴."""
    v = analyze(text)
    assert v.level == Level.SUSPICIOUS and "needs_context" in v.signals
    assert v.reasons[0].en.startswith("This message asks for money, but there's no clear sign of fraud")


def test_seller_sending_their_own_card_is_not_asking_for_yours():
    v = analyze("Buyurtma uchun oldindan 50 000 so'm olamiz. Karta raqamini yozib yuboraymi?")
    assert "secret_code" not in v.signals


def test_needs_context_is_not_counted_as_a_scam_on_the_radar():
    from scamguard import radar
    v = analyze("Buyurtmangiz uchun 80 000 so'mni shu kartaga o'tkazing.")
    assert radar.primary_category(v.signals) == "other" and "needs_context" in v.signals
