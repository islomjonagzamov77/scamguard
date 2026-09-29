"""What does the sender want from the reader?

Word-matching alone can't tell these apart. All three contain "SMS kod":

    request  "SMS kodni shu yerga yozib yuboring."        -> someone wants your code
    warning  "SMS kodni hech kimga aytmang."               -> safety advice
    report   "Kecha mendan SMS kodimni so'rashdi, bermadim." -> a story about the past

This module labels a message with one intent and the sentence that proves it.
The analyzer then uses that evidence: a warning or a story is not accused of
"asking for your code", because nothing in it asks you for anything.

The priority order is a safety choice, from most to least cautious:
  quote > request > warning > report > info
  * quote:   someone pasted a message and asks about it -> judge the pasted scam in full
  * Secrecy is NOT a warning: "никому не говори" / "hech kimga aytma" (don't tell anyone,
    informal) is a classic scam line, so only formal safety advice ("aytmang", "не сообщайте")
    counts as a warning.
  * request: any real ask for money/codes/links/files wins, even if the message
             also contains warning words (scammers add "kodni hech kimga aytmang" too)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .textnorm import mask_private, variants

REQUEST, WARNING, REPORT, QUOTE, INFO = "request", "warning", "report", "quote", "info"


def _r(*alternatives: str) -> re.Pattern:
    return re.compile("|".join(f"(?:{a})" for a in alternatives), re.IGNORECASE)


# --- the reader is asked to DO something risky --------------------------------------
# Uzbek imperatives follow vowel harmony: consonant stems take -ing (yubor-ing),
# vowel stems take -ng (tashla-ng). Negative forms ("yubor-ma-ng") never match here.
_ASK_VERB = _r(
    r"\b(?:yubor|jo'nat|kirit|ayt|bos|o't|och|o'tkaz|ber|o'rnat|kir|ol|ko'r|yoz|oshir|qo'sh)"
    r"(?:ing|ingiz|inglar|ingizchi|ingchi)\b",
    r"\b(?:tashla|to'la|yukla|tasdiqla)(?:ng|ngiz|nglar|ngchi)\b",
    r"\b(?:tashla|yubor|jo'nat|ayt|to'la|o'tkaz|kirit)\b",                 # informal: "pul tashla"
    r"\bto'lov(?:ni)? qiling\b",
    r"\b\w+(?:ib|b) (?:ber|bering|beringiz|qo'y|qo'ying|yubor|yuboring|tur|turing)\b",   # "tashlab ber/qo'ying/tur"
    # an offer is an ask too: "1000$ tashlasangiz, 3 kunda 2000$" (if you send...)
    r"\b(?:tashla|to'la|yubor|o'tkaz|qo'sh|kirit|qo'y|jo'nat|kirgiz)(?:sangiz|sang|sangizlar)\b",
    r"\bto'lov qilsangiz\b",
    r"\b(?:отправьте|отправь|пришлите|скиньте|скинь|переведите|переведи|оплатите|оплати|введите|"
    r"перейдите|скажите|сообщите|назовите|нажмите|установите|скачайте|продиктуйте|вложите|внесите|"
    r"отдай|отдайте|передай|передайте|дай|дайте|займи|одолжи)\b",
    # English verbs only when English follows: "click here", "send me the code". "Click" alone is
    # also the name of an Uzbek payment app ("Click orqali to'lang"), so it must not count.
    r"(?<!not )(?<!n't )(?<!never )\b(?:send|pay|transfer|enter|click|tap|install|download|share|open)"
    r"\s+(?:the|this|your|my|me|us|here|now|a|an|on|to|it|via)\b",
)
# "I need money" is an ask too, even without an imperative ("srochno pul kerak", "I need only $800")
_NEED = _r(
    r"\bpul (?:kerak|zarur|juda kerak)", r"\bpulga muhtoj", r"\d[\d\s.,]*\s?(?:\$|dollar|so'm|ming|mln)\S*\s+kerak\b",
    r"нужны деньги", r"деньги нужны", r"срочно нужн", r"нужн\w* \d",
    r"\bneed (?:the |some )?money\b", r"\bneed (?:only |just )?(?:\$|usd ?)?\d",
)
# ...and what they are asked to hand over or open
_RISKY_OBJECT = _r(
    r"\bkod", r"\bsms", r"parol", r"\bpin\b", r"cvv", r"karta", r"\bpul", r"to'lov", r"so'm", r"\bmln\b",
    r"\bming\b", r"dollar", r"\$", r"usdt", r"ssilka", r"\blink", r"havola", r"sayt", r"\.apk\b", r"fayl", r"ilova",
    r"ma'lumot", r"dannil", r"https?://", r"\b[\w-]+\.(?:uz|com|top|xyz|online|site|ru|net|org)\b",
    r"код", r"смс", r"пароль", r"карт", r"деньг", r"рубл", r"\bсум", r"ссылк", r"сайт", r"файл",
    r"приложени", r"данны",
    r"\bcode", r"\botp\b", r"password", r"\bcard", r"money", r"payment", r"\bfile", r"\bapp\b", r"details",
)
# money in particular: a request for money with nothing else suspicious is "can't tell", not "safe"
_MONEY = _r(
    r"\bpul", r"to'lov", r"so'm", r"\bming\b", r"\bmln\b", r"dollar", r"\$", r"usdt", r"zakalat", r"oldindan",
    r"деньг", r"\bсум", r"рубл", r"доллар", r"предоплат", r"залог", r"перевод",
    r"\bmoney", r"payment", r"\bfee\b", r"\busd\b",
)
# safe advice is phrased as a request too ("IT bo'limga xabar bering", "bankka qo'ng'iroq qiling")
_SAFE_ACTION = _r(
    r"\bxabar ber\w*", r"\bmurojaat qil\w*", r"\bqo'ng'iroq qil\w*", r"\bblok(?:la\w*| qil\w*)", r"\bo'chir\w*",
    r"\btekshir\w*", r"позвоните\w*", r"обратитесь\w*", r"сообщите в (?:банк|полици\w*)",
    r"\bcall (?:your|the) bank\b", r"\breport (?:it|them)\b",
)

# --- the sender says NOT to do something, or gives safety advice ----------------------
_WARNING = _r(
    r"\b(?:yubor|jo'nat|kirit|bos|och|o'tkaz|ber|o'rnat|kir|ol|yoz|tashla|to'la|yukla|ishon|aldan)"
    r"ma(?:ng|ngiz|nglar|slik|sin)\b",                                  # "ochmang", "bermang", "ishonmang"
    r"\bhech qachon\b", r"\b(?:so'ramaydi|talab qilmaydi|olinmaydi|so'ramaymiz)\b",
    r"\b(?:ehtiyot|ogoh|hushyor) bo'ling", r"firibgar", r"aldamchi",
    r"\b(?:desa|deyishsa|deyilsa)\b", r"\bdegan (?:xabar|qo'ng'iroq|sms)", r"\bdeb (?:yozishsa|qo'ng'iroq qilishsa)",
    r"не (?:переходите|отправляйте|открывайте|устанавливайте)", r"осторожно",
    r"мошенни", r"никогда не (?:просит|запрашива|спрашива)",
    r"\bnever (?:share|send|give)", r"\b(?:do not|don't) (?:share|send|open|click)", r"\bbeware\b",
    r"\bscammers?\b", r"\bnever asks?\b",
)
# "don't tell" is advice only when it protects a secret ("kodni hech kimga aytmang").
# On its own it is a scammer asking for secrecy ("hech kimga aytmang, joy kam", "don't tell your family").
_TELL_NOT = _r(
    r"\baytma(?:ng|ngiz|nglar)\b", r"никому не (?:говорите|сообщайте|называйте|показывайте)",
    r"не (?:сообщайте|говорите|называйте)", r"\b(?:never|do not|don't) tell\b",
)
_SECRET = _r(
    r"\bkod", r"\bsms", r"parol", r"\bpin\b", r"cvv", r"karta", r"ma'lumot",
    r"код", r"смс", r"пароль", r"карт", r"данн", r"\bcode", r"\botp\b", r"password", r"\bcard",
)
# words after which an imperative is being quoted, not said: "'kodni yuboring' desa, bermang"
_QUOTING_WORD = re.compile(r"\b(?:desa|deyishsa|deyilsa|degan|deb|dedi|deydi|deya|deyish\w*)\b", re.IGNORECASE)
_QUOTED_SPAN = re.compile(
    r"\"[^\"]*\"|«[^»]*»|“[^”]*”|„[^“”]*[“”]"
    # single quotes clash with Uzbek o'/g', so they only count when a quoting verb follows:
    # 'posilkangiz tamozhnyada, 38 ming to'lang' deb SMS kelibdi
    r"|(?<!\w)'(?:[^'\n]|(?<=\w)'(?=\w))+?'(?=\s*,?\s*(?:deb|degan|dedi|deydi|deya|deyish\w*|desa|деб|деган|деди|дейди|дея|дейиш\w*|деса)\b)",
    re.IGNORECASE,
)

# --- the sender tells a story about something that already happened -------------------
_WHO = _r(
    r"\b(?:menga|mendan|meni|bizga|bizni|guruhga|guruhimizga|kimdir|kecha|vchera|bugun ertalab|o'tgan hafta)\b",
    r"\b(?:onam|otam|dadam|buvim|bobom|opam|akam|ukam|singlim|jiyanim|do'stim|dugonam|qo'shnim|hamkasbim|"
    r"kollegam|tanishim|o'rtog'im)\w*",
    r"\b(?:мне|меня|нам|вчера|мама|маме|маму|папе|бабушк\w*|дедушк\w*|коллег\w*|подруг\w*|друг\w*|сосед\w*|"
    r"сестр\w*|брат\w*)\b",
)
_PAST = _r(
    r"\b\w{2,}(?:di|dim|dik|dilar|ibdi|ibdilar|ishibdi|ishdi|gandi|ganman)\b",
    r"\b\w{2,}(?:ла|ли|ло|ал|ил|ел|ял)\b",
)
NARRATIVE_PAST_VERBS = 3   # this many past-tense verbs and no ask = a story, even without "menga"/"мне"

# --- someone pasted a message and asks about it -------------------------------------
_QUOTE = _r(
    r"\brostmi\b", r"\bhaqiqatmi\b", r"\bhaqiqiymi\b", r"firibgarlikmi", r"\baldovmi\b", r"\bto'g'rimi\b",
    r"\bshunday xabar\b", r"\bxabar keldi\s*:", r"\bshu tashlandi\b", r"\bkimdir biladimi\b",
    r"\bishonsa bo'ladimi\b", r"\b(?:ochaymi|kiraymi|bosaymi|to'laymi|to'layinmi|yuklaymi|o'rnataymi)\b",
    r"это правда", r"это развод", r"\bis this (?:real|a scam|legit)", r"\bi got this\b",
)


@dataclass(frozen=True)
class Intent:
    kind: str                 # request / warning / report / quote / info
    evidence: str = ""        # the sentence (from the original message) that shows it
    asks_money: bool = False  # the ask (or the pasted message) is about money


def _sentences(text: str) -> list[tuple[int, int]]:
    spans, pos = [], 0
    for piece in re.split(r"(?<=[.!?…])\s+|\n+", text):
        start = text.find(piece, pos)
        if piece.strip():
            spans.append((start, start + len(piece)))
        pos = start + len(piece)
    return spans


def _any(pattern: re.Pattern, text: str) -> bool:
    return any(pattern.search(v) for v in variants(text))


def _asks(sentence: str, context: str) -> tuple[bool, bool]:
    """(asks for something risky, asks for money). An affirmative imperative, an offer or a
    "need money" line, outside quoted speech. The object may sit in the previous sentence:
    "I need only $800. Please send it now." """
    for v, ctx in zip(variants(sentence), variants(context + " " + sentence)):
        v = _SAFE_ACTION.sub(" ", v)
        cut = list(_QUOTING_WORD.finditer(v))
        tail = v[cut[-1].end():] if cut else v           # "kodni yuboring desa, bermang" -> look after "desa"
        if _NEED.search(tail):
            return True, True
        if _ASK_VERB.search(tail) and _RISKY_OBJECT.search(ctx):
            return True, bool(_MONEY.search(ctx))
    return False, False


def _warns(sentence: str) -> bool:
    return _any(_WARNING, sentence) or (_any(_TELL_NOT, sentence) and _any(_SECRET, sentence))


def _short(sentence: str, limit: int = 90) -> str:
    s = " ".join(mask_private(sentence).split())   # never echo card or phone numbers back
    return s if len(s) <= limit else s[: limit - 1].rstrip() + "…"


def detect(text: str) -> Intent:
    masked = _QUOTED_SPAN.sub(lambda m: " " * len(m.group()), text)
    spans = _sentences(text)
    found: dict[str, str] = {}
    money = {REQUEST: False, QUOTE: False}
    for i, (start, end) in enumerate(spans):
        sentence, masked_sentence = text[start:end], masked[start:end]
        previous = masked[spans[i - 1][0]:spans[i - 1][1]] if i else ""
        if QUOTE not in found and _any(_QUOTE, sentence):
            found[QUOTE] = sentence
        if REQUEST not in found:
            asks, about_money = _asks(masked_sentence, previous)
            if asks:
                found[REQUEST], money[REQUEST] = sentence, about_money
        if WARNING not in found and _warns(sentence):
            found[WARNING] = sentence
        if REPORT not in found and _any(_WHO, masked_sentence) and _any(_PAST, masked_sentence):
            found[REPORT] = sentence
    if QUOTE in found:                     # judge the pasted message itself, quotes included
        money[QUOTE] = any(_asks(text[s:e], "")[1] for s, e in spans)
    if REPORT not in found and REQUEST not in found:
        past = max(len(_PAST.findall(v)) for v in variants(masked)) if masked.strip() else 0
        if past >= NARRATIVE_PAST_VERBS:
            found[REPORT] = text[spans[0][0]:spans[0][1]] if spans else ""
    for kind in (QUOTE, REQUEST, WARNING, REPORT):
        if kind in found:
            return Intent(kind, _short(found[kind]), money.get(kind, False))
    return Intent(INFO)
