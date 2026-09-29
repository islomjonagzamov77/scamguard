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
    r"\b(?:yubor|jo'nat|kirit|ayt|bos|o't|och|o'tkaz|ber|o'rnat|kir|ol|ko'r|yoz)(?:ing|ingiz|inglar|ingizchi|ingchi)\b",
    r"\b(?:tashla|to'la|yukla|tasdiqla)(?:ng|ngiz|nglar|ngchi)\b",
    r"\b(?:tashla|yubor|jo'nat|ayt|to'la|o'tkaz|kirit)\b",                 # informal: "pul tashla"
    r"\b(?:отправьте|отправь|пришлите|скиньте|скинь|переведите|переведи|оплатите|оплати|введите|"
    r"перейдите|скажите|сообщите|назовите|нажмите|установите|скачайте|продиктуйте)\b",
    # English verbs only when English follows: "click here", "send me the code". "Click" alone is
    # also the name of an Uzbek payment app ("Click orqali to'lang"), so it must not count.
    r"(?<!not )(?<!n't )(?<!never )\b(?:send|pay|transfer|enter|click|tap|install|download|share|open)"
    r"\s+(?:the|this|your|my|me|us|here|now|a|an|on|to|it|via)\b",
)
# "I need money" is an ask too, even without an imperative ("srochno pul kerak")
_NEED = _r(
    r"\bpul (?:kerak|zarur|juda kerak)", r"\bpulga muhtoj", r"нужны деньги", r"деньги нужны", r"срочно нужн",
    r"\bneed (?:the |some )?money\b",
)
# ...and what they are asked to hand over or open
_RISKY_OBJECT = _r(
    r"\bkod", r"\bsms", r"parol", r"\bpin\b", r"cvv", r"karta", r"\bpul", r"to'lov", r"so'm\b", r"\bmln\b",
    r"\bming\b", r"dollar", r"ssilka", r"\blink", r"havola", r"sayt", r"\.apk\b", r"fayl", r"ilova",
    r"ma'lumot", r"dannil", r"https?://", r"\b[\w-]+\.(?:uz|com|top|xyz|online|site|ru|net|org)\b",
    r"код", r"смс", r"пароль", r"карт", r"деньг", r"рубл", r"\bсум", r"ссылк", r"сайт", r"файл",
    r"приложени", r"данны",
    r"\bcode", r"\botp\b", r"password", r"\bcard", r"money", r"payment", r"\bfile", r"\bapp\b", r"details",
)

# --- the sender says NOT to do something, or gives safety advice ----------------------
_WARNING = _r(
    r"\b(?:yubor|jo'nat|kirit|ayt|bos|och|o'tkaz|ber|o'rnat|kir|ol|yoz|tashla|to'la|yukla|ishon|aldan)"
    r"ma(?:ng|ngiz|nglar|slik|sin)\b",                                  # "aytmang", "ochmang", "ishonmang"
    r"\bhech qachon\b", r"\b(?:so'ramaydi|talab qilmaydi|olinmaydi|so'ramaymiz)\b",
    r"\b(?:ehtiyot|ogoh|hushyor) bo'ling", r"firibgar", r"aldamchi",
    r"\b(?:desa|deyishsa|deyilsa)\b", r"\bdegan (?:xabar|qo'ng'iroq|sms)", r"\bdeb (?:yozishsa|qo'ng'iroq qilishsa)",
    r"никому не (?:сообщайте|говорите|передавайте|показывайте|называйте)", r"не (?:сообщайте|переходите|отправляйте|открывайте|устанавливайте|говорите)", r"осторожно",
    r"мошенни", r"никогда не (?:просит|запрашива|спрашива)",
    r"\bnever (?:share|send|give|tell)", r"\b(?:do not|don't) (?:share|send|open|click|tell)", r"\bbeware\b",
    r"\bscammers?\b", r"\bnever asks?\b",
)
# words after which an imperative is being quoted, not said: "'kodni yuboring' desa, bermang"
_QUOTING_WORD = re.compile(r"\b(?:desa|deyishsa|deyilsa|degan|deb)\b", re.IGNORECASE)
_QUOTED_SPAN = re.compile(r"\"[^\"]*\"|«[^»]*»|“[^”]*”|„[^“”]*[“”]")

# --- the sender tells a story about something that already happened -------------------
_WHO = _r(
    r"\b(?:menga|mendan|meni|onamga|onamni|otamga|dadamga|buvimga|bobomga|opamga|akamga|ukamga|singlimga|"
    r"dugonamga|do'stimga|qo'shnimga|bizga|guruhga|kimdir|kecha|vchera|bugun ertalab|o'tgan hafta)\b",
    r"\b(?:мне|меня|маме|папе|бабушке|нам|вчера)\b",
)
_PAST = _r(
    r"\b\w+(?:di|dim|dik|ibdi|ibdilar|ishibdi|ishdi|gandi|ganman)\b",
    r"\b\w+(?:ли|ла)\b",
)

# --- someone pasted a message and asks about it -------------------------------------
_QUOTE = _r(
    r"\brostmi\b", r"\bhaqiqatmi\b", r"firibgarlikmi", r"\baldovmi\b", r"\bshunday xabar\b",
    r"\bxabar keldi\s*:", r"\b\w+(?:aymi|ayinmi|aylikmi)\b",                   # "ochaymi?" = should I open it?
    r"это правда", r"это развод", r"\bis this (?:real|a scam|legit)", r"\bi got this\b",
)

@dataclass(frozen=True)
class Intent:
    kind: str            # request / warning / report / quote / info
    evidence: str = ""   # the sentence (from the original message) that shows it


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


def _asks(masked_sentence: str) -> bool:
    """An affirmative imperative about money/codes/links/files, outside quoted speech."""
    for v in variants(masked_sentence):
        cut = list(_QUOTING_WORD.finditer(v))
        tail = v[cut[-1].end():] if cut else v           # "kodni yuboring desa, bermang" -> look after "desa"
        if (_ASK_VERB.search(tail) and _RISKY_OBJECT.search(v)) or _NEED.search(tail):
            return True
    return False


def _short(sentence: str, limit: int = 90) -> str:
    s = " ".join(mask_private(sentence).split())   # never echo card or phone numbers back
    return s if len(s) <= limit else s[: limit - 1].rstrip() + "…"


def detect(text: str) -> Intent:
    masked = _QUOTED_SPAN.sub(lambda m: " " * len(m.group()), text)
    found: dict[str, str] = {}
    for start, end in _sentences(text):
        sentence, masked_sentence = text[start:end], masked[start:end]
        if QUOTE not in found and _any(_QUOTE, sentence):
            found[QUOTE] = sentence
        if REQUEST not in found and _asks(masked_sentence):
            found[REQUEST] = sentence
        if WARNING not in found and _any(_WARNING, sentence):
            found[WARNING] = sentence
        if REPORT not in found and _any(_WHO, masked_sentence) and _any(_PAST, masked_sentence):
            found[REPORT] = sentence
    for kind in (QUOTE, REQUEST, WARNING, REPORT):
        if kind in found:
            return Intent(kind, _short(found[kind]))
    return Intent(INFO)
