"""Text normalization: apostrophes, Uzbek Cyrillic -> Latin, masking private data."""

import re

# Uzbek has many apostrophe variants for o' and g'. Unify them.
_APOSTROPHES = str.maketrans({c: "'" for c in "ʻʼ’‘`´ʹ"})

_UZ_CYR_TO_LAT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "yo",
    "ж": "j", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "x", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "sh", "ъ": "'",
    "ь": "", "ы": "i", "э": "e", "ю": "yu", "я": "ya", "ў": "o'", "қ": "q",
    "ғ": "g'", "ҳ": "h",
}


def normalize(text: str) -> str:
    """Lowercase, unify apostrophes and collapse whitespace."""
    text = text.translate(_APOSTROPHES).lower()
    return re.sub(r"\s+", " ", text).strip()


def to_latin(text: str) -> str:
    """Transliterate Uzbek Cyrillic to Latin so one rule set covers both scripts."""
    return "".join(_UZ_CYR_TO_LAT.get(ch, ch) for ch in text)


def variants(text: str) -> list[str]:
    """Return the normalized text plus its Latin transliteration (if different).

    Russian rules are written in Cyrillic and match the first variant;
    Uzbek rules are written in Latin and match either variant.
    """
    norm = normalize(text)
    lat = to_latin(norm)
    return [norm] if lat == norm else [norm, lat]


_CARD = re.compile(r"\b(?:\d[ -]?){15,18}\d\b")
_PHONE = re.compile(r"(?:\+?998[ -]?)?\(?\d{2}\)?[ -]?\d{3}[ -]?\d{2}[ -]?\d{2}\b")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")


def mask_private(text: str) -> str:
    """Remove card numbers, phone numbers and emails before anything is stored."""
    text = _CARD.sub("<CARD>", text)
    text = _EMAIL.sub("<EMAIL>", text)
    return _PHONE.sub("<PHONE>", text)
