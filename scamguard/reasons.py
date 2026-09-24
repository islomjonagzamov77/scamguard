from dataclasses import dataclass

LANGS = ("uz", "ru", "en")


@dataclass(frozen=True)
class Reason:
    """One human-readable explanation in Uzbek, English and Russian."""

    uz: str
    en: str
    ru: str = ""

    def text(self, lang: str = "uz") -> str:
        if lang == "ru":
            return self.ru or self.en
        return self.en if lang == "en" else self.uz
