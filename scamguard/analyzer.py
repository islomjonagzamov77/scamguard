"""Combines rules, link checks and the ML model into one explained verdict."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from . import model
from .links import LinkReport, analyze_links
from .reasons import Reason
from .rules import match_rules

SUSPICIOUS_AT = 0.35
DANGEROUS_AT = 0.65


class Level(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"


@dataclass
class Verdict:
    score: float
    level: Level
    reasons: list[Reason] = field(default_factory=list)
    links: list[LinkReport] = field(default_factory=list)
    rule_score: float = 0.0
    link_score: float = 0.0
    model_score: float | None = None

    def to_dict(self, lang: str = "uz") -> dict:
        return {
            "score": round(self.score, 3),
            "level": self.level.value,
            "reasons": [r.text(lang) for r in self.reasons],
            "components": {
                "rules": round(self.rule_score, 3),
                "links": round(self.link_score, 3),
                "model": None if self.model_score is None else round(self.model_score, 3),
            },
        }


def _noisy_or(values: list[float]) -> float:
    """Combine independent evidence: each signal can only push the score up."""
    remaining = 1.0
    for v in values:
        remaining *= 1.0 - max(0.0, min(1.0, v))
    return 1.0 - remaining


def analyze(text: str, use_model: bool = True) -> Verdict:
    rules = match_rules(text)
    rule_score = _noisy_or([r.weight for r in rules])

    links = analyze_links(text)
    link_score = max((l.score for l in links), default=0.0)

    model_score = model.predict_proba(text) if use_model else None
    # The model only adds evidence when it leans "scam"; it never vetoes rules.
    model_evidence = 0.0 if model_score is None else max(0.0, (model_score - 0.5) * 2) * 0.7

    score = _noisy_or([rule_score, link_score, model_evidence])
    level = (
        Level.DANGEROUS if score >= DANGEROUS_AT
        else Level.SUSPICIOUS if score >= SUSPICIOUS_AT
        else Level.SAFE
    )

    reasons: list[Reason] = [r.reason for r in sorted(rules, key=lambda r: -r.weight)]
    for link in links:
        reasons.extend(link.reasons)
    if model_score is not None and model_score >= 0.6:
        pct = round(model_score * 100)
        reasons.append(Reason(
            f"AI model matnni {pct}% ehtimol bilan firibgarlik deb baholadi",
            f"The AI model rates this text {pct}% likely to be a scam",
            f"AI-модель оценивает вероятность мошенничества в {pct}%",
        ))

    return Verdict(score, level, reasons, links, rule_score, link_score, model_score)
