"""Combines rules, link checks and the ML model into one explained verdict.

Design principle: every warning must have a concrete, human-readable reason.
  * The ML model only adds risk when it is confident (>= MODEL_MIN), and on its
    own it can raise a message to SUSPICIOUS at most, never DANGEROUS.
  * "Amplifier" rules (urgency, mentioning a government body) are normal on
    their own and only count when a core scam signal is also present.
  * A SAFE verdict never lists risk reasons. It may list trust signals instead
    (e.g. the link goes to an official site).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from . import model
from .links import LinkReport, analyze_links
from .reasons import Reason
from .rules import match_rules

SUSPICIOUS_AT = 0.35
DANGEROUS_AT = 0.65
MODEL_MIN = 0.80          # model probability needed before it adds any risk
MODEL_MAX_EVIDENCE = 0.5  # model alone -> at most SUSPICIOUS


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
    trust: list[Reason] = field(default_factory=list)

    def to_dict(self, lang: str = "uz") -> dict:
        return {
            "score": round(self.score, 3),
            "level": self.level.value,
            "reasons": [r.text(lang) for r in self.reasons],
            "trust": [r.text(lang) for r in self.trust],
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


def level_for(score: float) -> Level:
    return Level.DANGEROUS if score >= DANGEROUS_AT else Level.SUSPICIOUS if score >= SUSPICIOUS_AT else Level.SAFE


def model_evidence(p: float | None) -> float:
    if p is None or p < MODEL_MIN:
        return 0.0
    return (p - MODEL_MIN) / (1 - MODEL_MIN) * MODEL_MAX_EVIDENCE


def analyze(text: str, use_model: bool = True, model_proba: float | None = None) -> Verdict:
    """Explained verdict for a message. `model_proba` lets evaluation code inject a
    cross-validated probability instead of asking the trained model."""
    matched = match_rules(text)
    links = analyze_links(text)
    link_score = max((l.score for l in links), default=0.0)

    core = [r for r in matched if not r.amplifier]
    has_core_signal = bool(core) or link_score > 0
    counted = core + ([r for r in matched if r.amplifier] if has_core_signal else [])
    rule_score = _noisy_or([r.weight for r in counted])

    p = model_proba if model_proba is not None else (model.predict_proba(text) if use_model else None)
    m = model_evidence(p)

    score = _noisy_or([rule_score, link_score, m])
    level = level_for(score)
    if not has_core_signal and level == Level.DANGEROUS:
        level = Level.SUSPICIOUS          # the model alone never says "dangerous"
        score = min(score, DANGEROUS_AT - 0.01)

    reasons: list[Reason] = []
    trust: list[Reason] = []
    if level != Level.SAFE:
        reasons = [r.reason for r in sorted(counted, key=lambda r: -r.weight)]
        for link in links:
            reasons.extend(link.reasons)
        if m > 0:
            pct = round(p * 100)
            reasons.append(Reason(
                f"AI model matnni {pct}% ehtimol bilan firibgarlik deb baholadi",
                f"The AI model rates this text {pct}% likely to be a scam",
                f"AI-модель оценивает вероятность мошенничества в {pct}%",
            ))
    else:
        official = sorted({l.host.removeprefix("www.") for l in links if l.official})
        if official:
            sites = ", ".join(official[:3])
            trust.append(Reason(
                f"Havola rasmiy saytga olib boradi: {sites}",
                f"The link goes to an official site: {sites}",
                f"Ссылка ведёт на официальный сайт: {sites}",
            ))

    return Verdict(score, level, reasons, links, rule_score, link_score, p, trust)
