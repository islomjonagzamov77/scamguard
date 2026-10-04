"""Combines rules, link checks and the ML model into one explained verdict.

Design principle: every warning must have a concrete, human-readable reason.
  * The ML model only adds risk when it is confident (>= MODEL_MIN), and on its
    own it can raise a message to SUSPICIOUS at most, never DANGEROUS.
  * "Amplifier" rules (urgency, mentioning a government body) are normal on
    their own and only count when a core scam signal is also present.
  * A SAFE verdict never lists risk reasons. It may list trust signals instead
    (e.g. the link goes to an official site).
  * Intent comes first (see intent.py). A warning or a story about the past only
    *mentions* scam words, so text rules and the model count for little there and
    their "asks for your code" reasons are not shown: nothing in it asks for anything.
    Links are judged on their own, because a scam link is dangerous to open wherever it appears.
  * "Can't tell": a request for money with no other warning sign could be a real shop or a
    scammer. The bot doesn't guess 🟢 or 🔴: it says 🟡 and asks one question instead.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from . import model
from .intent import INFO, QUOTE, REPORT, REQUEST, WARNING, Intent, detect
from .links import LinkReport, analyze_links
from .reasons import Reason
from .rules import match_rules

SUSPICIOUS_AT = 0.35
DANGEROUS_AT = 0.65
# The AI model on its own can raise a 🟡 warning once it is MODEL_MIN sure, never a 🔴.
# 0.75 was chosen on the training data with every scam *type* held out in turn, not on the test set
# (benchmark.py): about 4% of normal messages go above it, and 67% of scams of a type the model never
# saw (39% before the semantic model was added). See RESULTS.md.
MODEL_MIN = 0.75
MODEL_MAX_EVIDENCE = 0.5  # model alone -> at most SUSPICIOUS
MENTION_WEIGHT = 0.3      # text rules in a warning/story count this much


NEEDS_CONTEXT = Reason(
    "Xabar pul so'rayapti, lekin firibgarlik belgisi aniq emas. Buni kutganmidingiz? Qabul qiluvchini "
    "o'zingiz tekshiring: tanish bo'lsa — o'zingiz qo'ng'iroq qiling, do'kon bo'lsa — rasmiy sayt yoki ilova "
    "orqali. Tekshirmaguncha pul o'tkazmang.",
    "This message asks for money, but there's no clear sign of fraud. Were you expecting it? Check the "
    "recipient yourself: call the person you know, or use the shop's official site or app. Don't send "
    "money until you have.",
    "Сообщение просит деньги, но явных признаков мошенничества нет. Вы этого ждали? Проверьте получателя "
    "сами: позвоните знакомому, у магазина — через официальный сайт или приложение. Не переводите деньги, "
    "пока не проверите.",
)


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
    signals: list[str] = field(default_factory=list)   # names of the rules/link checks that counted
    intent: Intent = field(default_factory=lambda: Intent(INFO))

    def to_dict(self, lang: str = "uz") -> dict:
        return {
            "score": round(self.score, 3),
            "level": self.level.value,
            "reasons": [r.text(lang) for r in self.reasons],
            "trust": [r.text(lang) for r in self.trust],
            "intent": {"kind": self.intent.kind, "evidence": self.intent.evidence},
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
    """Below MODEL_MIN the model adds nothing; from MODEL_MIN it is enough for 🟡 on its own,
    rising to MODEL_MAX_EVIDENCE, which is still below 🔴."""
    if p is None or p < MODEL_MIN:
        return 0.0
    return SUSPICIOUS_AT + (p - MODEL_MIN) / (1 - MODEL_MIN) * (MODEL_MAX_EVIDENCE - SUSPICIOUS_AT)


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

    intent = detect(text)
    mentions_only = intent.kind in (WARNING, REPORT)
    if mentions_only:
        rule_score *= MENTION_WEIGHT
        m = 0.0

    score = _noisy_or([rule_score, link_score, m])
    level = level_for(score)
    if level == Level.DANGEROUS and level_for(_noisy_or([rule_score, link_score])) != Level.DANGEROUS:
        # The AI model reads the same text as the rules, so it is not independent evidence.
        # It may lift 🟢 to 🟡, but 🔴 always needs the rules or links on their own.
        level = Level.SUSPICIOUS
        score = min(score, DANGEROUS_AT - 0.01)

    reasons: list[Reason] = []
    trust: list[Reason] = []
    needs_context = level == Level.SAFE and intent.asks_money and intent.kind in (REQUEST, QUOTE)
    if needs_context:
        level, score = Level.SUSPICIOUS, max(score, SUSPICIOUS_AT)
        reasons.append(NEEDS_CONTEXT)
    elif level != Level.SAFE:
        if intent.kind == REQUEST:
            reasons.append(Reason(
                f"Xabar sizdan buni talab qilyapti: «{intent.evidence}»",
                f"The message asks you to do this: «{intent.evidence}»",
                f"Сообщение просит вас сделать это: «{intent.evidence}»",
            ))
        if not mentions_only:
            reasons += [r.reason for r in sorted(counted, key=lambda r: -r.weight)]
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
        if intent.kind == WARNING and counted:
            trust.append(Reason(
                f"Bu ogohlantirish — xabar sizdan hech narsa so'ramayapti: «{intent.evidence}»",
                f"This is a warning — the message doesn't ask you for anything: «{intent.evidence}»",
                f"Это предупреждение — сообщение ничего у вас не просит: «{intent.evidence}»",
            ))
        elif intent.kind == REPORT and counted:
            trust.append(Reason(
                f"Bu bo'lib o'tgan voqea haqida hikoya — xabar sizdan hech narsa so'ramayapti: «{intent.evidence}»",
                f"This describes something that already happened — it doesn't ask you for anything: «{intent.evidence}»",
                f"Это рассказ о случившемся — сообщение ничего у вас не просит: «{intent.evidence}»",
            ))

    signals = [] if mentions_only else [r.name for r in sorted(counted, key=lambda r: -r.weight)]
    for link in links:
        signals.extend(link.signals)
    if m > 0:
        signals.append("ai_model")
    if needs_context:
        signals.append("needs_context")
    return Verdict(score, level, reasons, links, rule_score, link_score, p, trust, signals, intent)
