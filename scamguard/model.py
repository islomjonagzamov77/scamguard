"""The AI part of the verdict: two trained text classifiers, averaged (see train.py).

  * char n-grams: TF-IDF over character 2-5-grams + logistic regression. Works across
    Latin/Cyrillic and survives the misspellings scammers use to dodge keyword filters, but it
    only knows the spellings it was trained on.
  * semantic: a pretrained multilingual transformer (semantic.py) that reads what a message
    *means*, so it also recognises scam types that are worded differently from the training data.

On scam types held out from training the average catches 72% at 5% false alarms, against 52%
for char n-grams alone (benchmark.py, RESULTS.md). Without the encoder files the bot falls back
to char n-grams alone.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from . import semantic

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "baseline.joblib"


@lru_cache(maxsize=1)
def _load():
    path = Path(os.getenv("SCAMGUARD_MODEL", DEFAULT_MODEL_PATH))
    if not path.exists():
        return None
    import joblib

    return joblib.load(path)


def model_available() -> bool:
    return _load() is not None


def char_proba(text: str) -> float | None:
    pipeline = _load()
    if pipeline is None:
        return None
    from .textnorm import normalize, to_latin

    return float(pipeline.predict_proba([to_latin(normalize(text))])[0][1])


def combine(char: float | None, meaning: float | None) -> float | None:
    parts = [p for p in (char, meaning) if p is not None]
    return sum(parts) / len(parts) if parts else None


def predict_proba(text: str) -> float | None:
    """Probability that `text` is a scam, or None if no model is trained yet."""
    return combine(char_proba(text), semantic.predict_proba(text))
