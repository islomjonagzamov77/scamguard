"""Loads the trained text classifier (see train.py) if one exists.

The baseline is a character n-gram TF-IDF + logistic regression model.
Character n-grams work across Latin/Cyrillic scripts and survive the
misspellings scammers use to dodge keyword filters. Swap in a fine-tuned
transformer later by keeping the same `predict_proba(text) -> float` API.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

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


def predict_proba(text: str) -> float | None:
    """Probability that `text` is a scam, or None if no model is trained yet."""
    pipeline = _load()
    if pipeline is None:
        return None
    from .textnorm import normalize, to_latin

    return float(pipeline.predict_proba([to_latin(normalize(text))])[0][1])
