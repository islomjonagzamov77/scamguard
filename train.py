"""Train the baseline scam classifier and compare it with the rule engine.

Usage:
    python train.py                         # uses data/*.csv
    python train.py --data data/my.csv      # specific file(s)

Every CSV needs `text` and `label` columns (1 = scam, 0 = legit).
The script prints a cross-validated comparison of:
    rules only  vs  ML model only  vs  full analyzer (rules + links + model)
and saves the model fitted on all data to models/baseline.joblib.
"""

from __future__ import annotations

import argparse
import glob
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import Pipeline

from scamguard.analyzer import SUSPICIOUS_AT, _noisy_or
from scamguard.links import analyze_links
from scamguard.rules import match_rules
from scamguard.textnorm import normalize, to_latin

ROOT = Path(__file__).resolve().parent


def build_pipeline() -> Pipeline:
    return Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=1, sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=2000, class_weight="balanced", C=4.0)),
    ])


def load(paths: list[str]) -> pd.DataFrame:
    frames = [pd.read_csv(p) for p in paths]
    df = pd.concat(frames, ignore_index=True).dropna(subset=["text", "label"])
    df["label"] = df["label"].astype(int)
    return df.drop_duplicates(subset="text").reset_index(drop=True)


def heuristic_score(text: str) -> float:
    rule = _noisy_or([r.weight for r in match_rules(text)])
    link = max((l.score for l in analyze_links(text)), default=0.0)
    return _noisy_or([rule, link])


def report(name: str, y_true, y_pred) -> None:
    p = precision_score(y_true, y_pred, zero_division=0)
    r = recall_score(y_true, y_pred, zero_division=0)
    f = f1_score(y_true, y_pred, zero_division=0)
    print(f"  {name:<28} precision={p:.3f}  recall={r:.3f}  f1={f:.3f}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", nargs="*", default=sorted(glob.glob(str(ROOT / "data" / "*.csv"))))
    ap.add_argument("--out", default=str(ROOT / "models" / "baseline.joblib"))
    ap.add_argument("--folds", type=int, default=5)
    args = ap.parse_args()

    data_files = [p for p in args.data if not p.endswith("feedback.csv")]
    df = load(data_files)
    texts = df["text"].tolist()
    x = [to_latin(normalize(t)) for t in texts]
    y = df["label"].to_numpy()
    print(f"Loaded {len(df)} messages ({y.sum()} scam / {len(y) - y.sum()} legit) from {len(data_files)} file(s)")

    heur = np.array([heuristic_score(t) for t in texts])
    model_proba = np.zeros(len(y))
    skf = StratifiedKFold(n_splits=args.folds, shuffle=True, random_state=42)
    for train_idx, test_idx in skf.split(x, y):
        pipe = build_pipeline().fit([x[i] for i in train_idx], y[train_idx])
        model_proba[test_idx] = pipe.predict_proba([x[i] for i in test_idx])[:, 1]

    model_evidence = np.clip((model_proba - 0.5) * 2, 0, 1) * 0.7
    combined = 1 - (1 - heur) * (1 - model_evidence)

    print(f"\n{args.folds}-fold cross-validation (flagged = suspicious or dangerous):")
    report("rules + links only", y, heur >= SUSPICIOUS_AT)
    report("ML model only (p >= 0.5)", y, model_proba >= 0.5)
    report("full analyzer", y, combined >= SUSPICIOUS_AT)

    missed = [(t, s) for t, s, lbl in zip(texts, combined, y) if lbl == 1 and s < SUSPICIOUS_AT]
    false_alarms = [(t, s) for t, s, lbl in zip(texts, combined, y) if lbl == 0 and s >= SUSPICIOUS_AT]
    for title, items in (("Missed scams", missed), ("False alarms", false_alarms)):
        if items:
            print(f"\n{title} ({len(items)}):")
            for t, s in items[:10]:
                print(f"  [{s:.2f}] {t[:90]}")

    final = build_pipeline().fit(x, y)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(final, args.out)
    print(f"\nSaved model trained on all data to {args.out}")


if __name__ == "__main__":
    main()
