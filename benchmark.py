"""How well does each AI model recognise scam TYPES it has never seen?

    python benchmark.py

A normal cross-validation puts paraphrases of one scam on both sides of the split, so a model
that memorises wording looks great. Real life is harder: scammers invent new schemes. Here
every category (fake grant, parcel, account takeover, ...) is held out in turn: the model is
trained on all the other categories and scored on the one it never saw. Legit categories are
held out the same way, so false alarms on new kinds of normal messages are measured too.

Models compared (only the AI part, without rules or links):
  * char n-grams  - the TF-IDF + logistic regression model the bot used so far (model.py)
  * semantic      - multilingual-e5-small sentence vectors + logistic regression (semantic.py)
  * both          - the average of the two probabilities

Numbers:
  * AUC: chance that a random scam scores above a random normal message (1.0 = perfect)
  * caught @ 5% false alarms: share of unseen scams caught when the threshold is set so
    that 5% of unseen normal messages are flagged
The training data is never the eval set in data/eval/ (see evaluate.py for that).
"""

from __future__ import annotations

import glob
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

from train import ROOT, build_pipeline, load
from scamguard.textnorm import normalize, to_latin

# A few files use different names for the same kind of message.
SAME_CATEGORY = {"bank": "bank_impersonation", "job": "job_scam", "bank_notice": "bank_notification"}


def training_data():
    files = [p for p in sorted(glob.glob(str(ROOT / "data" / "*.csv"))) if not p.endswith("feedback.csv")]
    df = load(files)
    cats = [SAME_CATEGORY.get(c, c) if isinstance(c, str) else ("other_scam" if l else "other_safe")
            for c, l in zip(df["category"], df["label"])]
    return df["text"].tolist(), df["label"].to_numpy(), cats


def held_out_by_category(texts, y, cats, fit_predict) -> np.ndarray:
    """Out-of-category probability for every message."""
    proba = np.zeros(len(y))
    by_cat = defaultdict(list)
    for i, c in enumerate(cats):
        by_cat[c].append(i)
    for c, test_idx in by_cat.items():
        train_idx = [i for i in range(len(y)) if cats[i] != c]
        proba[test_idx] = fit_predict(train_idx, test_idx)
    return proba


def caught_at(proba, y, false_alarm_rate=0.05) -> float:
    threshold = np.quantile(proba[y == 0], 1 - false_alarm_rate)
    return float((proba[y == 1] > threshold).mean())


def main() -> None:
    texts, y, cats = training_data()
    n_scam_types = len({c for c, l in zip(cats, y) if l})
    print(f"{len(y)} messages ({y.sum()} scam / {len(y) - y.sum()} normal), "
          f"{n_scam_types} scam types and {len(set(cats)) - n_scam_types} normal types, each held out in turn\n")

    latin = [to_latin(normalize(t)) for t in texts]

    def tfidf(train_idx, test_idx):
        pipe = build_pipeline().fit([latin[i] for i in train_idx], y[train_idx])
        return pipe.predict_proba([latin[i] for i in test_idx])[:, 1]

    results = {"char n-grams (current)": held_out_by_category(texts, y, cats, tfidf)}

    from scamguard import semantic

    enc = semantic.get_encoder()
    if enc is None:
        print("Semantic encoder not found: run  python -m scamguard.semantic download\n")
    else:
        vectors = enc.encode(texts)

        def sem(train_idx, test_idx):
            bundle = semantic.build_bundle(vectors[train_idx], y[train_idx], [cats[i] for i in train_idx])
            return bundle["clf"].predict_proba(vectors[test_idx])[:, 1]

        results["semantic (multilingual-e5)"] = held_out_by_category(texts, y, cats, sem)
        results["both (average)"] = (results["char n-grams (current)"] + results["semantic (multilingual-e5)"]) / 2

        # How close do paraphrases of one scheme get, compared with different schemes?
        scam = np.where(y == 1)[0]
        sims = vectors[scam] @ vectors[scam].T
        same = np.array([[cats[i] == cats[j] for j in scam] for i in scam])
        off_diag = ~np.eye(len(scam), dtype=bool)
        print("Cosine similarity between scams: same type median "
              f"{np.median(sims[same & off_diag]):.2f}, different types median {np.median(sims[~same]):.2f}, "
              f"different types 99th percentile {np.quantile(sims[~same], 0.99):.2f}\n")

    print(f"  {'model':<28} {'AUC':>6}   {'caught @ 5% false alarms':>24}   {'caught @ p>=0.5':>16}   "
          f"{'false alarms @ p>=0.5':>22}")
    for name, p in results.items():
        print(f"  {name:<28} {roc_auc_score(y, p):>6.3f}   {caught_at(p, y):>24.0%}   "
              f"{(p[y == 1] >= 0.5).mean():>16.0%}   {(p[y == 0] >= 0.5).mean():>22.0%}")

    if len(results) > 1:
        print("\nPer held-out scam type (share caught @ 5% false alarms):")
        thresholds = {name: np.quantile(p[y == 0], 0.95) for name, p in results.items()}
        names = list(results)
        print(f"  {'type':<20} {'n':>3}  " + "  ".join(f"{n.split(' ')[0]:>10}" for n in names))
        for c in sorted({c for c, l in zip(cats, y) if l}):
            idx = [i for i in range(len(y)) if cats[i] == c]
            row = "  ".join(f"{(results[n][idx] > thresholds[n]).mean():>10.0%}" for n in names)
            print(f"  {c:<20} {len(idx):>3}  {row}")


if __name__ == "__main__":
    main()
