"""Tests for collect.py: masking, de-duplication, the train/holdout split and scoring."""

import csv
import glob
from pathlib import Path

import pytest

import collect

ROOT = Path(__file__).resolve().parent.parent


def test_mask_hides_private_data_but_keeps_scam_signals():
    text = ("Kartangiz 8600 1234 5678 9012 bloklandi. +998 90 123 45 67 ga qo'ng'iroq qiling, "
            "yoki @click_support_uz ga yozing, ali@mail.ru. Havola: t.me/click_bonus_bot")
    masked = collect.mask(text)
    assert "<CARD>" in masked and "<PHONE>" in masked and "<EMAIL>" in masked and "<USER>" in masked
    for private in ("8600", "123 45 67", "click_support_uz", "ali@mail.ru"):
        assert private not in masked
    assert "t.me/click_bonus_bot" in masked          # links stay: they are evidence, not personal data


def test_fingerprint_ignores_spelling_noise():
    a = collect.fingerprint("Kartangiz  bloklandi! SMS kodni yuboring")
    b = collect.fingerprint("kartangiz bloklandi sms kodni yuboring.")
    c = collect.fingerprint("Картангиз блокланди! СМС кодни юборинг")
    assert a == b == c
    assert a != collect.fingerprint("Kartangiz bloklanmadi")


def test_split_is_fixed_and_about_twenty_percent():
    texts = [f"Xabar raqami {i}: pulni shu kartaga o'tkazing" for i in range(2000)]
    first = [collect.destination(t) for t in texts]
    assert first == [collect.destination(t) for t in texts]          # never changes between runs
    share = sum(d == collect.HOLDOUT_FILE for d in first) / len(first)
    assert 0.15 < share < 0.25


def test_holdout_is_never_read_by_train_py():
    train_inputs = glob.glob(str(ROOT / "data" / "*.csv"))           # exactly what train.py reads
    assert str(collect.HOLDOUT_FILE) not in train_inputs
    assert collect.TRAIN_FILE.parent == ROOT / "data"


def test_known_fingerprints_covers_training_and_test_sets():
    seen = collect.known_fingerprints()
    with open(ROOT / "data" / "seed_dataset.csv", encoding="utf-8") as f:
        assert collect.fingerprint(next(csv.DictReader(f))["text"]) in seen
    with open(ROOT / "data" / "eval" / "intent_pairs.csv", encoding="utf-8") as f:
        assert collect.fingerprint(next(csv.DictReader(f))["text"]) in seen


@pytest.mark.parametrize("text,lang", [
    ("Hurmatli mijoz, kartangiz bloklandi. Kodni yuboring", "uz"),
    ("Картангиз блокланди, кодни айтинг", "uz"),
    ("Ваша карта заблокирована, назовите код из СМС", "ru"),
    ("Your card is blocked, please send the code", "en"),
])
def test_guess_lang(text, lang):
    assert collect.guess_lang(text) == lang


def test_append_row_writes_header_once(tmp_path):
    path = tmp_path / "x.csv"
    for i in range(3):
        collect.append_row(path, {"text": f"t{i}", "label": 0, "lang": "uz", "category": "personal",
                                  "source": "pasted", "added": "2026-10-02"})
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    assert [r["text"] for r in rows] == ["t0", "t1", "t2"]


def test_score_counts_caught_scams_and_false_alarms(tmp_path):
    path = tmp_path / "holdout.csv"
    rows = [("Kartangiz bloklandi. Blokdan chiqarish uchun SMS kodni shu raqamga yuboring", 1),
            ("Ertaga soat 10 da darsga kelasanmi?", 0)]
    for text, label in rows:
        collect.append_row(path, {"text": text, "label": label, "lang": "uz", "category": "x",
                                  "source": "pasted", "added": "2026-10-02"})
    s = collect.score(path, use_model=False)
    assert s == {"total": 2, "scams": 1, "caught": 1, "safe": 1, "false_alarms": 0}


def test_label_one_saves_masked_row_then_skips_the_duplicate(tmp_path, monkeypatch):
    monkeypatch.setattr(collect, "TRAIN_FILE", tmp_path / "train.csv")
    monkeypatch.setattr(collect, "HOLDOUT_FILE", tmp_path / "holdout.csv")
    answers = iter(["1", "1", ""])                       # scam, first scam category, keep language
    monkeypatch.setattr("builtins.input", lambda _="": next(answers))
    stats = dict(train=0, holdout=0, duplicates=0, skipped=0, bot_wrong=0)
    seen: set[str] = set()
    message = "Kartangiz bloklandi, kodni +998 90 123 45 67 raqamiga yuboring"

    assert collect.label_one(message, "pasted", seen, stats)
    saved = [r for f in (tmp_path / "train.csv", tmp_path / "holdout.csv") if f.exists()
             for r in csv.DictReader(open(f, encoding="utf-8"))]
    assert len(saved) == 1
    assert saved[0]["label"] == "1" and saved[0]["category"] == collect.SCAM_CATEGORIES[0]
    assert "<PHONE>" in saved[0]["text"] and saved[0]["lang"] == "uz"

    assert collect.label_one(message, "pasted", seen, stats)   # same message again: no question asked
    assert stats["duplicates"] == 1
