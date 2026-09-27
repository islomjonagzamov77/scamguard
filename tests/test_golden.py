"""Regression tests on realistic messages (tests/golden_set.csv).

Every false alarm or missed scam reported by users should be added here, so a
mistake that was fixed can never come back unnoticed. Runs on every deploy.

  safe -> verdict must be SAFE and must not show any risk reason
  flag -> verdict must be SUSPICIOUS or DANGEROUS
"""

import csv
from pathlib import Path

import pytest

from scamguard.analyzer import Level, analyze

ROWS = list(csv.DictReader(open(Path(__file__).with_name("golden_set.csv"), encoding="utf-8")))


@pytest.mark.parametrize("row", ROWS, ids=[r["note"] for r in ROWS])
def test_golden(row):
    v = analyze(row["text"])
    if row["expect"] == "safe":
        assert v.level == Level.SAFE, f"false alarm ({v.score:.2f}): {[r.en for r in v.reasons]}"
        assert not v.reasons, f"risk reasons shown on a safe message: {[r.en for r in v.reasons]}"
    else:
        assert v.level != Level.SAFE, f"missed scam ({v.score:.2f})"
