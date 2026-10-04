"""Tests for the community memory (community.py) with fake vectors, so they run without the encoder."""

import numpy as np
import pytest

from scamguard import community, semantic
from scamguard.storage import Storage

VECTORS = {
    "wave": [1.0, 0.0, 0.0],
    "wave, other name": [0.97, 0.243, 0.0],     # cosine 0.97 with "wave"
    "same topic, not the same": [0.9, 0.0, 0.436],  # cosine 0.90: below SAME_SCAM_AT
    "unrelated": [0.0, 1.0, 0.0],
}


@pytest.fixture()
def memory(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMGUARD_SALT", "test")
    monkeypatch.setattr(semantic, "embed", lambda text: np.array(VECTORS[text], dtype=np.float32))
    return community.CommunityMemory(Storage(tmp_path / "t.db"))


def test_counts_different_people_not_reports(memory):
    memory.add("wave", reporter_id=1)
    memory.add("wave", reporter_id=1)
    assert memory.reporters_of_similar("wave, other name") == 1
    memory.add("wave, other name", reporter_id=2)
    assert memory.reporters_of_similar("wave") == 2


def test_only_near_copies_match(memory):
    memory.add("wave", 1)
    memory.add("wave", 2)
    assert memory.reporters_of_similar("same topic, not the same") == 0
    assert memory.reporters_of_similar("unrelated") == 0


def test_reports_survive_a_restart(memory):
    memory.add("wave", 1)
    memory.add("wave", 2)
    fresh = community.CommunityMemory(memory.storage)          # e.g. after a redeploy
    assert fresh.reporters_of_similar("wave, other name") == 2


def test_without_the_encoder_nothing_is_stored(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAMGUARD_SALT", "test")
    monkeypatch.setattr(semantic, "embed", lambda text: None)
    mem = community.CommunityMemory(Storage(tmp_path / "t.db"))
    assert mem.add("anything", 1) is False
    assert mem.reporters_of_similar("anything") == 0


def test_a_match_alone_is_a_warning_never_dangerous():
    from scamguard.analyzer import DANGEROUS_AT, SUSPICIOUS_AT

    assert SUSPICIOUS_AT <= community.COMMUNITY_WEIGHT < DANGEROUS_AT
