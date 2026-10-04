"""The bot learns new scams from its users, with no retraining and no redeploy.

Scams come in waves: the same template is sent to thousands of people with only the name, the
amount or the link changed. The trained models only know last month's schemes. So when someone
reports a message as a scam (🚩, or ❌ on a 🟢 verdict), the bot keeps its meaning vector from the
semantic model. Once REPORT_THRESHOLD *different* people have reported messages that mean almost
the same thing, everyone who checks a near-copy is warned, minutes after the wave started.

Design choices:
  * Only the 384-number vector of the masked message is stored, never its text.
  * SAME_SCAM_AT = 0.93 (cosine). Variants of one scam template (other name, amount, link) score
    0.94-0.96; a real bank notification next to a fake one 0.915, two different scams ~0.89.
    In the training data 2% of normal messages are this close to any known scam.
  * A match alone gives 🟡 at most (COMMUNITY_WEIGHT), never 🔴, so two fake accounts can't get
    a normal message marked dangerous. Together with the bot's own evidence it can go higher.
  * Same rule as the blocklist: different reporters, counted by salted fingerprint.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import numpy as np

from . import semantic

SAME_SCAM_AT = float(os.getenv("SCAMGUARD_SAME_SCAM_AT", "0.93"))
MEMORY_DAYS = 90                 # scam waves fade; old reports stop counting
COMMUNITY_WEIGHT = 0.5           # evidence of a match: enough for 🟡 on its own, not for 🔴


class CommunityMemory:
    def __init__(self, storage):
        self.storage = storage
        self._vectors: np.ndarray | None = None   # loaded lazily from the database
        self._reporters: list[str] = []

    def _load(self) -> None:
        since = (datetime.now(timezone.utc) - timedelta(days=MEMORY_DAYS)).isoformat(timespec="seconds")
        rows = self.storage.scam_vectors(since)
        self._reporters = [who for _, who in rows]
        self._vectors = (np.vstack([np.frombuffer(v, dtype=np.float16) for v, _ in rows]).astype(np.float32)
                         if rows else np.zeros((0, 0), dtype=np.float32))

    def add(self, text: str, reporter_id: int) -> bool:
        """Remember that this person reported `text` as a scam. False without the semantic model."""
        vec = semantic.embed(text) if text.strip() else None
        if vec is None:
            return False
        reporter = self.storage.add_scam_vector(vec.astype(np.float16).tobytes(), reporter_id)
        if self._vectors is not None:
            row = vec.astype(np.float16).astype(np.float32)[None, :]
            self._vectors = row if self._vectors.size == 0 else np.vstack([self._vectors, row])
            self._reporters.append(reporter)
        return True

    def reporters_of_similar(self, text: str) -> int:
        """How many different people reported a message that means almost the same as `text`."""
        vec = semantic.embed(text) if text.strip() else None
        if vec is None:
            return 0
        if self._vectors is None:
            self._load()
        if self._vectors.size == 0:
            return 0
        sims = self._vectors @ vec
        return len({who for who, s in zip(self._reporters, sims) if s >= SAME_SCAM_AT})
