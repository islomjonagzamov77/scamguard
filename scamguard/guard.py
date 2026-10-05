"""Group guard: what the bot does with a checked message in a group or a channel's comments.

The bot only deletes when it is an admin with the "Delete messages" right. Choices, from most to
least important:
  * Never act on admins, anonymous admins or the group's own linked channel (its posts are copied
    into the comments group automatically). Their messages are the group's own voice.
  * 🔴 dangerous (scam links, programs like .apk/.exe, community-blocklisted numbers) -> delete.
  * 🟡 suspicious -> left alone by default: a deleted normal message angers members more than a
    missed borderline one. "Strict" mode deletes these too. A "can't tell" question about a money
    request is never deleted.
  * Every deletion posts a short notice with the reason, so members see the group is protected and
    admins can undo a mistake.
  * Repeat offenders (OFFENSES_TO_MUTE deletions in OFFENSE_WINDOW_S) can be muted for MUTE_S if
    the admins switch that on.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass

from .analyzer import Level

MODES = ("delete", "warn", "off")
OFFENSES_TO_MUTE = 3
OFFENSE_WINDOW_S = 24 * 3600
MUTE_S = 24 * 3600

NONE, WARN, DELETE = "none", "warn", "delete"


@dataclass
class GroupSettings:
    mode: str = "delete"     # delete: remove 🔴 (warn if the bot can't); warn: only reply; off: silent
    strict: bool = False     # also remove 🟡
    mute: bool = False       # mute repeat offenders for a day
    lang: str = "uz"         # language of the bot's messages in this group
    deleted: int = 0         # messages removed so far (shown in /settings)


def decide(level: Level, signals: list[str], settings: GroupSettings, can_delete: bool) -> str:
    """NONE, WARN or DELETE for a message from an ordinary member."""
    if settings.mode == "off":
        return NONE
    harmful = level == Level.DANGEROUS or (
        settings.strict and level == Level.SUSPICIOUS and "needs_context" not in signals)
    if not harmful:
        return NONE
    if settings.mode == "delete" and can_delete:
        return DELETE
    return WARN if level == Level.DANGEROUS else NONE   # without deleting, speak up only for 🔴


class Offenses:
    """Deletions per member per group, in memory (a restart forgives everyone)."""

    def __init__(self) -> None:
        self._hits: dict[tuple[int, int], deque] = defaultdict(deque)

    def add(self, chat_id: int, sender_id: int, now: float | None = None) -> int:
        """Record a deletion and return how many this sender has in the window."""
        now = time.time() if now is None else now
        hits = self._hits[(chat_id, sender_id)]
        hits.append(now)
        while hits and now - hits[0] > OFFENSE_WINDOW_S:
            hits.popleft()
        return len(hits)

    def clear(self, chat_id: int, sender_id: int) -> None:
        self._hits.pop((chat_id, sender_id), None)
