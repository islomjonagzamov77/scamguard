"""Tests for the group guard's decisions (guard.py)."""

from scamguard.analyzer import Level
from scamguard.guard import DELETE, NONE, OFFENSE_WINDOW_S, WARN, GroupSettings, Offenses, decide


def test_dangerous_is_removed_when_possible_else_warned():
    s = GroupSettings()
    assert decide(Level.DANGEROUS, [], s, can_delete=True) == DELETE
    assert decide(Level.DANGEROUS, [], s, can_delete=False) == WARN
    assert decide(Level.SAFE, [], s, can_delete=True) == NONE


def test_suspicious_only_in_strict_mode_and_never_a_question():
    assert decide(Level.SUSPICIOUS, [], GroupSettings(), True) == NONE
    strict = GroupSettings(strict=True)
    assert decide(Level.SUSPICIOUS, [], strict, True) == DELETE
    assert decide(Level.SUSPICIOUS, ["needs_context"], strict, True) == NONE
    assert decide(Level.SUSPICIOUS, [], strict, False) == NONE        # can't delete: don't nag about 🟡


def test_modes():
    assert decide(Level.DANGEROUS, [], GroupSettings(mode="warn"), True) == WARN
    assert decide(Level.DANGEROUS, [], GroupSettings(mode="off"), True) == NONE


def test_offenses_expire():
    o = Offenses()
    assert o.add(1, 7, now=0) == 1
    assert o.add(1, 7, now=10) == 2
    assert o.add(2, 7, now=10) == 1                                    # counted per group
    assert o.add(1, 7, now=OFFENSE_WINDOW_S + 5) == 2                   # the first one expired
    o.clear(1, 7)
    assert o.add(1, 7, now=OFFENSE_WINDOW_S + 6) == 1
