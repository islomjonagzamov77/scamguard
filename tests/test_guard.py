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


# ---------------- looking inside files (files.look_inside) ----------------
import io
import zipfile

from scamguard.files import look_inside, needs_look_inside, zip_names
from test_apk import SMS_STEALER, build_apk


def make_zip(names, encrypted=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n in names:
            z.writestr(n, b"payload")
    data = bytearray(buf.getvalue())
    if encrypted:                                   # set the "encrypted" flag like a password-protected zip
        data[6] |= 1
    return bytes(data)


def test_apk_hidden_in_a_zip_is_dangerous_even_with_a_password():
    for encrypted in (False, True):
        v = look_inside(make_zip(["rasmlar/foto_2026.apk", "readme.txt"], encrypted), "rasmlar.zip")
        assert v.level == Level.DANGEROUS and "foto_2026.apk" in v.reasons[0].text("en")


def test_app_renamed_to_look_harmless_is_dangerous():
    v = look_inside(build_apk(SMS_STEALER), "document")
    assert v.level == Level.DANGEROUS and "really an Android app" in v.reasons[0].text("en")
    assert look_inside(build_apk(SMS_STEALER), "app.apk") is None      # the name check already covers it


def test_windows_program_under_another_name():
    assert look_inside(b"MZ\x90\x00" + b"\0" * 64, "video.dat").level == Level.DANGEROUS


def test_normal_archives_and_files_add_nothing():
    assert look_inside(make_zip(["a.jpg", "b.pdf"]), "photos.zip") is None
    assert look_inside(b"%PDF-1.7 ...", "x.bin") is None


def test_damaged_zip_names_are_still_read():
    data = make_zip(["foto.apk"])
    damaged = data[:data.rfind(b"PK\x01\x02")]           # central directory cut off
    assert zip_names(damaged) == ["foto.apk"]


def test_only_archives_and_unknown_types_are_downloaded():
    assert needs_look_inside("photos.zip") and needs_look_inside("document") and needs_look_inside("x.dat")
    assert not any(needs_look_inside(n) for n in ["a.pdf", "rasm.jpg", "song.mp3", "app.apk", "doc.docm"])


def test_existing_databases_get_the_new_column(tmp_path, monkeypatch):
    """The live bot's database was created before test mode existed."""
    import sqlite3

    from scamguard.storage import Storage

    monkeypatch.setenv("SCAMGUARD_SALT", "test")
    db = sqlite3.connect(tmp_path / "old.db")
    db.execute("CREATE TABLE group_settings (chat_id INTEGER PRIMARY KEY, mode TEXT NOT NULL DEFAULT 'delete', "
               "strict INTEGER NOT NULL DEFAULT 0, mute INTEGER NOT NULL DEFAULT 0, lang TEXT NOT NULL DEFAULT 'uz', "
               "deleted INTEGER NOT NULL DEFAULT 0)")
    db.execute("INSERT INTO group_settings (chat_id, mode, deleted) VALUES (-1, 'warn', 7)")
    db.commit()
    db.close()
    storage = Storage(tmp_path / "old.db")
    settings = storage.group_settings(-1)
    assert (settings.mode, settings.deleted, settings.test) == ("warn", 7, False)
    settings.test = True
    storage.save_group_settings(-1, settings)
    assert Storage(tmp_path / "old.db").group_settings(-1).test is True     # opening twice is fine too
