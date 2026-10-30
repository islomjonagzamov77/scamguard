"""Tiny SQLite storage: language settings, anonymous counters and opt-in feedback.

Privacy by design:
  * Telegram user IDs are never stored. A salted SHA-256 fingerprint is kept
    only so the bot remembers each person's language and counts unique users.
  * Checked messages are never stored. Feedback text is saved only when a user
    presses a feedback button, and card/phone/email data is masked first.
  * For messages reported as scams, the community memory keeps only the semantic
    model's vector of the masked text (see community.py), not the text.
  * The group log keeps, for 30 days, when a message was removed, the sender's display
    name and the reason, so a group's admins can review removals. Never the message text.
  * For newcomer protection, when a member joined a group (salted fingerprint, 2 days),
    and for "My groups", which groups a person manages (salted fingerprint).
"""

from __future__ import annotations

import csv
import hashlib
import os
import secrets
import sqlite3
from datetime import date, datetime, timezone
from pathlib import Path

from .textnorm import mask_private

# On a server, point SCAMGUARD_DATA_DIR at a persistent volume (e.g. /data on Railway)
# so stats, language settings and feedback survive redeploys.
DATA_DIR = Path(os.getenv("SCAMGUARD_DATA_DIR") or Path(__file__).resolve().parent.parent / "data")


class Storage:
    def __init__(self, path: Path | str = DATA_DIR / "scamguard.db"):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                fp TEXT PRIMARY KEY, lang TEXT NOT NULL, created TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS daily (
                day TEXT PRIMARY KEY,
                checks INTEGER DEFAULT 0, safe INTEGER DEFAULT 0,
                suspicious INTEGER DEFAULT 0, dangerous INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS reports (
                ind TEXT NOT NULL, kind TEXT NOT NULL, preview TEXT NOT NULL,
                reporter TEXT NOT NULL, ts TEXT NOT NULL,
                PRIMARY KEY (ind, reporter)
            );
            CREATE TABLE IF NOT EXISTS daily_cat (
                day TEXT NOT NULL, category TEXT NOT NULL, n INTEGER DEFAULT 0,
                PRIMARY KEY (day, category)
            );
            CREATE TABLE IF NOT EXISTS flagged_domains (
                domain TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
                hits INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS group_settings (
                chat_id INTEGER PRIMARY KEY, mode TEXT NOT NULL DEFAULT 'delete',
                strict INTEGER NOT NULL DEFAULT 0, mute INTEGER NOT NULL DEFAULT 0,
                lang TEXT NOT NULL DEFAULT 'uz', deleted INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS group_members (
                chat_id INTEGER NOT NULL, fp TEXT NOT NULL, joined REAL NOT NULL,
                PRIMARY KEY (chat_id, fp)
            );
            CREATE TABLE IF NOT EXISTS group_managers (
                chat_id INTEGER NOT NULL, fp TEXT NOT NULL, PRIMARY KEY (chat_id, fp)
            );
            CREATE TABLE IF NOT EXISTS group_log (
                chat_id INTEGER NOT NULL, ts TEXT NOT NULL, sender TEXT NOT NULL, reason TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scam_vectors (
                vec BLOB NOT NULL, reporter TEXT NOT NULL, ts TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL, label INTEGER NOT NULL, predicted TEXT NOT NULL,
                user_agreed INTEGER NOT NULL, ts TEXT NOT NULL
            );
        """)
        for column in ("test INTEGER NOT NULL DEFAULT 0", "newcomers INTEGER NOT NULL DEFAULT 1",
                       "clean_joins INTEGER NOT NULL DEFAULT 0", "title TEXT NOT NULL DEFAULT ''"):
            try:   # columns added after the first release: older databases get them here
                self.db.execute(f"ALTER TABLE group_settings ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass   # already there
        self.db.commit()
        self._salt = self._load_salt(path.parent / ".salt")

    @staticmethod
    def _load_salt(salt_file: Path) -> bytes:
        env = os.getenv("SCAMGUARD_SALT")
        if env:
            return env.encode()
        if not salt_file.exists():
            salt_file.write_text(secrets.token_hex(32))
        return salt_file.read_text().strip().encode()

    def _fp(self, user_id: int) -> str:
        return hashlib.sha256(self._salt + str(user_id).encode()).hexdigest()[:32]

    # ---- users / language ----
    def get_lang(self, user_id: int) -> str | None:
        row = self.db.execute("SELECT lang FROM users WHERE fp = ?", (self._fp(user_id),)).fetchone()
        return row[0] if row else None

    def set_lang(self, user_id: int, lang: str) -> None:
        self.db.execute(
            "INSERT INTO users (fp, lang, created) VALUES (?, ?, ?) "
            "ON CONFLICT(fp) DO UPDATE SET lang = excluded.lang",
            (self._fp(user_id), lang, datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        self.db.commit()

    # ---- counters ----
    def record_check(self, level: str) -> None:
        if level not in ("safe", "suspicious", "dangerous"):
            return
        today = date.today().isoformat()
        self.db.execute("INSERT OR IGNORE INTO daily (day) VALUES (?)", (today,))
        self.db.execute(
            f"UPDATE daily SET checks = checks + 1, {level} = {level} + 1 WHERE day = ?", (today,)
        )
        self.db.commit()

    # ---- radar (public, aggregated) ----
    def record_category(self, category: str) -> None:
        today = date.today().isoformat()
        self.db.execute("INSERT OR IGNORE INTO daily_cat (day, category) VALUES (?, ?)", (today, category))
        self.db.execute("UPDATE daily_cat SET n = n + 1 WHERE day = ? AND category = ?", (today, category))
        self.db.commit()

    def record_domain(self, domain: str) -> None:
        today = date.today().isoformat()
        self.db.execute(
            "INSERT INTO flagged_domains (domain, first_seen, last_seen, hits) VALUES (?, ?, ?, 1) "
            "ON CONFLICT(domain) DO UPDATE SET last_seen = excluded.last_seen, hits = hits + 1",
            (domain, today, today),
        )
        self.db.commit()

    def daily_series(self, days: int) -> list[tuple[str, int, int]]:
        """(day, checks, scams) for the last `days` days, oldest first, zero-filled."""
        from datetime import timedelta
        today = date.today()
        rows = dict((d, (c, s + x)) for d, c, s, x in self.db.execute(
            "SELECT day, checks, suspicious, dangerous FROM daily WHERE day >= ?",
            ((today - timedelta(days=days - 1)).isoformat(),)))
        out = []
        for i in range(days - 1, -1, -1):
            d = (today - timedelta(days=i)).isoformat()
            c, s = rows.get(d, (0, 0))
            out.append((d, c, s))
        return out

    def category_counts(self, since: str) -> list[tuple[str, int]]:
        return self.db.execute(
            "SELECT category, SUM(n) FROM daily_cat WHERE day >= ? GROUP BY category ORDER BY SUM(n) DESC", (since,)
        ).fetchall()

    def recent_domains(self, limit: int) -> list[tuple[str, str, str, int]]:
        return self.db.execute(
            "SELECT domain, first_seen, last_seen, hits FROM flagged_domains ORDER BY last_seen DESC, hits DESC LIMIT ?",
            (limit,)).fetchall()

    def community_sites(self, threshold: int, limit: int) -> list[tuple[str, str, int]]:
        """Sites reported by at least `threshold` different people: (preview, first report day, reporters)."""
        return self.db.execute(
            "SELECT preview, MIN(substr(ts, 1, 10)), COUNT(*) FROM reports WHERE kind = 'site' "
            "GROUP BY ind HAVING COUNT(*) >= ? ORDER BY MAX(ts) DESC LIMIT ?", (threshold, limit)).fetchall()

    def first_day(self) -> str | None:
        row = self.db.execute("SELECT MIN(day) FROM daily").fetchone()
        return row[0] if row else None

    def stats(self, threshold: int = 2) -> dict[str, int]:
        users = self.db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        c, s, d = self.db.execute(
            "SELECT COALESCE(SUM(checks),0), COALESCE(SUM(suspicious),0), COALESCE(SUM(dangerous),0) FROM daily"
        ).fetchone()
        row = self.db.execute("SELECT checks FROM daily WHERE day = ?", (date.today().isoformat(),)).fetchone()
        return {"users": users, "checks": c, "suspicious": s, "dangerous": d, "today": row[0] if row else 0,
                "blocked": self.blocked_count(threshold)}

    # ---- community blocklist ----
    def _ind(self, kind: str, value: str) -> str:
        return hashlib.sha256(self._salt + f"{kind}:{value}".encode()).hexdigest()[:32]

    def add_reports(self, indicators, reporter_id: int) -> int:
        """Record one person's report of these indicators. Returns how many were new for this person."""
        reporter, now, new = self._fp(reporter_id), datetime.now(timezone.utc).isoformat(timespec="seconds"), 0
        for ind in indicators:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO reports (ind, kind, preview, reporter, ts) VALUES (?, ?, ?, ?, ?)",
                (self._ind(ind.kind, ind.value), ind.kind, ind.preview, reporter, now),
            )
            new += cur.rowcount
        self.db.commit()
        return new

    def report_counts(self, indicators) -> dict:
        """Number of distinct reporters for each indicator (only those reported at least once)."""
        out = {}
        for ind in indicators:
            n = self.db.execute("SELECT COUNT(*) FROM reports WHERE ind = ?", (self._ind(ind.kind, ind.value),)).fetchone()[0]
            if n:
                out[ind] = n
        return out

    def blocked_count(self, threshold: int) -> int:
        return self.db.execute(
            "SELECT COUNT(*) FROM (SELECT ind FROM reports GROUP BY ind HAVING COUNT(*) >= ?)", (threshold,)
        ).fetchone()[0]

    # ---- groups (see guard.py) ----
    def group_settings(self, chat_id: int):
        from .guard import GroupSettings

        row = self.db.execute("SELECT mode, strict, mute, lang, deleted, test, newcomers, clean_joins "
                              "FROM group_settings WHERE chat_id = ?", (chat_id,)).fetchone()
        if row is None:
            return GroupSettings()
        mode, strict, mute, lang, deleted, test, newcomers, clean_joins = row
        return GroupSettings(mode, bool(strict), bool(mute), lang, deleted, bool(test), bool(newcomers),
                             bool(clean_joins))

    def save_group_settings(self, chat_id: int, settings) -> None:
        self.db.execute(
            "INSERT INTO group_settings (chat_id, mode, strict, mute, lang, deleted, test, newcomers, clean_joins) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(chat_id) DO UPDATE SET mode = excluded.mode, strict = excluded.strict, "
            "mute = excluded.mute, lang = excluded.lang, test = excluded.test, newcomers = excluded.newcomers, "
            "clean_joins = excluded.clean_joins",
            (chat_id, settings.mode, int(settings.strict), int(settings.mute), settings.lang, settings.deleted,
             int(settings.test), int(settings.newcomers), int(settings.clean_joins)))
        self.db.commit()

    def count_group_deletion(self, chat_id: int) -> None:
        self.db.execute("INSERT OR IGNORE INTO group_settings (chat_id) VALUES (?)", (chat_id,))
        self.db.execute("UPDATE group_settings SET deleted = deleted + 1 WHERE chat_id = ?", (chat_id,))
        self.db.commit()

    # newcomers: when each member joined (salted fingerprint, kept 2 days)
    def member_joined(self, chat_id: int, user_id: int, when: float) -> None:
        self.db.execute("INSERT OR REPLACE INTO group_members (chat_id, fp, joined) VALUES (?, ?, ?)",
                        (chat_id, self._fp(user_id), when))
        self.db.execute("DELETE FROM group_members WHERE joined < ?", (when - 2 * 86400,))
        self.db.commit()

    def joined_at(self, chat_id: int, user_id: int) -> float | None:
        row = self.db.execute("SELECT joined FROM group_members WHERE chat_id = ? AND fp = ?",
                              (chat_id, self._fp(user_id))).fetchone()
        return row[0] if row else None

    # "My groups": who manages which group (salted fingerprint), and the group's name
    def add_manager(self, chat_id: int, user_id: int, title: str) -> None:
        self.db.execute("INSERT OR IGNORE INTO group_managers (chat_id, fp) VALUES (?, ?)", (chat_id, self._fp(user_id)))
        self.db.execute("INSERT OR IGNORE INTO group_settings (chat_id) VALUES (?)", (chat_id,))
        if title:
            self.db.execute("UPDATE group_settings SET title = ? WHERE chat_id = ?", (title, chat_id))
        self.db.commit()

    def managed_groups(self, user_id: int) -> list[tuple[int, str, int]]:
        """(chat_id, title, removed so far) for the groups this person manages."""
        return self.db.execute(
            "SELECT m.chat_id, COALESCE(g.title, ''), COALESCE(g.deleted, 0) FROM group_managers m "
            "LEFT JOIN group_settings g ON g.chat_id = m.chat_id WHERE m.fp = ? ORDER BY g.deleted DESC",
            (self._fp(user_id),)).fetchall()

    def forget_group(self, chat_id: int) -> None:
        """The bot left or was removed: the group disappears from everyone's list."""
        self.db.execute("DELETE FROM group_managers WHERE chat_id = ?", (chat_id,))
        self.db.execute("DELETE FROM group_members WHERE chat_id = ?", (chat_id,))
        self.db.commit()

    LOG_DAYS = 30

    def add_group_log(self, chat_id: int, sender: str, reason: str) -> None:
        """What was removed in a group and why, for its admins (/log). Never the message text."""
        now = datetime.now(timezone.utc)
        self.db.execute("INSERT INTO group_log (chat_id, ts, sender, reason) VALUES (?, ?, ?, ?)",
                        (chat_id, now.isoformat(timespec="seconds"), sender, reason))
        from datetime import timedelta
        self.db.execute("DELETE FROM group_log WHERE ts < ?",
                        ((now - timedelta(days=self.LOG_DAYS)).isoformat(timespec="seconds"),))
        self.db.commit()

    def group_log(self, chat_id: int, limit: int = 15) -> list[tuple[str, str, str]]:
        """(time, sender, reason), newest first."""
        return self.db.execute("SELECT ts, sender, reason FROM group_log WHERE chat_id = ? ORDER BY ts DESC, rowid DESC "
                               "LIMIT ?", (chat_id, limit)).fetchall()

    # ---- community memory (vectors of reported messages, see community.py) ----
    def add_scam_vector(self, vec: bytes, reporter_id: int) -> str:
        """Store one person's report as a vector. Returns the reporter's fingerprint."""
        reporter = self._fp(reporter_id)
        self.db.execute("INSERT INTO scam_vectors (vec, reporter, ts) VALUES (?, ?, ?)",
                        (vec, reporter, datetime.now(timezone.utc).isoformat(timespec="seconds")))
        self.db.commit()
        return reporter

    def scam_vectors(self, since: str) -> list[tuple[bytes, str]]:
        return self.db.execute("SELECT vec, reporter FROM scam_vectors WHERE ts >= ?", (since,)).fetchall()

    # ---- feedback ----
    def add_feedback(self, text: str, label: int, predicted: str, user_agreed: bool) -> None:
        self.db.execute(
            "INSERT INTO feedback (text, label, predicted, user_agreed, ts) VALUES (?, ?, ?, ?, ?)",
            (mask_private(text), label, predicted, int(user_agreed),
             datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        self.db.commit()

    def export_feedback(self, csv_path: Path | str = DATA_DIR / "feedback_export.csv") -> int:
        """Write feedback as a text,label CSV that train.py can use directly."""
        rows = self.db.execute("SELECT text, label, predicted, user_agreed, ts FROM feedback").fetchall()
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["text", "label", "predicted", "user_agreed", "timestamp"])
            w.writerows(rows)
        return len(rows)
