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
  * Groups whose admins switch on "Help train the AI" add a masked copy of each removed
    message to training_candidates: no group, no sender, only the text, the verdict and the
    date. Only the owner (SCAMGUARD_OWNER_IDS) can export it, to review and label by hand.
"""

from __future__ import annotations

import csv
import hashlib
import os
import secrets
import sqlite3
from datetime import date, datetime, timezone
from pathlib import Path

from .textnorm import mask_for_dataset

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
            CREATE TABLE IF NOT EXISTS domain_seen (
                domain TEXT NOT NULL, fp TEXT NOT NULL, PRIMARY KEY (domain, fp)
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
            CREATE TABLE IF NOT EXISTS training_candidates (
                fp TEXT PRIMARY KEY, text TEXT NOT NULL, verdict TEXT NOT NULL, source TEXT NOT NULL,
                first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, hits INTEGER NOT NULL DEFAULT 1
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
                       "clean_joins INTEGER NOT NULL DEFAULT 0", "title TEXT NOT NULL DEFAULT ''",
                       "train INTEGER NOT NULL DEFAULT 0"):
            try:   # columns added after the first release: older databases get them here
                self.db.execute(f"ALTER TABLE group_settings ADD COLUMN {column}")
            except sqlite3.OperationalError:
                pass   # already there
        try:
            self.db.execute("ALTER TABLE flagged_domains ADD COLUMN confirmed INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass
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

    def record_domain(self, domain: str, seen_by: int | None = None, confirmed: bool = False) -> None:
        """Count a detection. `seen_by` (whose message or check it was, kept as a salted fingerprint)
        lets the threat feed require different people; `confirmed` = Google Safe Browsing or VirusTotal agreed."""
        today = date.today().isoformat()
        self.db.execute(
            "INSERT INTO flagged_domains (domain, first_seen, last_seen, hits, confirmed) VALUES (?, ?, ?, 1, ?) "
            "ON CONFLICT(domain) DO UPDATE SET last_seen = excluded.last_seen, hits = hits + 1, "
            "confirmed = MAX(confirmed, excluded.confirmed)",
            (domain, today, today, int(confirmed)),
        )
        if seen_by is not None:
            self.db.execute("INSERT OR IGNORE INTO domain_seen (domain, fp) VALUES (?, ?)", (domain, self._fp(seen_by)))
        self.db.commit()

    def feed_domains(self, min_people: int, limit: int) -> list[tuple[str, str, str, int]]:
        """Detected domains trustworthy enough for the public threat feed: confirmed by an online
        service, or seen in the messages or checks of at least `min_people` different people."""
        return self.db.execute(
            "SELECT d.domain, d.first_seen, d.last_seen, d.hits FROM flagged_domains d "
            "WHERE d.confirmed = 1 OR (SELECT COUNT(*) FROM domain_seen s WHERE s.domain = d.domain) >= ? "
            "ORDER BY d.last_seen DESC, d.hits DESC LIMIT ?", (min_people, limit)).fetchall()

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
            "SELECT preview, MIN(substr(ts, 1, 10)), COUNT(*) FROM reports WHERE kind = 'site' AND ts >= ? "
            "GROUP BY ind HAVING COUNT(*) >= ? ORDER BY MAX(ts) DESC LIMIT ?",
            (self.reports_since(), threshold, limit)).fetchall()

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
    @staticmethod
    def reports_since() -> str:
        """Reports older than REPORT_DAYS stop counting everywhere: warnings, the feed and the stats."""
        from datetime import timedelta
        from .blocklist import REPORT_DAYS

        return (datetime.now(timezone.utc) - timedelta(days=REPORT_DAYS)).isoformat(timespec="seconds")

    def _ind(self, kind: str, value: str) -> str:
        return hashlib.sha256(self._salt + f"{kind}:{value}".encode()).hexdigest()[:32]

    def add_reports(self, indicators, reporter_id: int) -> int:
        """Record one person's report of these indicators. Returns how many were new for this person."""
        reporter, now, new = self._fp(reporter_id), datetime.now(timezone.utc).isoformat(timespec="seconds"), 0
        for ind in indicators:
            key = self._ind(ind.kind, ind.value)
            if self.db.execute("SELECT 1 FROM reports WHERE ind = ? AND reporter = ?", (key, reporter)).fetchone():
                # already reported by this person: only refresh the date, so the report keeps counting
                self.db.execute("UPDATE reports SET ts = ? WHERE ind = ? AND reporter = ?", (now, key, reporter))
                continue
            self.db.execute("INSERT INTO reports (ind, kind, preview, reporter, ts) VALUES (?, ?, ?, ?, ?)",
                            (key, ind.kind, ind.preview, reporter, now))
            new += 1
        self.db.commit()
        return new

    def report_counts(self, indicators, since: str = "") -> dict:
        """Number of distinct reporters for each indicator (only those reported at least once),
        counting only reports made at or after `since` (an ISO timestamp)."""
        out = {}
        for ind in indicators:
            n = self.db.execute("SELECT COUNT(*) FROM reports WHERE ind = ? AND ts >= ?",
                                (self._ind(ind.kind, ind.value), since)).fetchone()[0]
            if n:
                out[ind] = n
        return out

    def blocked_count(self, threshold: int) -> int:
        return self.db.execute(
            "SELECT COUNT(*) FROM (SELECT ind FROM reports WHERE ts >= ? GROUP BY ind HAVING COUNT(*) >= ?)",
            (self.reports_since(), threshold)
        ).fetchone()[0]

    # ---- groups (see guard.py) ----
    def group_settings(self, chat_id: int):
        from .guard import GroupSettings

        row = self.db.execute("SELECT mode, strict, mute, lang, deleted, test, newcomers, clean_joins, train "
                              "FROM group_settings WHERE chat_id = ?", (chat_id,)).fetchone()
        if row is None:
            return GroupSettings()
        mode, strict, mute, lang, deleted, test, newcomers, clean_joins, train = row
        return GroupSettings(mode, bool(strict), bool(mute), lang, deleted, bool(test), bool(newcomers),
                             bool(clean_joins), bool(train))

    def save_group_settings(self, chat_id: int, settings) -> None:
        self.db.execute(
            "INSERT INTO group_settings (chat_id, mode, strict, mute, lang, deleted, test, newcomers, clean_joins, "
            "train) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(chat_id) DO UPDATE SET mode = excluded.mode, strict = excluded.strict, "
            "mute = excluded.mute, lang = excluded.lang, test = excluded.test, newcomers = excluded.newcomers, "
            "clean_joins = excluded.clean_joins, train = excluded.train",
            (chat_id, settings.mode, int(settings.strict), int(settings.mute), settings.lang, settings.deleted,
             int(settings.test), int(settings.newcomers), int(settings.clean_joins), int(settings.train)))
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

    # ---- training candidates: scams removed in groups that opted in (see bot.py, /export) ----
    MAX_CANDIDATES = 20_000

    def add_candidate(self, text: str, verdict: str, source: str = "group") -> None:
        """Keep a masked copy of a removed message for the owner to review and label. Repeats of one
        scam wave are counted, not stored again. No chat, sender or time of day beyond the date."""
        masked = mask_for_dataset(text)
        if len(masked) < 8:
            return
        import re as _re

        from .textnorm import normalize, to_latin
        fp = hashlib.sha256(_re.sub(r"[^\w<>]", "", to_latin(normalize(masked))).encode()).hexdigest()
        today = date.today().isoformat()
        cur = self.db.execute(
            "UPDATE training_candidates SET hits = hits + 1, last_seen = ? WHERE fp = ?", (today, fp))
        if cur.rowcount == 0:
            if self.db.execute("SELECT COUNT(*) FROM training_candidates").fetchone()[0] >= self.MAX_CANDIDATES:
                return
            self.db.execute("INSERT INTO training_candidates (fp, text, verdict, source, first_seen, last_seen) "
                            "VALUES (?, ?, ?, ?, ?, ?)", (fp, masked[:4000], verdict, source, today, today))
        self.db.commit()

    def export_dataset_csv(self) -> tuple[bytes, int, int]:
        """Everything collected for training, as one CSV that `python collect.py feedback <file>`
        reviews: (file bytes, feedback rows, group rows)."""
        import io

        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["text", "label", "predicted", "user_agreed", "timestamp", "source", "hits"])
        feedback = self.db.execute("SELECT text, label, predicted, user_agreed, ts FROM feedback ORDER BY id").fetchall()
        for text, label, predicted, agreed, ts in feedback:
            w.writerow([text, label, predicted, agreed, ts, "feedback", 1])
        groups = self.db.execute("SELECT text, verdict, first_seen, hits FROM training_candidates "
                                 "ORDER BY hits DESC, first_seen").fetchall()
        for text, verdict, first_seen, hits in groups:
            w.writerow([text, "", verdict, "", first_seen, "group", hits])
        return buf.getvalue().encode("utf-8"), len(feedback), len(groups)

    # ---- feedback ----
    def add_feedback(self, text: str, label: int, predicted: str, user_agreed: bool) -> None:
        self.db.execute(
            "INSERT INTO feedback (text, label, predicted, user_agreed, ts) VALUES (?, ?, ?, ?, ?)",
            (mask_for_dataset(text), label, predicted, int(user_agreed),
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
