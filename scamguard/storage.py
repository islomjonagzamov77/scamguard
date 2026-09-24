"""Tiny SQLite storage: language settings, anonymous counters and opt-in feedback.

Privacy by design:
  * Telegram user IDs are never stored. A salted SHA-256 fingerprint is kept
    only so the bot remembers each person's language and counts unique users.
  * Checked messages are never stored. Feedback text is saved only when a user
    presses a feedback button, and card/phone/email data is masked first.
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
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT NOT NULL, label INTEGER NOT NULL, predicted TEXT NOT NULL,
                user_agreed INTEGER NOT NULL, ts TEXT NOT NULL
            );
        """)
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

    def stats(self) -> dict[str, int]:
        users = self.db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        c, s, d = self.db.execute(
            "SELECT COALESCE(SUM(checks),0), COALESCE(SUM(suspicious),0), COALESCE(SUM(dangerous),0) FROM daily"
        ).fetchone()
        row = self.db.execute("SELECT checks FROM daily WHERE day = ?", (date.today().isoformat(),)).fetchone()
        return {"users": users, "checks": c, "suspicious": s, "dangerous": d, "today": row[0] if row else 0}

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
