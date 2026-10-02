"""Collect REAL messages for training and for an honest real-world test.

    python collect.py                         # paste messages one by one
    python collect.py screenshots/            # read every image in a folder with OCR
    python collect.py feedback data/feedback_export.csv   # review what bot users sent as feedback
    python collect.py score                   # how well the bot does on real messages it never trained on

Why this exists: every message in data/*.csv was written by hand or by an AI, so the bot
learned how *we imagine* scams look. Real scams are messier. This tool turns a real
message or screenshot into a masked, labeled row in a few seconds.

Where each message goes (decided by a fingerprint of the text, so it never changes):
  * about 80% -> data/real_messages.csv        used for training (train.py reads data/*.csv)
  * about 20% -> data/eval/real_holdout.csv    NEVER used for training; only `score` reads it
Same rule as the intent test set: never change a rule *because* a holdout message fails.

Privacy: card numbers, phone numbers, emails and @usernames are masked automatically.
Names of real people are not: remove them yourself when the tool asks (press e to edit).
"""

from __future__ import annotations

import csv
import glob
import hashlib
import os
import re
import sys
import textwrap
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TRAIN_FILE = ROOT / "data" / "real_messages.csv"
HOLDOUT_FILE = ROOT / "data" / "eval" / "real_holdout.csv"
COLUMNS = ["text", "label", "lang", "category", "source", "added"]
HOLDOUT_SHARE = 20          # percent of messages kept away from training
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".webp"}

# Same category names as the existing data, so all files can be compared.
SCAM_CATEGORIES = ["blocked_account", "bank_impersonation", "prize", "fake_grant", "advance_fee",
                   "easy_money", "investment", "job_scam", "marketplace", "parcel", "relative",
                   "apk", "gov", "threat", "other_scam"]
SAFE_CATEGORIES = ["personal", "bank_notification", "service", "official_post", "news",
                   "marketplace_legit", "business_ad", "work", "warning", "other_safe"]

BOLD, DIM, RED, GREEN, YELLOW, END = "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[0m"

_USERNAME = re.compile(r"(?<![\w.])@[A-Za-z][A-Za-z0-9_]{3,31}\b")
_APOS = "'ʻʼ’‘`"
_NOT_APOS = "(?![" + _APOS + "])"
# Each language gets points for its typical letters, little words and word endings.
_LANG_SIGNS = {
    "uz_cyr": [re.compile(r"[ўқғҳ]", re.I),
               re.compile(r"\w(лар|ни|га|да|дан|нинг|ди|миз|сиз|ингиз|моқда|лик)\b", re.I)],
    "ru": [re.compile(r"[ыьщё]", re.I),
           re.compile(r"\b(и|в|не|на|что|вы|ваш|ваша|вам|для|по|это|с|у|от|за|как|если|чтобы|я|мы)\b", re.I),
           re.compile(r"\w(ть|ие|ия|ий|ый|ой|ую|ешь|ете|ого|ему)\b", re.I)],
    "uz_lat": [re.compile(r"\w?[og][" + _APOS + r"]\w", re.I),
               re.compile(r"\w(lar|ni|ga|da|dan|ning|di|miz|siz|ingiz|moqda|lik|mi|man|san)\b", re.I)],
    "en": [re.compile(r"\b(the|you|your|is|are|to|and|of|for|on|in|at|a|an|be|it|i|my|me|we|our|now|"
                      r"this|that|have|has|will|please|from|with|don't|i'll)\b" + _NOT_APOS, re.I),
           re.compile(r"\w(ing|ed|tion|ly)\b", re.I)],
}


# ---------- pure helpers (tested in tests/test_collect.py) ----------

def mask(text: str) -> str:
    """Mask private data before anything is saved."""
    from scamguard.textnorm import mask_private

    text = mask_private(text)
    return _USERNAME.sub("<USER>", text).strip()


def fingerprint(text: str) -> str:
    """Spelling-insensitive key: the same message pasted twice gets the same key."""
    from scamguard.textnorm import normalize, to_latin

    key = re.sub(r"[^\w<>]", "", to_latin(normalize(text)))
    return hashlib.sha256(key.encode()).hexdigest()


def destination(text: str) -> Path:
    """Fixed 80/20 split. The same text always lands in the same file."""
    return HOLDOUT_FILE if int(fingerprint(text)[:8], 16) % 100 < HOLDOUT_SHARE else TRAIN_FILE


def guess_lang(text: str) -> str:
    """Rough guess (a person confirms it): count each language's typical letters,
    small words and word endings, and pick the script's best match."""
    points = {lang: sum(len(p.findall(text)) for p in pats) for lang, pats in _LANG_SIGNS.items()}
    cyr = sum("а" <= c.lower() <= "я" or c in "ёЁўқғҳЎҚҒҲ" for c in text)
    if cyr > len(text) * 0.2:
        return "ru" if points["ru"] > points["uz_cyr"] else "uz"
    return "en" if points["en"] > points["uz_lat"] else "uz"


def known_fingerprints() -> set[str]:
    """Every message already in any dataset, so nothing is added twice
    and no test message sneaks into training."""
    seen = set()
    files = glob.glob(str(ROOT / "data" / "*.csv")) + glob.glob(str(ROOT / "data" / "eval" / "*.csv"))
    for path in files:
        if path.endswith(("feedback.csv", "feedback_export.csv")):
            continue
        with open(path, encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                if row.get("text"):
                    seen.add(fingerprint(row["text"]))
    return seen


def append_row(path: Path, row: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    new = not path.exists()
    with open(path, "a", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS, lineterminator="\n")
        if new:
            writer.writeheader()
        writer.writerow(row)


def score(path: Path = HOLDOUT_FILE, use_model: bool = True) -> dict:
    """Scams caught and false alarms on real messages the bot never trained on."""
    from scamguard.analyzer import Level, analyze

    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    flagged = [analyze(r["text"], use_model=use_model).level != Level.SAFE for r in rows]
    scams = [fl for fl, r in zip(flagged, rows) if r["label"] == "1"]
    safes = [fl for fl, r in zip(flagged, rows) if r["label"] == "0"]
    return {"total": len(rows), "scams": len(scams), "caught": sum(scams),
            "safe": len(safes), "false_alarms": sum(safes)}


# ---------- terminal interaction ----------

def ask(prompt: str, allowed: set[str] | None = None, default: str = "") -> str:
    while True:
        answer = input(prompt).strip()
        if not answer and default:
            return default
        if allowed is None or answer.lower() in allowed:
            return answer.lower() if allowed else answer
        print(f"  {DIM}Please type one of: {', '.join(sorted(a for a in allowed if a))}{END}")


def read_pasted() -> str | None:
    print(f"\n{BOLD}Paste a message{END} {DIM}(finish with an empty line, or type q to quit){END}")
    lines = []
    while True:
        line = input()
        if not lines and line.strip().lower() == "q":
            return None
        if not line.strip():
            if lines:
                return "\n".join(lines)
            continue
        lines.append(line)


def pick_category(label: int) -> str:
    options = SCAM_CATEGORIES if label == 1 else SAFE_CATEGORIES
    for i, name in enumerate(options, 1):
        print(f"  {DIM}{i:>2}{END} {name}", end="\n" if i % 4 == 0 else "   ")
    print()
    choice = ask("  Category number: ", {str(i) for i in range(1, len(options) + 1)})
    return options[int(choice) - 1]


def label_one(raw: str, source: str, seen: set[str], stats: dict) -> bool:
    """Show one message, ask for a label, save it. Returns False when the user quits."""
    text = mask(raw)
    while True:
        if len(re.findall(r"\w", text)) < 8:
            print(f"  {DIM}Too short or unreadable, skipped.{END}")
            stats["skipped"] += 1
            return True
        fp = fingerprint(text)
        if fp in seen:
            print(f"  {DIM}Already in the dataset, skipped.{END}")
            stats["duplicates"] += 1
            return True

        print("\n" + "─" * 70)
        for para in text.splitlines():
            for line in textwrap.wrap(para, 68) or [""]:
                print(f"  {BOLD}{line}{END}")
        print(f"\n  {DIM}Remove real people's names with e. Read it fully before answering.{END}")
        answer = ask("  1 = scam   0 = safe   e = edit text   s = skip   q = quit: ",
                     {"1", "0", "e", "s", "q"})
        if answer == "q":
            return False
        if answer == "s":
            stats["skipped"] += 1
            return True
        if answer == "e":
            edited = read_pasted()
            if edited:
                text = mask(edited)
            continue
        break

    label = int(answer)
    category = pick_category(label)
    lang = guess_lang(text)
    lang = ask(f"  Language [{lang}] (uz/ru/en, Enter = keep): ", {"uz", "ru", "en", ""}, default=lang)

    dest = destination(text)
    append_row(dest, {"text": text, "label": label, "lang": lang, "category": category,
                      "source": source, "added": date.today().isoformat()})
    seen.add(fp)

    if dest == HOLDOUT_FILE:
        stats["holdout"] += 1
        print(f"  {YELLOW}Saved to the holdout (never trained on).{END}")
    else:
        stats["train"] += 1
        # Only for training rows: show the bot's answer AFTER labeling, so it can't bias the label.
        from scamguard.analyzer import Level, analyze
        verdict = analyze(text)
        flagged = verdict.level != Level.SAFE
        if flagged == bool(label):
            print(f"  {GREEN}Saved. The bot already gets this one right ({verdict.level.value}).{END}")
        else:
            stats["bot_wrong"] += 1
            what = "missed this scam" if label else "raised a false alarm"
            print(f"  {RED}Saved. The bot {what} ({verdict.level.value}): a useful example.{END}")
    return True


def items_from_folder(folder: Path):
    from scamguard import ocr

    if not ocr.available():
        sys.exit("Tesseract is not installed. On a Mac: brew install tesseract tesseract-lang")
    images = sorted(p for p in folder.iterdir() if p.suffix.lower() in IMAGE_EXT)
    print(f"Found {len(images)} image(s) in {folder}")
    for i, path in enumerate(images, 1):
        print(f"\n{DIM}[{i}/{len(images)}] {path.name}{END}")
        yield ocr.image_to_text(path.read_bytes()), "screenshot"


def items_from_feedback(path: Path):
    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    print(f"{len(rows)} feedback row(s). Users can be wrong, so you decide every label yourself.")
    for row in rows:
        agreed = "agreed with" if row.get("user_agreed") == "1" else "disagreed with"
        print(f"\n{DIM}The user {agreed} the bot's verdict ({row.get('predicted', '?')}).{END}")
        yield row["text"], "bot_feedback"


def items_from_paste():
    while True:
        text = read_pasted()
        if text is None:
            return
        yield text, "pasted"


def print_score() -> None:
    if not HOLDOUT_FILE.exists():
        sys.exit("No holdout yet. Collect some real messages first.")
    s = score()
    print(f"\nReal-message holdout: {s['total']} messages the bot never trained on")
    if s["scams"]:
        print(f"  scams caught   {s['caught']}/{s['scams']} ({100 * s['caught'] / s['scams']:.0f}%)")
    if s["safe"]:
        print(f"  false alarms   {s['false_alarms']}/{s['safe']} ({100 * s['false_alarms'] / s['safe']:.0f}%)"
              "   (lower is better)")
    if s["total"] < 50:
        print(f"  {DIM}Fewer than 50 messages: each one moves the numbers a lot. Treat them as a rough sign.{END}")


def main() -> None:
    args = sys.argv[1:]
    if args and args[0] == "score":
        print_score()
        return
    if args and args[0] == "feedback":
        items = items_from_feedback(Path(args[1] if len(args) > 1 else ROOT / "data" / "feedback_export.csv"))
    elif args:
        items = items_from_folder(Path(args[0]))
    else:
        items = items_from_paste()

    seen = known_fingerprints()
    stats = dict(train=0, holdout=0, duplicates=0, skipped=0, bot_wrong=0)
    try:
        for raw, source in items:
            if not label_one(raw, source, seen, stats):
                break
    except (KeyboardInterrupt, EOFError):
        print()

    print(f"\n{BOLD}Session done.{END} Added {stats['train']} for training and {stats['holdout']} to the holdout. "
          f"Skipped {stats['skipped']}, duplicates {stats['duplicates']}.")
    if stats["train"]:
        print(f"The bot was wrong on {stats['bot_wrong']} of the new training messages.")
        print("Next: python train.py   then   python collect.py score")


if __name__ == "__main__":
    os.chdir(ROOT)
    main()
