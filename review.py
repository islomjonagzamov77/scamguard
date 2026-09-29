"""Review and add examples in the test set without editing the CSV by hand.

    python review.py          # go through every example nobody has reviewed yet
    python review.py add      # add a new message (for example a real one someone sent you)

Everything is saved after every answer, so you can stop at any time (q) and continue later.
"""

import csv
import os
import re
import sys
import textwrap

from evaluate import COLUMNS, DEFAULT_FILE, check, load

LABELS = {"1": "scam", "2": "safe", "3": "needs_context"}
INTENTS = {"1": "request", "2": "warning", "3": "report", "4": "quote", "5": "info"}
CATEGORIES = ["bank", "marketplace", "apk", "relative", "grant", "prize", "money", "job", "other"]
LABEL_HELP = "1 = scam   2 = safe   3 = can't tell (needs_context)"
INTENT_HELP = "1 = request (asks you to do something)   2 = warning   3 = report (story)   4 = quote   5 = info"

BOLD, DIM, RED, GREEN, YELLOW, END = "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[0m"
COLOR = {"scam": RED, "safe": GREEN, "needs_context": YELLOW}


def save(rows: list[dict]) -> None:
    tmp = DEFAULT_FILE.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    os.replace(tmp, DEFAULT_FILE)                 # never leaves a half-written file behind


def ask(prompt: str, allowed: set[str] | None = None, default: str = "") -> str:
    while True:
        answer = input(prompt).strip()
        if not answer and default:
            return default
        if allowed is None or answer.lower() in allowed:
            return answer.lower() if allowed else answer
        print(f"  {DIM}Please type one of: {', '.join(sorted(a for a in allowed if a))}{END}")


def your_name() -> str:
    name = ask("Your name (it goes in the 'reviewer' column): ")
    return re.sub(r"[^\w-]", "", name.lower()) or "reviewer"


def show(row: dict, n: int, total: int) -> None:
    print("\n" + "─" * 70)
    print(f"{DIM}{n}/{total}   {row['id']}   group {row['group']}   {row['script']}   {row['category']}{END}\n")
    for line in textwrap.wrap(row["text"], 68):
        print(f"  {BOLD}{line}{END}")
    label = row["label"]
    print(f"\n  Draft label:  {COLOR[label]}{BOLD}{label}{END}      intent: {row['intent']}")
    print(f"  Key words:    «{row['evidence']}»")
    if row["note"]:
        print(f"  Note:         {DIM}{row['note']}{END}")


def review() -> None:
    rows = load(DEFAULT_FILE)
    todo = [r for r in rows if r["reviewer"] == "claude-draft"]
    if not todo:
        print("✓ Everything is reviewed. Add new messages with:  python review.py add")
        return
    print(f"{len(todo)} example(s) to review. Question for each one:")
    print(f"{BOLD}  If someone forwarded me this, what should ScamGuard answer?{END}\n")
    name = your_name()
    print(f"\n  Enter = I agree     {LABEL_HELP}")
    print("  i = change intent   n = add a note   s = skip for now   q = save and quit")
    done = 0
    for n, row in enumerate(todo, start=1):
        show(row, n, len(todo))
        answer = ask("\n  Your answer: ", {"", "1", "2", "3", "i", "n", "s", "q"})
        if answer == "q":
            break
        if answer == "s":
            continue
        if answer in LABELS and LABELS[answer] != row["label"]:
            reason = ask(f"  Changed to {LABELS[answer]}. Why? (one short sentence, or Enter): ")
            row["note"] = "; ".join(x for x in (row["note"], f"{name} changed label {row['label']}→{LABELS[answer]}"
                                               + (f": {reason}" if reason else "")) if x)
            row["label"] = LABELS[answer]
        elif answer == "i":
            print(f"  {INTENT_HELP}")
            row["intent"] = INTENTS[ask("  Intent: ", set(INTENTS))]
        elif answer == "n":
            row["note"] = "; ".join(x for x in (row["note"], ask("  Note: ")) if x)
        if answer in ("i", "n"):                      # after an intent change or a note, confirm the label too
            label = ask(f"  Label ({LABEL_HELP}, Enter = keep {row['label']}): ", {"", "1", "2", "3"})
            if label:
                row["label"] = LABELS[label]
        row["reviewer"] = name
        save(rows)
        done += 1
    left = sum(r["reviewer"] == "claude-draft" for r in rows)
    print(f"\n✓ Saved. You reviewed {done} now; {left} left. Run  python review.py  again any time.")


def detect_script(text: str) -> str:
    cyr = len(re.findall(r"[а-яёўқғҳ]", text.lower()))
    lat = len(re.findall(r"[a-z]", text.lower()))
    if cyr and not lat:
        return "cyrl" if re.search(r"[ўқғҳ]", text.lower()) else "ru"
    return "mixed" if cyr else "latn"


def add() -> None:
    rows = load(DEFAULT_FILE)
    name = your_name()
    while True:
        print("\n" + "─" * 70)
        text = " ".join(ask("Paste the message (one line) and press Enter, or just Enter to stop:\n> ").split())
        if not text:
            break
        print(f"\n  {LABEL_HELP}")
        label = LABELS[ask("  Label: ", set(LABELS))]
        print(f"  {INTENT_HELP}")
        intent = INTENTS[ask("  Intent: ", set(INTENTS))]
        while True:
            evidence = ask("  Copy the few words that decide it (they must be in the message):\n  > ")
            if evidence and evidence in text:
                break
            print(f"  {RED}Those words aren't in the message exactly. Copy-paste them.{END}")
        print("  Category: " + "  ".join(f"{i}={c}" for i, c in enumerate(CATEGORIES, 1)))
        category = CATEGORIES[int(ask("  Category number: ", {str(i) for i in range(1, len(CATEGORIES) + 1)})) - 1]
        real = ask("  Is this a REAL message someone received? (y/n): ", {"y", "n"}) == "y"
        if real:
            print(f"  {YELLOW}Make sure card numbers, phone numbers and names are hidden (8600 **** **** 1234).{END}")
        slug = re.sub(r"[^a-z0-9]+", "-", ask("  Short name for this scheme, e.g. job-fee: ").lower()).strip("-") or category
        existing = [r["group"] for r in rows if r["group"].split("-", 1)[-1] == slug]
        if existing:
            group = existing[0]
        else:
            numbers = [int(m.group(1)) for r in rows if (m := re.match(r"g(\d+)", r["group"]))]
            group = f"g{max(numbers, default=0) + 1:02d}-{slug}"
        next_id = max(int(r["id"][1:]) for r in rows if re.fullmatch(r"p\d+", r["id"])) + 1
        row = {"id": f"p{next_id:03d}", "group": group, "intent": intent, "label": label,
               "script": detect_script(text), "category": category, "text": text, "evidence": evidence,
               "source": "real" if real else "written", "reviewer": name, "note": ""}
        problems = check(rows + [row])
        if problems:
            print(f"  {RED}Not saved: {problems[-1]}{END}")
            continue
        rows.append(row)
        save(rows)
        print(f"  {GREEN}✓ Saved as {row['id']} in group {group}.{END}")


if __name__ == "__main__":
    try:
        add() if sys.argv[1:] == ["add"] else review()
    except (KeyboardInterrupt, EOFError):
        print("\nStopped. Everything answered so far is saved.")
