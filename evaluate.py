"""Evaluate ScamGuard on the frozen, human-reviewed test set in data/eval/.

    python evaluate.py              # check the file, then score the analyzer
    python evaluate.py --check      # only check the file format (run after every labeling session)
    python evaluate.py --no-model   # rules and links only

The test set is NEVER used for training (train.py only reads data/*.csv) and rules must
never be tuned by looking at it. Otherwise the numbers stop meaning anything.
See data/eval/LABELING_GUIDE.md for how rows are labeled.
"""

import argparse
import csv
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).parent
DEFAULT_FILE = ROOT / "data" / "eval" / "intent_pairs.csv"

COLUMNS = ["id", "group", "intent", "label", "script", "category", "text", "evidence", "source", "reviewer", "note"]
ALLOWED = {
    "intent": {"request", "warning", "report", "quote", "info"},
    "label": {"scam", "safe", "needs_context"},
    "script": {"latn", "cyrl", "mixed", "ru", "en"},
    "source": {"written", "real"},
}


def load(path: Path) -> list[dict]:
    with open(path, encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != COLUMNS:
            sys.exit(f"{path.name}: columns must be exactly:\n  {','.join(COLUMNS)}\nfound:\n  {','.join(reader.fieldnames or [])}")
        return list(reader)


def check(rows: list[dict]) -> list[str]:
    """Return a list of problems. An empty list means the file is valid."""
    problems, seen = [], set()
    for n, row in enumerate(rows, start=2):                     # line 1 is the header
        where = f"line {n} ({row.get('id') or 'no id'})"
        for col in ("id", "group", "intent", "label", "script", "text", "evidence", "source", "reviewer"):
            if not (row.get(col) or "").strip():
                problems.append(f"{where}: '{col}' is empty")
        if row["id"] in seen:
            problems.append(f"{where}: duplicate id")
        seen.add(row["id"])
        for col, allowed in ALLOWED.items():
            if row[col] and row[col] not in allowed:
                problems.append(f"{where}: {col}='{row[col]}' - use one of {sorted(allowed)}")
        if row["evidence"] and row["evidence"] not in row["text"]:
            problems.append(f"{where}: evidence must be copied exactly from the text")
    return problems


def outcome(label: str, level: str) -> str:
    if label == "scam":
        return "ok" if level != "safe" else "MISSED"
    if label == "safe":
        return "ok" if level == "safe" else "FALSE ALARM"
    return "ok" if level == "suspicious" else f"{level.upper()} (want suspicious)"   # needs_context


def pct(a: int, b: int) -> str:
    return f"{a}/{b} ({a / b:.0%})" if b else "-"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", type=Path, default=DEFAULT_FILE)
    ap.add_argument("--check", action="store_true", help="only validate the file")
    ap.add_argument("--no-model", action="store_true", help="rules and links only")
    args = ap.parse_args()

    rows = load(args.file)
    problems = check(rows)
    if problems:
        print(f"✗ {len(problems)} problem(s) in {args.file.name}:")
        print("\n".join(f"  - {p}" for p in problems))
        sys.exit(1)
    labels = Counter(r["label"] for r in rows)
    print(f"✓ {args.file.name}: {len(rows)} rows, {len({r['group'] for r in rows})} groups, "
          + ", ".join(f"{k}={v}" for k, v in sorted(labels.items())))
    unreviewed = sum(r["reviewer"] == "claude-draft" for r in rows)
    if unreviewed:
        print(f"  ! {unreviewed} row(s) still marked claude-draft: review them and put your name in 'reviewer'")
    if args.check:
        return

    from scamguard.analyzer import analyze

    results = []
    for r in rows:
        v = analyze(r["text"], use_model=not args.no_model)
        results.append((r, v.level.value, v.score, outcome(r["label"], v.level.value)))

    scam = [x for x in results if x[0]["label"] == "scam"]
    safe = [x for x in results if x[0]["label"] == "safe"]
    ctx = [x for x in results if x[0]["label"] == "needs_context"]
    print("\nHeadline")
    print(f"  scams caught          {pct(sum(x[3] == 'ok' for x in scam), len(scam))}")
    print(f"  false alarms on safe  {pct(sum(x[3] != 'ok' for x in safe), len(safe))}   (lower is better)")
    print(f"  needs-context → 🟡    {pct(sum(x[3] == 'ok' for x in ctx), len(ctx))}")

    by_intent = defaultdict(list)
    for x in results:
        by_intent[x[0]["intent"]].append(x)
    print("\nBy intent (share handled correctly)")
    for intent in sorted(by_intent):
        xs = by_intent[intent]
        print(f"  {intent:<9} {pct(sum(x[3] == 'ok' for x in xs), len(xs))}")

    groups = defaultdict(list)
    for x in results:
        groups[x[0]["group"]].append(x[3] == "ok")
    print(f"\nPairs fully right: {pct(sum(all(v) for v in groups.values()), len(groups))}"
          "  (every row in the group handled correctly)")

    wrong = [x for x in results if x[3] != "ok"]
    if wrong:
        print("\nMistakes")
        for r, level, score, what in wrong:
            text = r["text"] if len(r["text"]) <= 90 else r["text"][:87] + "..."
            print(f"  {r['id']} [{r['intent']}/{r['label']}] {what:<12} score {score:.2f}  {text}")


if __name__ == "__main__":
    main()
