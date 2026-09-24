"""Check a message from the terminal.

    python -m scamguard.cli "Siz sovg'a yutib oldingiz! click-bonus.xyz"
    python -m scamguard.cli --lang en --json "Вы выиграли приз"
    echo "some text" | python -m scamguard.cli
"""

import argparse
import json
import sys

from .analyzer import analyze

ICONS = {"safe": "🟢", "suspicious": "🟡", "dangerous": "🔴"}


def main() -> None:
    ap = argparse.ArgumentParser(description="ScamGuard message checker")
    ap.add_argument("text", nargs="?", help="message to check (reads stdin if omitted)")
    ap.add_argument("--lang", choices=["uz", "en"], default="en")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-model", action="store_true", help="rules and links only")
    args = ap.parse_args()

    text = args.text if args.text is not None else sys.stdin.read()
    verdict = analyze(text, use_model=not args.no_model)
    if args.json:
        print(json.dumps(verdict.to_dict(args.lang), ensure_ascii=False, indent=2))
        return
    print(f"{ICONS[verdict.level.value]} {verdict.level.value.upper()}  (score {verdict.score:.2f})")
    for reason in verdict.reasons:
        print(f"  • {reason.text(args.lang)}")


if __name__ == "__main__":
    main()
