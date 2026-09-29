# ScamGuard 🛡️

**An explainable scam detector for Uzbekistan, delivered as a Telegram bot.**
It understands Uzbek (Latin and Cyrillic), Russian and English.

Users forward a suspicious message, link or file. ScamGuard replies with a verdict (🟢 safe / 🟡 suspicious / 🔴 dangerous) and says *why*, for example "this domain imitates click.uz" or "real banks never ask for SMS codes".

## Why this project exists

Most scams in Uzbekistan reach people through Telegram and SMS: fake prizes, fake "bank security" calls, OLX "receive your payment here" links, and `.apk` files disguised as photos that steal SMS codes. Existing scam filters are built for English. There is almost no public tooling or data for Uzbek.

## Bot features

- 🌐 **3 languages**: Uzbek, Russian, English. Auto-detected, switchable with /lang
- 🔍 **Explained verdicts** for messages, links (including links hidden behind text) and files
- 📷 **Reads screenshots**: OCR in Uzbek (Latin + Cyrillic), Russian and English, with adaptive thresholding so light- and dark-mode chat screenshots both work. Images are processed in memory only
- 🚩 **Community blocklist**: users report scam sites, phone numbers and Telegram accounts. After 2 *different* people report the same one, everyone who meets it is warned. The threshold protects innocent people from a single false report. Numbers and accounts are stored only as salted SHA-256 fingerprints
- 💬 **Inline mode**: type `@scamguard_uzbbot <link>` in *any* chat to get a verdict card; tapping it posts the verdict, signed by the bot (a built-in growth loop)
- 📎 **File checks by name and type only**: .apk/.exe, double extensions like `photo.jpg.apk`, macro documents, archives. Files are never downloaded
- 🆘 **"I got scammed" guide**: block the card, secure Telegram, keep evidence, call 102
- 📚 **Scam-types guide**: 8 common Uzbek scams with red flags
- 👥 **Group protection**: stays silent on normal messages and warns only on dangerous ones; `/check` as a reply scans any message
- 📊 **Anonymous statistics**: no message text or Telegram IDs are stored (salted-hash fingerprints only)
- ✅❌ **Opt-in feedback** saved masked to SQLite; export it for retraining with `Storage().export_feedback()`
- 🛡 **Rate limiting** and a global error handler
- 🪪 **Auto profile**: description, short description and command menus in 3 languages are set on startup
- 🎨 `assets/`: logo and welcome picture (SVG sources + PNG)

## 🌐 Scam Radar (public website)

The bot also serves a public page that shows what ScamGuard is catching across Uzbekistan:
a 30-day trend, the most common scam types, and recently detected fake sites.
It's in Uzbek, Russian and English, with light and dark themes, and it works on phones.

- **Privacy by design:** only aggregated counts, scam categories and fake-site domains are published. Message text,
  users, phone numbers and Telegram accounts are never published (enforced by `tests/test_radar.py`).
- Fake sites are **defanged** (`el-yurt-grant[.]xyz`), so nobody opens them by accident.
- Total counters appear only after 100 checks (`SCAMGUARD_SHOW_TOTALS_FROM`).
- Security: a strict Content-Security-Policy (the inline script is pinned by its SHA-256 hash), no third-party scripts
  or fonts, `nosniff`, and only Telegram may embed the page (`frame-ancestors`).
- Endpoints: `/` (page), `/api/radar.json` (data, cached 30s), `/healthz`.
- On Railway: **Settings → Networking → Generate Domain**. The web server listens on `$PORT` (default 8080).

## How it works

```
message ─┬─► rules.py      multilingual scam patterns (explainable)
         ├─► links.py      lookalike domains, shorteners, risky TLDs, .apk links, punycode, IPs
         └─► model.py      ML classifier (char n-gram TF-IDF + logistic regression)
                 │
                 ▼
          analyzer.py      noisy-OR combination → score, level, reasons
```

- **Intent first** (`intent.py`): before scoring, the bot decides what the sender wants from the reader.
  It can be a **request** ("SMS kodni yuboring"), a **warning** ("SMS kodni hech kimga aytmang"), a **report**
  of something that already happened ("kecha mendan kodimni so'rashdi, bermadim") or a **quote** ("menga shunday xabar keldi… rostmi?").
  Warnings and stories only *mention* scam words, so they aren't accused of asking for anything, and every
  verdict quotes the sentence it is based on. A real ask always wins, even when scammers add warning words, and
  informal secrecy ("никому не говори", "don't tell anyone") is treated as a red flag, not as advice.
- **Cyrillic Uzbek** is transliterated to Latin first, so one rule set covers both scripts.
- **Lookalike detection** catches `c1ick.uz`, `paymе.uz` (with a Cyrillic "е"), `0lx-uz.com`, and `click-uz-bonus.xyz`, using homoglyph folding and edit distance against a list of official domains.
- **Hidden links**: the bot also checks URLs hidden behind Telegram text links and inline buttons.
- **The model only adds evidence.** It can raise a score but never overrules a rule, and every verdict stays explainable.
- **Privacy**: messages are not stored. When a user presses a feedback button, the text is saved with card numbers, phone numbers and emails masked, and no user IDs. `.apk` files are never downloaded.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m pytest                   # 167 tests incl. a simulated Telegram chat and real OCR
python train.py                    # train the model and print the evaluation
python -m scamguard.cli --lang en "Siz iPhone yutib oldingiz! click-bonus.xyz"

cp .env.example .env               # paste your token from @BotFather
python bot.py
```

## Deploy 24/7 on Railway

1. Push the repo to GitHub (`.env` is git-ignored, so your token never leaves your Mac).
2. On [railway.com](https://railway.com): **New Project → Deploy from GitHub repo** → pick this repo.
   Railway builds the `Dockerfile`: it installs dependencies, trains the model and runs the tests. A broken commit never goes live.
3. **Variables:** add `BOT_TOKEN`.
4. **Volume:** add one mounted at `/data`, so stats, language settings and feedback survive redeploys.
5. Stop any local copy of the bot. Telegram allows only one running instance per token.

Every `git push` then redeploys automatically.

## Project layout

| Path | What it is |
|---|---|
| `scamguard/rules.py` | Scam patterns: secret codes, prizes, urgency, blocked account, bank or government impersonation, advance fees, OLX scams, easy money, apk, "relative in trouble" |
| `scamguard/links.py` | Offline URL risk analysis |
| `scamguard/textnorm.py` | Apostrophe unification, Cyrillic→Latin conversion, private-data masking |
| `scamguard/model.py` | Loads the trained classifier |
| `scamguard/analyzer.py` | Combines everything into a `Verdict` |
| `bot.py` | Telegram bot (aiogram 3) with feedback buttons |
| `train.py` | Cross-validated comparison: rules vs. model vs. full system |
| `data/seed_dataset.csv` | 99 **hand-written example** messages used to bootstrap training |

## Evaluation set

`data/eval/` is a separate, human-reviewed test set of **paired examples**: the same scam wording as a request,
a warning and a report. The labels ask one question: *what should the bot answer if this text were forwarded to it?*
It is never used for training or for tuning rules. See `data/eval/LABELING_GUIDE.md`.

```bash
python evaluate.py --check   # validate the file
python evaluate.py --split dev    # the half we study: every mistake is shown
python evaluate.py --split test   # the held-out half: totals only (results in data/eval/RESULTS.md)
```

## ⚠️ Honest note on the current numbers

The training data in `data/seed_*.csv` (180 messages) was written by hand to bootstrap the project, and the rules were
tuned on it, so cross-validation scores on it are optimistic. Two things keep the bot honest:

- **Safety policy** (`analyzer.py`): the AI model only adds risk when it is confident, can never make a message
  "dangerous" on its own, and a safe verdict never shows risk reasons. Every warning has a concrete reason.
- **Regression set** (`tests/golden_set.csv`): realistic messages, including real false alarms reported by users
  (e.g. an official El-yurt umidi channel post) and legitimate look-alikes of scam wording. It runs on every deploy.

Real metrics will come from real users' ✅/❌ feedback and 🚩 reports (see the roadmap).

## Roadmap

**Phase 1: working bot (weeks 1–4)** ✅ scaffolded
- [x] Rules, link analysis, baseline model, bot, tests
- [ ] Deploy the bot (Railway, Render or a small VPS) and share it with friends and family
- [ ] Collect feedback through the buttons

**Phase 2: the dataset, your main contribution (weeks 4–10)**
- [ ] Collect 1,000+ real scam messages: scams people forward to you, public Telegram channels that warn about scams, and screenshots from news reports (transcribe and mask them). Add an equal number of normal messages, including hard negatives such as real bank SMS and real OLX buyers
- [ ] Label each message with a category and language, and write a labeling guide
- [ ] Hold out a test set that is never used to write rules
- [ ] Publish the anonymized dataset on Hugging Face with a datasheet

**Phase 3: better AI (weeks 8–14)**
- [ ] Fine-tune `xlm-roberta-base` (or a smaller multilingual model) and compare it with the baseline and the rules
- [ ] Compare against a zero-shot LLM
- [ ] Error analysis: which scam types and languages fail, and why

**Phase 4: deeper security (later)**
- [ ] Online link reputation: Google Safe Browsing, VirusTotal, domain age from WHOIS
- [ ] APK static analysis with `androguard`: flag SMS-reading, accessibility and overlay permissions. Parse the file only. **Never install or run samples**, and keep them in an isolated environment
- [ ] Group mode: the bot warns a group chat when someone posts a scam link

## Writing it up

Treat this like a research project, not just an app. Include the problem, the dataset and how it was collected, the three-way comparison (rules / ML / hybrid) with precision and recall on a held-out set, error analysis, ethics and privacy, and real usage numbers. That write-up is what makes it stand out in a portfolio.
