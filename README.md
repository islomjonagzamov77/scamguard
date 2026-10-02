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
- 📱 **Looks inside .apk apps**: the bot reads the app's manifest in memory and explains what it could do: read SMS
  codes, control the screen through Accessibility, draw fake login windows over bank apps, hide its icon, install
  more apps. It reads through the file-damaging tricks banking trojans use to crash analysis tools.
  Apps are **never installed, run or saved** (`scamguard/apk.py`)
- 🌍 **Online link checks**: domain age (scam sites are usually days old), plus Google Safe Browsing and VirusTotal
  when free API keys are set. Only the link is sent, without the part after `?`; slow services are skipped
  (`scamguard/reputation.py`)
- 📎 **File checks by name and type**: .exe, double extensions like `photo.jpg.apk`, macro documents, archives. Only .apk files are downloaded (into memory)
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
message ─┬─► intent.py     what does the sender want? (request / warning / story / quote)
         ├─► rules.py      multilingual scam patterns (explainable)
         ├─► links.py      lookalike domains, shorteners, risky TLDs, .apk links, punycode, IPs
         └─► model.py      AI classifier (char n-gram TF-IDF + logistic regression)
                 │
                 ▼
          analyzer.py      offline verdict: score, level, reasons
                 │
                 ├─► reputation.py   online: domain age, Google Safe Browsing, VirusTotal (adds risk only)
.apk file ──────►└─► apk.py          what the app may do, read from its manifest in memory
```

- **The AI model** may raise 🟡 on its own once it is 75% sure. It reads the same words as the rules, so it is not
  counted as independent proof: 🔴 always needs the rules or links on their own. On scam schemes it never saw,
  it raised the share of scams caught from 60% to 72% with no extra false alarms (`data/eval/RESULTS.md`).

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
- **Privacy**: messages are not stored. When a user presses a feedback button, the text is saved with card numbers, phone numbers and emails masked, and no user IDs. `.apk` files are read in memory and never installed, run or saved.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m pytest                   # 217 tests incl. a simulated Telegram chat, real OCR and hostile APK files
python train.py                    # train the model and print the evaluation
python -m scamguard.cli --lang en "Siz iPhone yutib oldingiz! click-bonus.xyz"

cp .env.example .env               # paste your token from @BotFather
python bot.py
```

## Deploy 24/7 on Railway

1. Push the repo to GitHub (`.env` is git-ignored, so your token never leaves your Mac).
2. On [railway.com](https://railway.com): **New Project → Deploy from GitHub repo** → pick this repo.
   Railway builds the `Dockerfile`: it installs dependencies, trains the model and runs the tests. A broken commit never goes live.
3. **Variables:** add `BOT_TOKEN`. Optional: `GOOGLE_SAFE_BROWSING_KEY` and `VIRUSTOTAL_API_KEY` (see `.env.example`).
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
| `scamguard/apk.py` | Static .apk inspection: tolerant zip + binary-XML manifest reader, permissions → plain explanations |
| `scamguard/reputation.py` | Online checks: domain age (RDAP), Google Safe Browsing, VirusTotal; cached, time-limited |
| `collect.py` | Turns real messages, screenshots and bot feedback into masked, labeled data (80% training / 20% holdout) |
| `bot.py` | Telegram bot (aiogram 3) with feedback buttons |
| `train.py` | Cross-validated comparison: rules vs. model vs. full system |
| `data/seed_dataset.csv` | 99 **hand-written example** messages used to bootstrap training |
| `data/synthetic_claude.csv` | 228 training messages **written by Claude (an AI)** to cover more scam schemes (`tools/make_synthetic.py`) |

## Collecting real messages

Everything in `data/seed_*.csv` was written by hand, so the bot learned how *we imagine* scams look.
`collect.py` turns real messages and screenshots into masked, labeled rows in a few seconds:

```bash
python collect.py                      # paste messages one by one
python collect.py screenshots/         # OCR every image in a folder
python collect.py feedback data/feedback_export.csv   # review what bot users sent
python collect.py score                # real-world numbers on messages the bot never trained on
```

- Card numbers, phones, emails and @usernames are masked automatically. Remove people's names yourself (press `e`).
- Duplicates of anything already in any dataset (training or test) are skipped.
- A fixed fingerprint split sends about 80% to `data/real_messages.csv` (training) and 20% to
  `data/eval/real_holdout.csv`, which `train.py` never reads. The holdout gives the honest real-world number.
- For training rows, the bot's verdict is shown **after** you label, so you see where it fails without being biased by it.

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

The training data (180 hand-written messages in `data/seed_*.csv` and 228 AI-written ones in `data/synthetic_claude.csv`)
is imagined, not real, and the rules were tuned on the seed part, so cross-validation scores on it are optimistic.
The numbers that count are on the held-out test half (`data/eval/RESULTS.md`) and, once real messages are collected,
on the real holdout (`python collect.py score`). Two things keep the bot honest:

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
- [x] Tooling: `collect.py` masks, de-duplicates and splits real messages into training and a never-trained holdout
- [ ] Collect 1,000+ real scam messages: scams people forward to you, public Telegram channels that warn about scams, and screenshots from news reports (transcribe and mask them). Add an equal number of normal messages, including hard negatives such as real bank SMS and real OLX buyers
- [ ] Label each message with a category and language, and write a labeling guide
- [ ] Hold out a test set that is never used to write rules
- [ ] Publish the anonymized dataset on Hugging Face with a datasheet

**Phase 3: better AI (weeks 8–14)**
- [x] Make the AI model count: 228 more varied training messages and a threshold chosen with scam types held out.
  Scams caught on unseen schemes: 60% → 72%, false alarms unchanged (`data/eval/RESULTS.md`)
- [ ] Fine-tune `xlm-roberta-base` (or a smaller multilingual model) and compare it with the baseline and the rules
- [ ] Compare against a zero-shot LLM
- [ ] Error analysis: which scam types and languages fail, and why

**Phase 4: deeper security (later)**
- [x] Online link reputation: domain age (RDAP), Google Safe Browsing, VirusTotal (domains and app hashes)
- [x] APK static analysis: SMS-reading, accessibility, overlay, notification-reading, device-admin and hidden-icon
  checks, with a hand-written tolerant parser instead of `androguard` (real trojans corrupt their zip and manifest to
  crash tools). Files are parsed only, **never installed or run**
- [x] Group mode: the bot warns a group chat when someone posts a scam link
- [ ] Check that domain age works for `.uz` sites in production; if RDAP doesn't cover `.uz`, fall back to its WHOIS server
- [ ] Share confirmed fake sites with banks and the Central Bank as a feed (`/api/radar.json` is the start)

## Writing it up

Treat this like a research project, not just an app. Include the problem, the dataset and how it was collected, the three-way comparison (rules / ML / hybrid) with precision and recall on a held-out set, error analysis, ethics and privacy, and real usage numbers. That write-up is what makes it stand out in a portfolio.
