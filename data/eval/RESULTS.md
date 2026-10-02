# Evaluation results log

Every run on the **test** half is recorded here: date, bot version, numbers. The test half is run rarely,
and its individual mistakes are never looked at (see `evaluate.py`).

Set: `intent_pairs.csv`, 150 messages in 53 scheme groups, all reviewed by a person (islomjon).
20 rows were written by Claude while looking at the code (groups g01–g07, dev only). The other 130 were
written by a separate AI that never saw the code. Split by group:

- **dev** (85 messages, 30 groups): mistakes are studied here and the bot is improved
- **test** (65 messages, 23 groups: 25 scam, 35 safe, 5 needs_context): held out

## 2026-09-29: intent layer

| Version | Split | Scams caught | False alarms on safe | Needs-context → 🟡 | Pairs fully right |
|---|---|---|---|---|---|
| v0: rules + links + model (before intent) | test | 15/25 (60%) | 14/35 (40%) | 0/5 | 4/23 (17%) |
| v1: + intent (request / warning / report / quote) | test | 12/25 (48%) | 2/35 (6%) | 0/5 | 9/23 (39%) |
| v2: + dev error analysis (below) | test | 15/25 (60%) | 4/35 (11%) | 2/5 (40%) | 11/23 (48%) |
| v2 | dev | 32/32 (100%) | 0/46 (0%) | 7/7 (100%) | 29/30 (97%) |

**What changed from v1 to v2** (fixes for general causes found on dev, not for individual messages):
- stories told with single quotes ('…' deb) or about other people (onam, jiyanim, коллеге) are recognised as stories
- "don't tell anyone" counts as advice only when it protects a secret (a code, a card); on its own it's a scammer asking for secrecy
- more ways of asking: offers ("1000$ tashlasangiz…"), "I need only $800", converb + auxiliary forms ("tashlab ber/tur/qo'ying"), informal Russian ("отдай деньги")
- safe advice phrased as a request ("IT bo'limga xabar bering") is not an ask
- a request for money with no other scam sign gets 🟡 plus a question ("can't tell"), not 🟢
- the card-number rule only fires for **your** card, not a seller offering to send theirs

**What this shows**
- The intent layer cut false alarms on safe messages from 40% to 11% on unseen schemes, without losing scams (60% → 60%).
- Scam recall on unseen schemes is only 60%, while on the studied half it is 100%. Hand-written rules fit the
  schemes they were written for and generalise poorly to new ones. That gap is the main open problem.
- The test half is small (65 messages), so each message moves a number by 1.5–4 points.

**Next**
- More data, especially real (masked) messages, to grow both halves.
- A learned component that generalises better than rules (fine-tuned multilingual model), compared on the same test half.

## 2026-10-02: the AI model starts to count

Before this change the AI model never changed a verdict: it needed to be 94% sure to raise even a 🟡,
and with 180 hand-written training messages it never was (results with and without it were identical).

**What changed**
- 228 more training messages (`data/synthetic_claude.csv`), written by Claude (an AI) to cover schemes the seed data
  lacked: Telegram "vote for my niece" account theft, "I sent my code to you by mistake", fake loans with an upfront
  fee, jobs abroad, task-based "like and earn" schemes, card rental (money mules), fake utility debts and traffic fines,
  fake exam answers, rentals, tickets, customs fees, sextortion, plus normal look-alikes (real OTP SMS, bank
  notifications, legit OLX buyers, official posts). Marked `synthetic_claude`, never written by looking at the test half.
- The model alone may now raise 🟡 once it is 75% sure. The threshold was picked on the training data with each scam
  *type* held out in turn (about 3-4% of normal messages go above it), not on the test half.
- New safety rule: the model reads the same words as the rules, so it is not independent evidence. It can lift 🟢 to
  🟡, but 🔴 always needs the rules or links on their own (this fixed a courier "SMS code" message on dev that the
  model had pushed to 🔴).

**Model alone** (dev half, only messages where the model counts): AUC 0.73 → 0.92.
On scam types it never saw during training (one category held out at a time): AUC 0.88.

| Version | Split | Scams caught | False alarms on safe | Needs-context → 🟡 | Pairs fully right |
|---|---|---|---|---|---|
| v3 rules + links only | test | 15/25 (60%) | 4/35 (11%) | 2/5 (40%) | 11/23 (48%) |
| v3 rules + links + AI model | test | 18/25 (72%) | 4/35 (11%) | 2/5 (40%) | 12/23 (52%) |
| v3 rules + links + AI model | dev | 32/32 (100%) | 0/46 (0%) | 7/7 (100%) | 30/30 (100%) |

**What this shows**
- The AI model now catches 3 more unseen scams with no extra false alarms. It is the first measured contribution
  of the learned component.
- 3 messages is a small difference on a 65-message test half; treat it as a direction, not a precise number.
- The training data is still imagined (by people and by AI). The honest real-world number will come from
  `python collect.py score` once real messages are collected.
