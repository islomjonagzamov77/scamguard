# ScamGuard test set: labeling guide

This folder holds the **frozen test set**. It measures whether ScamGuard understands what a
message *wants*, not only which words it contains.

**Rules that keep the numbers honest**

1. Rows here are **never used for training** (`train.py` only reads `data/*.csv`, not this folder).
2. Never change a rule *because* a row here fails. Add similar examples to the training data instead,
   and write the fix so it is general. Otherwise the test stops measuring anything.
3. Every row is reviewed by a person. `claude-draft` in `reviewer` means nobody has checked it yet.

The easy way (no CSV editing): a program shows one message at a time.

```bash
python review.py        # review drafts: Enter = agree, 1/2/3 = change the label, q = save and quit
python review.py add    # add a new message, e.g. a real one someone forwarded to you
```

Read every message before you answer. Pressing Enter without reading makes the test worthless.

If you edit the CSV by hand, run this after every labeling session:

```bash
python evaluate.py --check    # finds typos and format mistakes
python evaluate.py            # scores the bot
```

## The one question behind every label

> **If someone forwarded this exact text to ScamGuard, what should the bot answer?**

| label | meaning |
|---|---|
| `scam` | The text is a scam attempt, **or** it quotes one and asks about it ("I got this, is it real?"). |
| `safe` | Nobody is being tricked: warnings, safety advice, stories about a scam that already happened, normal messages. |
| `needs_context` | It could be normal or fraud, and the text alone can't tell ("Pulni shu kartaga yuboring"). The bot should ask a question, not guess. |

## Intent: what the sender wants from the reader

| intent | the sender is… | example |
|---|---|---|
| `request` | asking the reader to **do** something (send, pay, open, tell) | "SMS kodni shu yerga yozib yuboring" |
| `warning` | telling the reader **not** to do something, or giving safety advice | "SMS kodni hech kimga aytmang" |
| `report` | **describing** something that already happened | "Kecha mendan SMS kodimni so'rashdi, bermadim" |
| `quote` | **pasting** another message and asking about it | "Menga shunday xabar keldi: '…'. Bu rostmi?" |
| `info` | just informing (news, an official announcement) | "Grant natijalari 15-oktabrda e'lon qilinadi" |

Tricky cases:

- A warning that **quotes** the scam line ("*'tezda pul tashla'* degan xabar kelsa, qo'ng'iroq qiling")
  is still a `warning` and `safe`. These are the most valuable rows. They are exactly where word-matching fails.
- A report that includes a link or phone number that is **still live** ("shu saytga kirgandim: click-bonus.xyz")
  is labeled `scam`: the reader could still open it. Explain why in `note`.
- If you honestly can't decide, write both views in `note`, and ask a second person. Keep the row.
  Disagreements are data too.

## Columns

| column | what to write |
|---|---|
| `id` | `p001`, `p002`, …, never reused, even if a row is deleted |
| `group` | rows that are variations of the **same scheme** share a group, e.g. `g01-sms-code`. Pairs live in one group. |
| `intent` | `request` / `warning` / `report` / `quote` / `info` |
| `label` | `scam` / `safe` / `needs_context` |
| `script` | `latn` (Uzbek Latin) / `cyrl` (Uzbek Cyrillic) / `mixed` (Uzbek + Russian) / `ru` / `en` |
| `category` | `bank`, `marketplace`, `apk`, `relative`, `grant`, `prize`, `money`, `job`, `other` |
| `text` | the message. **Mask** real card numbers, phone numbers and names: `8600 **** **** 1234`, `+998 ** *** ** 33`, `Aziz → [ism]` |
| `evidence` | the **exact words** from `text` that decide the intent. Copy-paste them; the checker verifies this. |
| `source` | `written` (you wrote it) or `real` (a real message, masked, used with permission) |
| `reviewer` | your name after you check the row |
| `note` | anything unusual; why the label might be argued |

## How to write good pairs

Start from one scam and make small changes that **flip** the meaning. Keep the scary words the same:

| | text | label |
|---|---|---|
| request | Kartangiz bloklandi, **kodni yuboring** | scam |
| warning | "Kartangiz bloklandi, kodni yuboring" desa, **javob bermang** | safe |
| report | Onamga "kartangiz bloklandi" deb yozishdi, **bankka qo'ng'iroq qildik** | safe |

Mix it up. Try Latin and Cyrillic, informal spelling (`ssilka`, `kodni tashla`, `srochna`), Russian words,
long and short messages, and emojis.

## Target for the first version

- **150 rows**: at least 40 groups, each with a `request` and at least one `warning` or `report`
- at least 20 `cyrl` and 20 `mixed` rows
- 10–15 `needs_context` rows
- as many `real` (masked) rows as you can collect with permission. These count the most.

When the file reaches 150 reviewed rows, we freeze it as **v1** and report all results against it.
