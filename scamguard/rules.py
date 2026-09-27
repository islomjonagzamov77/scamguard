"""Explainable scam-pattern rules for Uzbek (Latin + Cyrillic), Russian and English.

Uzbek patterns are written in Latin only: Cyrillic Uzbek text is
transliterated before matching (see textnorm.variants). Russian patterns
are written in Cyrillic. Each rule fires at most once per message.

These rules are the baseline the ML model is compared against, and they
supply the "why" explanation shown to users.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .reasons import Reason
from .textnorm import variants


@dataclass(frozen=True)
class Rule:
    name: str
    weight: float
    pattern: re.Pattern
    reason: Reason
    amplifier: bool = False   # only counts when a core scam signal is also present


# Context words that are normal on their own ("urgent", "tax office") and only
# matter together with a real scam signal (asking for codes, money, a fake link...).
AMPLIFIERS = {"urgency", "gov_impersonation"}


def _r(*alternatives: str) -> re.Pattern:
    return re.compile("|".join(f"(?:{a})" for a in alternatives), re.IGNORECASE)


RULES: list[Rule] = [
    Rule("secret_code", 0.6, _r(
        # "(?!ma)" keeps real bank OTPs ("kodni aytmang" = "don't tell the code") from matching
        r"(?:sms[ -]?kod|kod)\S*\s(?:\S+\s){0,3}?(?:yubor|ayt|kirit|jo'nat)(?!ma)",
        r"cvv", r"amal qilish muddat", r"karta(?:ngiz)? (?:raqam|ma'lumot)",
        r"(?:продиктуйте|назовите|отправьте|сообщите|введите) код", r"код из смс",
        r"(?:номер|данные) (?:вашей )?карты",
        r"срок действия карты", r"(?:send|tell|share|give)(?: me)?(?: the| your)? (?:code|otp|pin)",
        r"verification code", r"card (?:number|details)",
    ), Reason(
        "SMS kod, karta raqami yoki CVV so'ralmoqda — hech qachon hech kimga bermang",
        "Asks for an SMS code, card number or CVV — never share these",
        "Просят SMS-код, номер карты или CVV — никогда никому их не сообщайте",
    )),
    Rule("prize", 0.4, _r(
        # "YOU won" + a way to collect it; plain news about winners must not match
        r"yutib oldingiz", r"yutdingiz", r"g'olib bo'ldingiz", r"(?:siz|raqamingiz)\S* [^.\n]{0,25}g'olib",
        r"sovrin(?:ni)? (?:olish|olasiz|oling)", r"sovg'a(?:ni)? (?:olish|oling|yutib)", r"bonus(?:ni)? oling?",
        r"lotereya\S* (?:g'olib|yut)",
        r"вы выиграли", r"ваш выигрыш", r"(?:стали|являетесь) победител", r"(?:получения|получить|забрать) приз",
        r"you(?:'ve| have)? won", r"you(?:'re| are) (?:the|a|our) winner", r"claim your (?:prize|reward|gift)",
        r"(?:won|win) (?:the |a )?lottery",
    ), Reason(
        "Kutilmagan yutuq yoki sovg'a va'da qilinmoqda",
        "Promises an unexpected prize or gift",
        "Обещают неожиданный выигрыш или подарок",
    )),
    Rule("urgency", 0.25, _r(
        r"shoshiling", r"zudlik bilan", r"tezda", r"faqat bugun", r"\d+ (?:soat|daqiqa) ichida",
        r"oxirgi imkoniyat", r"kechiktirmasdan",
        r"срочно", r"немедленно", r"в течение \d+ (?:час|минут)", r"только сегодня", r"последний шанс",
        r"\burgent", r"immediately", r"within \d+ (?:hours?|minutes?)", r"last chance", r"act now",
    ), Reason(
        "Shoshiltirish va vaqt bosimi — firibgarlarning asosiy usuli",
        "Pressure to act fast — a classic scam tactic",
        "Давят срочностью — классический приём мошенников",
    )),
    Rule("blocked_account", 0.4, _r(
        r"karta(?:ngiz)? (?:bloklan|to'xtatil|muzlatil)", r"hisob(?:ingiz)? (?:bloklan|to'xtatil)",
        r"shubhali (?:operatsiya|tranzaksiya)",
        r"карта заблокирован", r"(?:счёт|счет|аккаунт) заблокирован", r"подозрительн\w* (?:операци|транзакци)",
        r"account (?:has been )?(?:suspended|blocked|locked)", r"suspicious (?:activity|transaction)",
    ), Reason(
        "Kartangiz yoki hisobingiz bloklangani haqida qo'rqitish",
        "Scares you that your card or account is blocked",
        "Пугают блокировкой карты или счёта",
    )),
    Rule("bank_impersonation", 0.3, _r(
        r"bank(?:ning)? xavfsizlik xizmati", r"xavfsizlik bo'limi", r"markaziy bank",
        r"служба безопасности (?:банка)?", r"сотрудник банка", r"центральн\w+ банк",
        r"bank security (?:team|department|service)",
    ), Reason(
        "O'zini bank xodimi yoki xavfsizlik xizmati deb tanishtirmoqda — banklar kod so'ramaydi",
        "Claims to be bank security staff — real banks never ask for codes",
        "Представляются сотрудником банка — настоящие банки никогда не спрашивают коды",
    )),
    Rule("advance_fee", 0.35, _r(
        r"oldindan to'lov", r"komissiya(?:ni)? to'la", r"(?:avval|oldin) \S+ (?:so'm|\$) (?:to'la|o'tkaz)",
        r"yetkazib berish (?:uchun )?to'lov", r"sug'urta to'lovi",
        r"предоплат", r"оплатит\w* комисси", r"оплат\w* доставк", r"страховой взнос",
        r"pay (?:a|the) (?:small )?(?:fee|deposit|commission)", r"processing fee",
    
        r"yig'im(?:ni)? (?:to'la|o'tkaz)",
        r"(?:olish|tasdiqlash|rasmiylashtirish|chiqarish|tayyorlash) uchun [^.\n]{0,30}?(?:to'lov qiling|to'lang|to'lash)",
        r"viza uchun [^.\n]{0,25}(?:to'la|o'tkaz|yig'im)",
        r"(?:для получения|для оформления|для подтверждения|для выдачи)[^.\n]{0,40}оплат",
        r"оплатите [\d\s]+(?:сум|\$|долл)",
        r"pay (?:the |a )?(?:\$?\d+ )?(?:release|processing|customs|delivery|registration|visa) fee",
        r"(?:for|with) a \$\d+ (?:deposit|fee)",
    
        r"to'lash uchun (?:havola|link|saytga)",
        r"(?:jo'natma|posilka|посылк)\S*[^.\n]{0,60}(?:to'la|yig'im|оплат)",
    ), Reason(
        "Pul olish uchun avval pul to'lash talab qilinmoqda",
        "Asks you to pay first in order to receive money",
        "Требуют сначала заплатить, чтобы получить деньги",
    )),
    Rule("marketplace", 0.4, _r(
        r"xavfsiz (?:bitim|savdo)", r"pulni (?:o'tkazib|tashlab) (?:berdim|qo'ydim)",
        r"to'lovni (?:havola orqali )?qabul qil", r"(?:olx|dostavka)\S* (?:orqali )?(?:to'lov|pul)",
        r"безопасн\w+ сделк", r"получить (?:оплату|деньги) по ссылке", r"деньги (?:уже )?(?:отправил|перевел)",
        r"receive (?:the )?payment (?:via|through|at) (?:the )?link", r"safe deal",
    ), Reason(
        "OLX/savdo firibgarligi belgisi: 'to'lovni havola orqali qabul qiling'",
        "Marketplace scam pattern: 'receive payment through this link'",
        "Схема мошенничества на OLX: «получите оплату по ссылке»",
    )),
    Rule("easy_money", 0.35, _r(
        # a promise of easy/guaranteed income; plain words like "investment" or "remote job" must not match
        r"kuniga \d[\d\s]*(?:so'm|ming|\$|dollar)", r"oyiga \d+ ?(?:\$|dollar|mln)", r"passiv daromad", r"oson pul",
        r"uyda o'tirib", r"(?:uyda|masofaviy)[^.\n]{0,30}(?:kuniga|oyiga) \d", r"layk bos",
        r"investitsiya qiling", r"(?:kripto|investitsiya)\S*[^.\n]{0,40}(?:foyda|daromad|x2|ikki barobar)",
        r"(?:x2|ikki barobar) qil", r"pul\S*[^.\n]{0,25}(?:x2|ikki barobar)",
        r"пассивн\w+ доход", r"заработ\w* от \d+", r"за лайки", r"(?:крипт|инвестиц)\S*[^.\n]{0,40}(?:прибыл|доход|удво)",
        r"удво\w* (?:ваш|депозит|деньги)",
        r"passive income", r"earn \$?\d+ (?:a|per) day", r"work from home[^.\n]{0,40}\$\d", r"double your",
    
        r"\d+ ?% (?:foyda|daromad)\S* kafolat",
        r"(?:kafolatlangan|гарантир\w*|guaranteed) (?:\d+ ?% )?(?:foyda|прибыл|returns?)",
        r"\d+ ?% (?:прибыли|weekly returns|returns)",
        r"инвестируйте",
        r"invest now",
    ), Reason(
        "Oson va tez daromad va'dasi",
        "Promises easy, fast money",
        "Обещают лёгкие и быстрые деньги",
    )),
    Rule("apk_file", 0.7, _r(r"\.apk\b"), Reason(
        ".apk fayl — bu rasm yoki hujjat emas, telefonga o'rnatiladigan dastur. Ochmang!",
        "An .apk file is an installable Android app, not a photo or document. Don't open it!",
        "Файл .apk — это не фото и не документ, а устанавливаемое приложение. Не открывайте!",
    )),
    Rule("install_app", 0.4, _r(
        r"ilova(?:ni)? (?:yuklab ol|o'rnat)", r"dastur(?:ni)? o'rnat",
        r"rasm(?:lar)?(?:ni)? ko'r", r"foto ko'r",
        r"установите приложение", r"скачайте приложение", r"посмотри(?:те)? фото",
        r"install (?:this|the) app", r"download (?:this|the) app",
    ), Reason(
        "Fayl yoki ilova o'rnatishga undamoqda — .apk orqali telefoningiz o'g'irlanishi mumkin",
        "Pushes you to install a file or app — .apk files can hijack your phone",
        "Уговаривают установить файл или приложение — через .apk могут взломать телефон",
    )),
    Rule("relative_in_trouble", 0.35, _r(
        r"yangi raqam(?:im|dan)", r"bu men,? (?:ona|dada|aka|opa)", r"(?:ona|dada)jon,? pul",
        r"muammoga (?:qoldim|tushdim)", r"hech kimga aytma",
        r"(?:мама|папа),? это я", r"мой новый номер", r"попал в (?:беду|аварию)", r"никому не говори",
        r"(?:mom|dad),? it'?s me", r"my new number", r"don'?t tell anyone",
    
        r"telefonim (?:buzildi|yo'qoldi|o'g'irlandi)",
        r"(?:do'stimning|boshqa (?:odamning )?)raqam(?:i|idan)",
        r"телефон (?:сломался|разбился|потерял)",
        r"с (?:чужого|другого) номера",
    ), Reason(
        "Qarindosh nomidan pul so'rash — avval o'sha odamga eski raqamiga qo'ng'iroq qiling",
        "Someone posing as a relative asking for money — call them on their old number",
        "Просят деньги от имени родственника — позвоните ему на старый номер",
    )),
    Rule("threat_payment", 0.45, _r(
        r"jarima(?:ni)? (?:darhol |tezda |zudlik bilan )?to'la", r"to'lamasangiz", r"sud ishi ochiladi", r"hibsga olinasiz",
        r"(?:hisob|karta)(?:ingiz)? (?:musodara|arest|muzlatiladi)",
        r"оплатите штраф", r"иначе (?:арест|блокировк|суд|уголовн)", r"возбуждено (?:уголовное|дело)", r"арест счет",
        r"pay the fine", r"(?:or|otherwise) (?:your account|you) will be (?:seized|arrested|blocked|frozen)", r"legal action",
    ), Reason(
        "Tahdid va pul talabi («to'lamasangiz — sud/arest»). Davlat idoralari messenjer orqali bunday talab qilmaydi",
        "Threatens you and demands payment (\"pay or face court/arrest\"). Real authorities don't do this via messengers",
        "Угрожают и требуют оплату («заплатите, иначе суд/арест»). Госорганы так не делают через мессенджеры",
    )),
    Rule("fake_admission", 0.5, _r(
        r"(?:kirish|qabul|o'qishga)\S*\s(?:\S+\s){0,2}kafolatla", r"komissiya(?:si)? a'zosiman",
        r"гарантирую поступление", r"я (?:—\s)?член (?:приёмной |приемной )?комиссии",
        r"guarantee (?:your )?(?:acceptance|admission)", r"i'?m (?:on|a member of) the admission committee",
    ), Reason(
        "Pul evaziga o'qishga kirish yoki grantni «kafolatlash». Haqiqiy tanlovlarda bunday bo'lmaydi",
        "Promises guaranteed admission or a grant for money. Real selection processes never work like this",
        "Обещают «гарантированное» поступление или грант за деньги. Так не бывает в настоящих конкурсах",
    )),
    Rule("gov_impersonation", 0.25, _r(
        r"soliq qo'mitasi", r"davlat xizmatlari", r"kompensatsiya", r"subsidiya", r"jarima(?:ni)? to'la",
        r"налогов\w+ (?:комитет|служб)", r"компенсаци", r"штраф",
        r"tax refund", r"government (?:grant|compensation)",
    ), Reason(
        "Davlat idorasi, kompensatsiya yoki jarima nomidan murojaat",
        "Uses a government body, compensation or fine as bait",
        "Прикрываются госорганом, компенсацией или штрафом",
    )),
]


RULES = [Rule(r.name, r.weight, r.pattern, r.reason, r.name in AMPLIFIERS) for r in RULES]


def match_rules(text: str) -> list[Rule]:
    """All rules that match (amplifiers included; the analyzer decides whether they count)."""
    texts = variants(text)
    return [rule for rule in RULES if any(rule.pattern.search(t) for t in texts)]
