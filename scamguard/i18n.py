"""All user-facing bot texts in Uzbek, Russian and English.

Keep formatting HTML-safe: only <b>, <i>, <code> tags are used.
"""

from __future__ import annotations

LANGS = ("uz", "ru", "en")
LANG_NAMES = {"uz": "🇺🇿 O'zbekcha", "ru": "🇷🇺 Русский", "en": "🇬🇧 English"}

T: dict[str, dict[str, str]] = {
    # ---------- onboarding ----------
    "choose_lang": {
        "uz": "🌐 Tilni tanlang:", "ru": "🌐 Выберите язык:", "en": "🌐 Choose your language:",
    },
    "lang_set": {
        "uz": "✅ Til: O'zbekcha", "ru": "✅ Язык: русский", "en": "✅ Language: English",
    },
    "welcome": {
        "uz": "👋 Salom, <b>{name}</b>! Men <b>ScamGuard</b> — firibgarlikni aniqlovchi AI botman.\n\n"
              "📩 Menga shubhali <b>xabar, havola yoki faylni forward qiling</b> — bir soniyada tekshirib, "
              "nima uchun xavfli ekanini tushuntiraman.\n\n"
              "Pastdagi menyudan foydalaning 👇",
        "ru": "👋 Привет, <b>{name}</b>! Я <b>ScamGuard</b> — AI-бот для распознавания мошенничества.\n\n"
              "📩 <b>Перешлите мне подозрительное сообщение, ссылку или файл</b> — я проверю его за секунду "
              "и объясню, чем он опасен.\n\n"
              "Пользуйтесь меню ниже 👇",
        "en": "👋 Hi, <b>{name}</b>! I'm <b>ScamGuard</b>, an AI bot that detects scams.\n\n"
              "📩 <b>Forward me any suspicious message, link or file</b>. I'll check it in a second "
              "and explain why it's dangerous.\n\n"
              "Use the menu below 👇",
    },
    # ---------- menu buttons ----------
    "btn_check": {"uz": "🔍 Qanday tekshiraman?", "ru": "🔍 Как проверить?", "en": "🔍 How to check"},
    "btn_sos": {"uz": "🆘 Aldandim — nima qilay?", "ru": "🆘 Меня обманули", "en": "🆘 I got scammed"},
    "btn_types": {"uz": "📚 Firibgarlik turlari", "ru": "📚 Виды мошенничества", "en": "📚 Scam types"},
    "btn_stats": {"uz": "📊 Statistika", "ru": "📊 Статистика", "en": "📊 Statistics"},
    "btn_lang": {"uz": "🌐 Til", "ru": "🌐 Язык", "en": "🌐 Language"},
    "btn_share": {"uz": "📤 Do'stlarga ulashish", "ru": "📤 Поделиться", "en": "📤 Share"},
    # ---------- how to check ----------
    "how_to_check": {
        "uz": "🔍 <b>Qanday tekshiraman?</b>\n\n"
              "1️⃣ Shubhali xabarni bosib turing → <b>Forward</b> → ScamGuard'ni tanlang\n"
              "2️⃣ Yoki matn / havolani nusxalab shu yerga yuboring\n"
              "📷 Yoki <b>skrinshot</b> yuboring — rasmdagi matnni o'qiyman\n"
              "3️⃣ Fayllarni ham yuborishingiz mumkin — men ularni <b>ochmayman</b>, faqat nomi va turini tekshiraman\n\n"
              "Men tekshiraman:\n"
              "• 💬 matndagi firibgarlik belgilari (o'zbek lotin/kirill, rus, ingliz)\n"
              "• 🔗 soxta saytlar (<code>c1ick.uz</code>, <code>paymе-bonus.xyz</code>…)\n"
              "• 🙈 matn orqasiga yashirilgan havolalar\n"
              "• 📎 xavfli fayllar (.apk, .exe, <code>rasm.jpg.apk</code>)\n"
              "• 🤖 AI model bahosi\n\n"
              "🚩 Firibgarni ko'rsangiz — «Firibgar deb belgilash» tugmasini bosing. 2 kishi belgilasa, bot hammani ogohlantiradi.\n\n"
              "👥 Guruhda: xabarga javoban /check yoki /report yozing.",
        "ru": "🔍 <b>Как проверить?</b>\n\n"
              "1️⃣ Зажмите подозрительное сообщение → <b>Переслать</b> → выберите ScamGuard\n"
              "2️⃣ Или скопируйте текст / ссылку и отправьте сюда\n"
              "📷 Или пришлите <b>скриншот</b> — я прочитаю текст на картинке\n"
              "3️⃣ Можно присылать и файлы — я их <b>не открываю</b>, проверяю только имя и тип\n\n"
              "Я проверяю:\n"
              "• 💬 признаки мошенничества в тексте (узбекский, русский, английский)\n"
              "• 🔗 поддельные сайты (<code>c1ick.uz</code>, <code>paymе-bonus.xyz</code>…)\n"
              "• 🙈 ссылки, спрятанные за текстом\n"
              "• 📎 опасные файлы (.apk, .exe, <code>foto.jpg.apk</code>)\n"
              "• 🤖 оценку AI-модели\n\n"
              "🚩 Увидели мошенника — нажмите «Пожаловаться». Когда отметят 2 человека, бот будет предупреждать всех.\n\n"
              "👥 В группе: ответьте на сообщение командой /check или /report.",
        "en": "🔍 <b>How to check</b>\n\n"
              "1️⃣ Long-press the suspicious message → <b>Forward</b> → choose ScamGuard\n"
              "2️⃣ Or copy the text / link and send it here\n"
              "📷 Or send a <b>screenshot</b>. I'll read the text in the image\n"
              "3️⃣ You can send files too. I <b>never open them</b>, I only check the name and type\n\n"
              "I check:\n"
              "• 💬 scam patterns in the text (Uzbek, Russian, English)\n"
              "• 🔗 fake websites (<code>c1ick.uz</code>, <code>paymе-bonus.xyz</code>…)\n"
              "• 🙈 links hidden behind text\n"
              "• 📎 dangerous files (.apk, .exe, <code>photo.jpg.apk</code>)\n"
              "• 🤖 the AI model's score\n\n"
              "🚩 Spotted a scammer? Tap \"Report as scam\". Once 2 people report it, the bot warns everyone.\n\n"
              "👥 In a group: reply to a message with /check or /report.",
    },
    # ---------- verdicts ----------
    "v_safe": {"uz": "🟢 <b>Xavf belgilari topilmadi</b>", "ru": "🟢 <b>Признаков угрозы не найдено</b>",
               "en": "🟢 <b>No scam signs found</b>"},
    "v_suspicious": {"uz": "🟡 <b>Shubhali!</b> Ehtiyot bo'ling", "ru": "🟡 <b>Подозрительно!</b> Будьте осторожны",
                     "en": "🟡 <b>Suspicious!</b> Be careful"},
    "v_dangerous": {"uz": "🔴 <b>Xavfli! Bu firibgarlikka juda o'xshaydi</b>",
                    "ru": "🔴 <b>Опасно! Очень похоже на мошенничество</b>",
                    "en": "🔴 <b>Dangerous! This looks like a scam</b>"},
    "risk": {"uz": "Xavf darajasi", "ru": "Уровень риска", "en": "Risk level"},
    "source": {"uz": "Manba", "ru": "Источник", "en": "Source"},
    "file": {"uz": "Fayl", "ru": "Файл", "en": "File"},
    "why": {"uz": "Nima uchun:", "ru": "Почему:", "en": "Why:"},
    "a_safe": {
        "uz": "Baribir: hech kimga SMS kod, karta raqami yoki CVV bermang.",
        "ru": "И всё же: никому не сообщайте SMS-коды, номер карты и CVV.",
        "en": "Still: never share SMS codes, card numbers or CVV with anyone.",
    },
    "a_suspicious": {
        "uz": "Havolani ochmang va javob bermang. Tashkilotning rasmiy raqamiga o'zingiz qo'ng'iroq qilib tekshiring.",
        "ru": "Не открывайте ссылку и не отвечайте. Сами позвоните на официальный номер организации и уточните.",
        "en": "Don't open the link or reply. Call the organization's official number yourself to verify.",
    },
    "a_dangerous": {
        "uz": "Havolani ochmang, fayl o'rnatmang, pul o'tkazmang va hech qanday kod aytmang. Yuboruvchini bloklang.",
        "ru": "Не открывайте ссылку, не устанавливайте файлы, не переводите деньги и не называйте коды. Заблокируйте отправителя.",
        "en": "Don't open links, install files, send money or share any code. Block the sender.",
    },
    "fa_safe": {
        "uz": "Bu turdagi fayllar odatda o'z-o'zidan zarar qilmaydi. Lekin ichidagi havolalarni bosmang va kod, karta yoki parol kiritmang.",
        "ru": "Такие файлы обычно безопасны сами по себе. Но не переходите по ссылкам внутри и не вводите коды, карты и пароли.",
        "en": "Files like this are usually harmless by themselves. But don't click links inside or enter codes, cards or passwords.",
    },
    "fa_suspicious": {
        "uz": "Yuboruvchini tanimasangiz, ochmang. Tanisangiz ham, unga qo'ng'iroq qilib so'rang.",
        "ru": "Не открывайте, если не знаете отправителя. Даже если знаете — позвоните и уточните.",
        "en": "Don't open it if you don't know the sender. Even if you do, call and ask first.",
    },
    "fa_dangerous": {
        "uz": "Ochmang va o'rnatmang. Agar o'rnatib qo'ygan bo'lsangiz — 🆘 tugmasini bosing.",
        "ru": "Не открывайте и не устанавливайте. Если уже установили — нажмите 🆘.",
        "en": "Don't open or install it. If you already did, press 🆘.",
    },
    "fb_ok": {"uz": "✅ To'g'ri", "ru": "✅ Верно", "en": "✅ Correct"},
    "fb_no": {"uz": "❌ Xato", "ru": "❌ Ошибка", "en": "❌ Wrong"},
    "fb_thanks": {"uz": "Rahmat! Bu modelni yaxshilaydi 🙏", "ru": "Спасибо! Это улучшит модель 🙏",
                  "en": "Thanks! This improves the model 🙏"},
    "fb_expired": {"uz": "Bu xabar eskirgan.", "ru": "Это сообщение устарело.", "en": "This message has expired."},
    "empty": {"uz": "Tekshirish uchun matn, havola yoki fayl yuboring.",
              "ru": "Отправьте текст, ссылку или файл для проверки.",
              "en": "Send a text, link or file to check."},
    "other_media": {
        "uz": "Men matn, havola, fayl va skrinshotlarni tekshiraman. Ovozli xabar va videolarni hozircha tekshira olmayman — "
              "shubhali matnni yozib yuboring.",
        "ru": "Я проверяю текст, ссылки, файлы и скриншоты. Голосовые и видео пока не проверяю — напишите подозрительный текст.",
        "en": "I check text, links, files and screenshots. I can't check voice messages or videos yet, so type out the suspicious text.",
    },
    "rate_limited": {"uz": "⏳ Juda tez! Bir daqiqadan so'ng qayta urinib ko'ring.",
                     "ru": "⏳ Слишком быстро! Попробуйте через минуту.",
                     "en": "⏳ Too fast! Try again in a minute."},
    # ---------- SOS ----------
    "sos": {
        "uz": "🆘 <b>Aldandim — endi nima qilaman?</b>\n\n"
              "Tinchlaning va shu tartibda harakat qiling:\n\n"
              "1️⃣ <b>Kartani darhol bloklang.</b> Karta orqasidagi bank raqamiga qo'ng'iroq qiling yoki bank ilovasida kartani muzlating.\n\n"
              "2️⃣ <b>.apk o'rnatgan bo'lsangiz:</b> telefonni parvoz rejimiga o'tkazing, ilovani o'chiring, bank ilovasi va Telegram parollarini boshqa qurilmadan almashtiring.\n\n"
              "3️⃣ <b>Telegram'ni himoyalang:</b> Sozlamalar → Qurilmalar → «Boshqa seanslarni yakunlash». "
              "So'ng Sozlamalar → Maxfiylik → «Ikki bosqichli tasdiqlash»ni yoqing.\n\n"
              "4️⃣ <b>Dalillarni saqlang:</b> yozishmalar, raqamlar, havolalar va to'lov cheklarini skrinshot qiling.\n\n"
              "5️⃣ <b>Militsiyaga murojaat qiling:</b> 📞 <b>102</b>. Tezroq murojaat qilsangiz, pulni qaytarish imkoniyati shuncha yuqori.\n\n"
              "6️⃣ <b>Yaqinlaringizni ogohlantiring</b> — firibgar ularga sizning nomingizdan yozishi mumkin.\n\n"
              "❤️ Aldanish — uyat emas. Firibgarlar professional ishlaydi.",
        "ru": "🆘 <b>Меня обманули — что делать?</b>\n\n"
              "Сохраняйте спокойствие и действуйте по порядку:\n\n"
              "1️⃣ <b>Сразу заблокируйте карту.</b> Позвоните по номеру банка на обороте карты или заморозьте её в приложении банка.\n\n"
              "2️⃣ <b>Если установили .apk:</b> включите режим полёта, удалите приложение, смените пароли от банка и Telegram с другого устройства.\n\n"
              "3️⃣ <b>Защитите Telegram:</b> Настройки → Устройства → «Завершить другие сеансы». "
              "Затем Настройки → Конфиденциальность → включите «Двухэтапную аутентификацию».\n\n"
              "4️⃣ <b>Сохраните доказательства:</b> скриншоты переписки, номера, ссылки и чеки переводов.\n\n"
              "5️⃣ <b>Обратитесь в милицию:</b> 📞 <b>102</b>. Чем раньше, тем выше шанс вернуть деньги.\n\n"
              "6️⃣ <b>Предупредите близких</b> — мошенник может писать им от вашего имени.\n\n"
              "❤️ Быть обманутым не стыдно. Мошенники работают профессионально.",
        "en": "🆘 <b>I got scammed. What now?</b>\n\n"
              "Stay calm and act in this order:\n\n"
              "1️⃣ <b>Block your card now.</b> Call the bank number on the back of the card, or freeze it in your bank app.\n\n"
              "2️⃣ <b>If you installed an .apk:</b> turn on airplane mode, delete the app, and change your bank and Telegram passwords from another device.\n\n"
              "3️⃣ <b>Secure Telegram:</b> Settings → Devices → \"Terminate all other sessions\". "
              "Then Settings → Privacy → turn on \"Two-Step Verification\".\n\n"
              "4️⃣ <b>Keep evidence:</b> screenshot the chat, phone numbers, links and payment receipts.\n\n"
              "5️⃣ <b>Report to the police:</b> 📞 <b>102</b>. The sooner you report, the better the chance of getting money back.\n\n"
              "6️⃣ <b>Warn your contacts</b>. The scammer may message them pretending to be you.\n\n"
              "❤️ Getting scammed is nothing to be ashamed of. Scammers are professionals.",
    },
    # ---------- scam types ----------
    "types_title": {"uz": "📚 <b>Firibgarlik turlari</b>\n\nBilish uchun birini tanlang:",
                    "ru": "📚 <b>Виды мошенничества</b>\n\nВыберите, чтобы узнать подробнее:",
                    "en": "📚 <b>Scam types</b>\n\nPick one to learn more:"},
    "back": {"uz": "⬅️ Orqaga", "ru": "⬅️ Назад", "en": "⬅️ Back"},
    # ---------- stats ----------
    "stats": {
        "uz": "📊 <b>ScamGuard statistikasi</b>\n\n"
              "👥 Foydalanuvchilar: <b>{users}</b>\n"
              "🔍 Jami tekshiruvlar: <b>{checks}</b>\n"
              "🔴 Xavfli topildi: <b>{dangerous}</b>\n"
              "🟡 Shubhali: <b>{suspicious}</b>\n"
              "📅 Bugun tekshirildi: <b>{today}</b>\n"
              "🚩 Jamoa bloklagan: <b>{blocked}</b>\n\n"
              "<i>Xabarlaringiz saqlanmaydi — faqat anonim sonlar.</i>",
        "ru": "📊 <b>Статистика ScamGuard</b>\n\n"
              "👥 Пользователей: <b>{users}</b>\n"
              "🔍 Всего проверок: <b>{checks}</b>\n"
              "🔴 Найдено опасных: <b>{dangerous}</b>\n"
              "🟡 Подозрительных: <b>{suspicious}</b>\n"
              "📅 Проверок сегодня: <b>{today}</b>\n"
              "🚩 Заблокировано сообществом: <b>{blocked}</b>\n\n"
              "<i>Сообщения не сохраняются — только анонимные счётчики.</i>",
        "en": "📊 <b>ScamGuard statistics</b>\n\n"
              "👥 Users: <b>{users}</b>\n"
              "🔍 Total checks: <b>{checks}</b>\n"
              "🔴 Dangerous found: <b>{dangerous}</b>\n"
              "🟡 Suspicious: <b>{suspicious}</b>\n"
              "📅 Checked today: <b>{today}</b>\n"
              "🚩 Blocked by the community: <b>{blocked}</b>\n\n"
              "<i>Messages aren't stored, only anonymous counts.</i>",
    },
    # ---------- share ----------
    "share": {
        "uz": "📤 Yaqinlaringizni firibgarlardan himoya qiling! Ayniqsa ota-onangiz va buvi-bobolaringizga ulashing 👇",
        "ru": "📤 Защитите близких от мошенников! Особенно поделитесь с родителями и бабушками-дедушками 👇",
        "en": "📤 Protect your family from scammers! Share it especially with parents and grandparents 👇",
    },
    "share_btn": {"uz": "📤 Ulashish", "ru": "📤 Поделиться", "en": "📤 Share"},
    "share_msg": {
        "uz": "🛡 ScamGuard — shubhali xabar, havola yoki faylni forward qiling va firibgarlikmi yo'qmi bilib oling. Bepul!",
        "ru": "🛡 ScamGuard — перешлите подозрительное сообщение, ссылку или файл и узнайте, мошенничество ли это. Бесплатно!",
        "en": "🛡 ScamGuard: forward any suspicious message, link or file and find out if it's a scam. Free!",
    },
    # ---------- privacy ----------
    "privacy": {
        "uz": "🔒 <b>Maxfiylik</b>\n\n"
              "• Tekshirilgan xabarlar <b>saqlanmaydi</b>.\n"
              "• Faqat «✅/❌» tugmasini bossangiz, xabar matni modelni yaxshilash uchun saqlanadi — "
              "karta, telefon raqamlari va emaillar oldindan o'chiriladi.\n"
              "• Ism va Telegram ID saqlanmaydi (til sozlamasi uchun faqat shifrlangan belgi).\n"
              "• Fayllar yuklab olinmaydi va ochilmaydi. Skrinshotlar faqat xotirada o'qiladi va saqlanmaydi.\n"
              "• 🚩 Belgilangan raqam va akkauntlar faqat shifrlangan belgi sifatida saqlanadi.",
        "ru": "🔒 <b>Конфиденциальность</b>\n\n"
              "• Проверенные сообщения <b>не сохраняются</b>.\n"
              "• Только если вы нажмёте «✅/❌», текст сохраняется для улучшения модели — "
              "номера карт, телефонов и email предварительно удаляются.\n"
              "• Имя и Telegram ID не хранятся (для языка — только зашифрованный отпечаток).\n"
              "• Файлы не скачиваются и не открываются. Скриншоты читаются только в памяти и не сохраняются.\n"
              "• 🚩 Отмеченные номера и аккаунты хранятся только в виде зашифрованных отпечатков.",
        "en": "🔒 <b>Privacy</b>\n\n"
              "• Checked messages are <b>not stored</b>.\n"
              "• Only when you press ✅/❌ is the text saved to improve the model, "
              "with card numbers, phone numbers and emails removed first.\n"
              "• Names and Telegram IDs are not stored (only a hashed fingerprint for your language setting).\n"
              "• Files are never downloaded or opened. Screenshots are read in memory only and never saved.\n"
              "• 🚩 Reported numbers and accounts are stored only as hashed fingerprints.",
    },
    # ---------- groups ----------
    "group_hello": {
        "uz": "🛡 Salom! Men bu guruhni firibgarlardan himoya qilaman.\n\n"
              "Xavfli havola yoki fayl yuborilsa, ogohlantiraman. Har bir xabarni ko'rishim uchun meni "
              "<b>admin</b> qiling. Istalgan xabarga javoban /check yozib tekshirish ham mumkin.",
        "ru": "🛡 Привет! Я защищаю эту группу от мошенников.\n\n"
              "Предупрежу, если кто-то отправит опасную ссылку или файл. Чтобы я видел все сообщения, "
              "сделайте меня <b>админом</b>. Также можно ответить на любое сообщение командой /check.",
        "en": "🛡 Hi! I'll protect this group from scammers.\n\n"
              "I'll warn you when someone posts a dangerous link or file. Make me an <b>admin</b> so I can "
              "see every message. You can also reply to any message with /check.",
    },
    "group_warn": {
        "uz": "⚠️ <b>Diqqat! Bu xabar firibgarlikka o'xshaydi.</b>",
        "ru": "⚠️ <b>Внимание! Это сообщение похоже на мошенничество.</b>",
        "en": "⚠️ <b>Warning! This message looks like a scam.</b>",
    },
    "group_warn_tail": {
        "uz": "Havolani ochmang, faylni o'rnatmang, kod aytmang.",
        "ru": "Не открывайте ссылку, не устанавливайте файл, не называйте коды.",
        "en": "Don't open the link, install the file or share any code.",
    },
    "check_hint": {
        "uz": "Tekshirish uchun biror xabarga <b>javob</b> tariqasida /check yozing.",
        "ru": "Ответьте командой /check <b>на сообщение</b>, которое нужно проверить.",
        "en": "<b>Reply</b> to a message with /check to scan it.",
    },
    # ---------- screenshots ----------
    "ocr_read": {"uz": "📷 Rasmdan o'qildi", "ru": "📷 Прочитано с картинки", "en": "📷 Read from the image"},
    "ocr_empty": {
        "uz": "📷 Rasmda o'qiladigan matn topilmadi. Matnni nusxalab yuborib ko'ring.",
        "ru": "📷 На картинке не найден читаемый текст. Попробуйте скопировать текст.",
        "en": "📷 I couldn't find readable text in this image. Try copying the text instead.",
    },
    "ocr_off": {
        "uz": "📷 Rasmlarni o'qish hozircha o'chirilgan. Matnni nusxalab yuboring.",
        "ru": "📷 Чтение картинок сейчас отключено. Скопируйте текст.",
        "en": "📷 Screenshot reading is turned off right now. Please copy the text.",
    },
    # ---------- community reports ----------
    "report_btn": {"uz": "🚩 Firibgar deb belgilash", "ru": "🚩 Пожаловаться", "en": "🚩 Report as scam"},
    "report_done": {
        "uz": "🚩 <b>Rahmat!</b> Belgilandi:\n{items}\n\n{threshold} xil odam belgilagach, bot boshqalarni ham ogohlantiradi.",
        "ru": "🚩 <b>Спасибо!</b> Отмечено:\n{items}\n\nКогда отметят {threshold} разных человека, бот начнёт предупреждать остальных.",
        "en": "🚩 <b>Thanks!</b> Reported:\n{items}\n\nOnce {threshold} different people report it, the bot will warn everyone else.",
    },
    "report_none": {
        "uz": "🚩 Rahmat! Xabarda havola, telefon raqam yoki Telegram akkaunt topilmadi, lekin u AI modelni o'qitish uchun saqlandi.",
        "ru": "🚩 Спасибо! В сообщении нет ссылок, номеров или Telegram-аккаунтов, но оно сохранено для обучения AI-модели.",
        "en": "🚩 Thanks! No links, phone numbers or Telegram accounts were found, but the message was saved to train the AI model.",
    },
    "report_dup": {"uz": "Siz buni allaqachon belgilagansiz 👍", "ru": "Вы уже отметили это 👍", "en": "You already reported this 👍"},
    "report_hint": {
        "uz": "Firibgar xabarga <b>javob</b> tariqasida /report yozing.",
        "ru": "Ответьте командой /report <b>на сообщение</b> мошенника.",
        "en": "<b>Reply</b> to the scam message with /report.",
    },
    "hit_site": {
        "uz": "🚩 {n} foydalanuvchi {preview} ni firibgar deb belgilagan",
        "ru": "🚩 {n} пользователей отметили {preview} как мошенничество",
        "en": "🚩 {n} users reported {preview} as a scam",
    },
    "hit_phone": {
        "uz": "🚩 {n} foydalanuvchi {preview} raqamini firibgar deb belgilagan",
        "ru": "🚩 {n} пользователей отметили номер {preview} как мошеннический",
        "en": "🚩 {n} users reported the number {preview} as a scammer",
    },
    "hit_tg": {
        "uz": "🚩 {n} foydalanuvchi {preview} Telegram akkauntini firibgar deb belgilagan",
        "ru": "🚩 {n} пользователей отметили Telegram-аккаунт {preview} как мошеннический",
        "en": "🚩 {n} users reported the Telegram account {preview} as a scammer",
    },
    # ---------- bot profile (set automatically on startup) ----------
    "bot_short": {
        "uz": "🛡 Firibgarlikni aniqlovchi AI bot. Shubhali xabar, havola yoki faylni forward qiling!",
        "ru": "🛡 AI-бот против мошенников. Перешлите подозрительное сообщение, ссылку или файл!",
        "en": "🛡 AI scam detector. Forward any suspicious message, link or file!",
    },
    "bot_description": {
        "uz": "🛡 ScamGuard — O'zbekiston uchun firibgarlikni aniqlovchi AI bot.\n\n"
              "✅ Soxta yutuq, «bank xodimi», OLX va .apk firibgarliklari\n"
              "✅ Soxta saytlar: c1ick.uz, paymе-bonus.xyz\n"
              "✅ Skrinshotlarni o'qiydi\n"
              "✅ O'zbek (lotin/kirill), rus va ingliz tillari\n"
              "✅ Guruhlarni himoya qiladi\n"
              "🔒 Xabarlaringiz saqlanmaydi\n\n"
              "«Start» ni bosing va shubhali xabarni forward qiling 👇",
        "ru": "🛡 ScamGuard — AI-бот для распознавания мошенничества в Узбекистане.\n\n"
              "✅ Фейковые выигрыши, «сотрудники банка», OLX и .apk\n"
              "✅ Поддельные сайты: c1ick.uz, paymе-bonus.xyz\n"
              "✅ Читает скриншоты\n"
              "✅ Узбекский (латиница/кириллица), русский и английский\n"
              "✅ Защищает группы\n"
              "🔒 Сообщения не сохраняются\n\n"
              "Нажмите «Старт» и перешлите подозрительное сообщение 👇",
        "en": "🛡 ScamGuard: an AI scam detector built for Uzbekistan.\n\n"
              "✅ Fake prizes, \"bank staff\", OLX and .apk scams\n"
              "✅ Fake sites like c1ick.uz, paymе-bonus.xyz\n"
              "✅ Reads screenshots\n"
              "✅ Uzbek (Latin/Cyrillic), Russian and English\n"
              "✅ Protects group chats\n"
              "🔒 Your messages are not stored\n\n"
              "Press Start and forward a suspicious message 👇",
    },
    "cmd_start": {"uz": "Botni ishga tushirish", "ru": "Запустить бота", "en": "Start the bot"},
    "cmd_help": {"uz": "Qanday tekshiraman", "ru": "Как проверить", "en": "How to check"},
    "cmd_sos": {"uz": "Aldandim — nima qilay?", "ru": "Меня обманули — что делать?", "en": "I got scammed, what now?"},
    "cmd_types": {"uz": "Firibgarlik turlari", "ru": "Виды мошенничества", "en": "Scam types"},
    "cmd_stats": {"uz": "Statistika", "ru": "Статистика", "en": "Statistics"},
    "cmd_lang": {"uz": "Tilni o'zgartirish", "ru": "Сменить язык", "en": "Change language"},
    "cmd_privacy": {"uz": "Maxfiylik", "ru": "Конфиденциальность", "en": "Privacy"},
    "cmd_report": {"uz": "Firibgarni belgilash (javob sifatida)", "ru": "Пожаловаться на мошенника (ответом)",
                   "en": "Report a scammer (as a reply)"},
    "cmd_check": {"uz": "Guruhda xabarni tekshirish (javob sifatida)", "ru": "Проверить сообщение в группе (ответом)",
                  "en": "Scan a message in a group (as a reply)"},
}

# (id, title, how it works, red flag)
SCAM_TYPES: dict[str, list[tuple[str, str, str, str]]] = {
    "uz": [
        ("bank", "🏦 «Bank xodimi»", "Qo'ng'iroq qilib yoki yozib, «kartangizda shubhali operatsiya» deydi va SMS kodni so'raydi.",
         "Hech bir bank SMS kod, CVV yoki parolni so'ramaydi. Go'shakni qo'ying va bankka o'zingiz qo'ng'iroq qiling."),
        ("prize", "🎁 Soxta yutuq", "«iPhone yutdingiz!» deb, sovg'ani olish uchun havolaga kirish yoki «yetkazish to'lovi»ni so'raydi.",
         "Qatnashmagan tanlovda yutib bo'lmaydi. Sovg'a uchun pul so'rashsa — bu firibgarlik."),
        ("olx", "🛒 OLX / savdo", "«Xaridor» pulni o'tkazdim, olish uchun havolaga kirib karta ma'lumotini kiriting deydi.",
         "Pul olish uchun hech qachon CVV yoki SMS kod kerak emas. Faqat uchrashib yoki ishonchli usulda savdo qiling."),
        ("apk", "📱 .apk fayllar", "«Rasmlarni ko'r», «posilkani kuzat» deb .apk fayl yuboradi. U SMS kodlaringizni o'g'irlaydi.",
         "Rasm yoki hujjat hech qachon .apk bo'lmaydi. Ilovalarni faqat Play Market'dan o'rnating."),
        ("relative", "👨‍👩‍👧 Qarindosh nomidan", "«Ona, bu men, yangi raqamim. Muammoga qoldim, pul tashla» deb yozadi.",
         "Pul yuborishdan oldin o'sha odamning eski raqamiga qo'ng'iroq qiling yoki faqat siz biladigan savol bering."),
        ("invest", "💸 Oson daromad / kripto", "«Kuniga 500 ming», «pulingizni 2 barobar qilamiz» deb avval to'lov yoki investitsiya so'raydi.",
         "Kafolatlangan yuqori daromad yo'q. Ishga olish uchun pul so'rashsa — firibgarlik."),
        ("gov", "🏛 Davlat nomidan", "«Sizga kompensatsiya ajratildi» yoki «jarima bor» deb karta ma'lumoti yoki to'lov so'raydi.",
         "Davlat idoralari messenjerda karta ma'lumotini so'ramaydi. Faqat my.gov.uz orqali tekshiring."),
        ("phish", "🔗 Soxta saytlar", "c1ick.uz, paymе-bonus.xyz kabi asliga o'xshash saytda login, karta yoki kod kiritishingizni so'raydi.",
         "Manzilni harfma-harf tekshiring. Bank va to'lov ilovalarini faqat o'zingiz ochib kiring."),
    ],
    "ru": [
        ("bank", "🏦 «Сотрудник банка»", "Звонит или пишет: «по вашей карте подозрительная операция» — и просит SMS-код.",
         "Ни один банк не спрашивает SMS-код, CVV или пароль. Положите трубку и сами позвоните в банк."),
        ("prize", "🎁 Фейковый выигрыш", "«Вы выиграли iPhone!» — просят перейти по ссылке или оплатить «доставку».",
         "Нельзя выиграть в конкурсе, в котором не участвовали. Просят деньги за подарок — это обман."),
        ("olx", "🛒 OLX / продажи", "«Покупатель» пишет, что уже оплатил, и просит ввести данные карты по ссылке, чтобы получить деньги.",
         "Для получения денег никогда не нужен CVV или SMS-код. Продавайте при личной встрече или надёжным способом."),
        ("apk", "📱 Файлы .apk", "Присылают .apk под видом «фото» или «трекинга посылки». Он крадёт ваши SMS-коды.",
         "Фото или документ никогда не бывает .apk. Устанавливайте приложения только из Play Маркета."),
        ("relative", "👨‍👩‍👧 От имени родственника", "«Мама, это я, новый номер. Попал в беду, скинь денег».",
         "Перед переводом позвоните на старый номер или задайте вопрос, ответ на который знаете только вы."),
        ("invest", "💸 Лёгкий заработок / крипта", "«500 тысяч в день», «удвоим депозит» — просят сначала оплату или вложение.",
         "Гарантированного высокого дохода не бывает. Просят деньги за трудоустройство — это обман."),
        ("gov", "🏛 От имени государства", "«Вам положена компенсация» или «у вас штраф» — просят данные карты или оплату.",
         "Госорганы не запрашивают данные карты в мессенджерах. Проверяйте только через my.gov.uz."),
        ("phish", "🔗 Поддельные сайты", "Сайты вроде c1ick.uz, paymе-bonus.xyz просят ввести логин, карту или код.",
         "Проверяйте адрес побуквенно. Открывайте банковские и платёжные приложения только сами."),
    ],
    "en": [
        ("bank", "🏦 \"Bank staff\"", "Calls or texts saying \"suspicious activity on your card\" and asks for your SMS code.",
         "No bank ever asks for SMS codes, CVV or passwords. Hang up and call your bank yourself."),
        ("prize", "🎁 Fake prize", "\"You won an iPhone!\" Then they ask you to open a link or pay a \"delivery fee\".",
         "You can't win a contest you never entered. Paying to receive a gift means it's a scam."),
        ("olx", "🛒 OLX / marketplace", "A \"buyer\" says they've paid and asks you to enter card details via a link to receive it.",
         "Receiving money never needs your CVV or SMS code. Sell in person or through a trusted method."),
        ("apk", "📱 .apk files", "They send an .apk disguised as \"photos\" or \"parcel tracking\". It steals your SMS codes.",
         "A photo or document is never an .apk. Only install apps from the Play Store."),
        ("relative", "👨‍👩‍👧 Posing as family", "\"Mom, it's me, new number. I'm in trouble, send money.\"",
         "Before paying, call their old number or ask something only they would know."),
        ("invest", "💸 Easy money / crypto", "\"Earn 500k a day\", \"we'll double your deposit\". They ask you to pay or invest first.",
         "Guaranteed high returns don't exist. Paying to get a job is a scam."),
        ("gov", "🏛 Posing as government", "\"You're owed compensation\" or \"you have a fine\". They ask for card details or payment.",
         "Government bodies don't ask for card details in messengers. Check only on my.gov.uz."),
        ("phish", "🔗 Fake websites", "Sites like c1ick.uz or paymе-bonus.xyz ask for your login, card or code.",
         "Check the address letter by letter. Open bank and payment apps yourself."),
    ],
}


def t(key: str, lang: str, **kwargs) -> str:
    entry = T[key]
    text = entry.get(lang) or entry["uz"]
    return text.format(**kwargs) if kwargs else text


def all_variants(key: str) -> set[str]:
    """Every language's text for a key; used to match menu buttons."""
    return set(T[key].values())


def guess_lang(language_code: str | None) -> str:
    code = (language_code or "").lower()
    if code.startswith("ru"):
        return "ru"
    if code.startswith("en"):
        return "en"
    return "uz"
