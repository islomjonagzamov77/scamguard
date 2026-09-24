import pytest

from scamguard.analyzer import Level, analyze
from scamguard.links import analyze_url, extract_urls
from scamguard.textnorm import mask_private, to_latin


@pytest.mark.parametrize("text", [
    "Tabriklaymiz! Siz iPhone yutib oldingiz! 24 soat ichida click-uz-bonus.xyz ga kiring",
    "Bank xavfsizlik xizmati: kartangiz bloklandi, SMS kodni ayting",
    "Картангиз блокланди. СМС кодни юборинг",
    "Служба безопасности банка. Продиктуйте код из смс",
    "Your account has been suspended. Verify immediately at secure-login.xyz",
    "Rasmlarni ko'ring: foto_2026.apk",
    "Pulni o'tkazib berdim, to'lovni qabul qilish uchun olx-uz.delivery.top ga kiring",
])
def test_scams_are_flagged(text):
    assert analyze(text, use_model=False).level != Level.SAFE


@pytest.mark.parametrize("text", [
    "Salom, ertaga soat 3 da uchrashamizmi?",
    "To'lovni click.uz orqali qildim, rahmat",
    "Assalomu alaykum, OLX dagi divan hali sotuvdami?",
    "Hey, are we still meeting at the library?",
    "Привет, как дела?",
    "Imtihon natijalari my.gov.uz saytida",
    "Hech kimga kodni aytmang! Tasdiqlash kodi: 482913",
    "Никому не сообщайте этот код: 551902",
])
def test_normal_messages_are_safe(text):
    assert analyze(text, use_model=False).level == Level.SAFE


@pytest.mark.parametrize("host", ["c1ick.uz", "click-bonus.xyz", "paymе.uz", "0lx-uz.com", "kapita1bank.uz"])
def test_lookalike_domains(host):
    assert analyze_url(f"https://{host}/login").score >= 0.7


@pytest.mark.parametrize("url", ["https://click.uz", "https://my.click.uz/pay", "olx.uz/d/item", "https://t.me/durov"])
def test_official_domains_are_clean(url):
    assert analyze_url(url).score == 0


def test_url_extraction():
    urls = extract_urls("Kiring: bit.ly/abc, yoki https://example.com/x?y=1. Rahmat")
    assert urls == ["bit.ly/abc", "https://example.com/x?y=1"]


def test_cyrillic_transliteration():
    assert to_latin("ютиб олдингиз") == "yutib oldingiz"
    assert to_latin("совға") == "sovg'a"


def test_private_data_masking():
    masked = mask_private("Karta 8600 1234 5678 9012, tel +998 90 123 45 67, a@b.uz")
    assert "8600" not in masked and "123 45 67" not in masked and "a@b.uz" not in masked


from scamguard.files import check_file  # noqa: E402


@pytest.mark.parametrize("name,expected", [
    ("EL YURT 1-xona ANSWERS.pdf", Level.SAFE),
    ("hisobot.docx", Level.SAFE),
    ("Rasm_2026.apk", Level.DANGEROUS),
    ("photo.jpg.apk", Level.DANGEROUS),
    ("invoice.pdf.exe", Level.DANGEROUS),
    ("budget.xlsm", Level.SUSPICIOUS),
    ("rasmlar.zip", Level.SUSPICIOUS),
])
def test_file_checks(name, expected):
    assert check_file(name).level == expected


def test_file_names_are_not_links():
    assert extract_urls("EL YURT 1-xona ANSWERS.pdf") == []
    assert analyze("EL YURT 1-xona ANSWERS.pdf", use_model=False).level == Level.SAFE
