"""Real OCR test (no mocks). Skipped automatically where Tesseract isn't installed (e.g. a laptop)."""

import io

import pytest
from PIL import Image, ImageDraw, ImageFont

from scamguard import ocr
from scamguard.analyzer import Level, analyze

pytestmark = pytest.mark.skipif(not ocr.available(), reason="Tesseract not installed")


def screenshot(text_lines, dark: bool) -> bytes:
    font = ImageFont.load_default(size=28)
    bg, bubble, fg = ((24, 25, 30), (43, 82, 120), (235, 235, 235)) if dark else ((208, 224, 196), (255, 255, 255), (20, 20, 20))
    img = Image.new("RGB", (760, 110 + 42 * len(text_lines)), bg)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle((30, 30, 700, 70 + 42 * len(text_lines)), 22, fill=bubble)
    for i, line in enumerate(text_lines):
        d.text((55, 50 + 42 * i), line, font=font, fill=fg)
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=80)
    return buf.getvalue()


@pytest.mark.parametrize("dark", [False, True])
def test_reads_scam_screenshot_light_and_dark(dark):
    data = screenshot(["Your account has been suspended.", "Verify immediately at secure-login-",
                       "bank.xyz and send the SMS code"], dark)
    text = ocr.image_to_text(data)
    assert "suspended" in text.lower()
    assert "secure-login-bank.xyz" in text.lower()      # wrapped link is re-joined
    assert analyze(text, use_model=False).level != Level.SAFE


def test_garbage_is_harmless():
    assert ocr.image_to_text(b"not an image") == ""
    assert ocr.image_to_text(b"") == ""
