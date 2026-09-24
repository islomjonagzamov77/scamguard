"""Read text from screenshots with Tesseract (Uzbek Latin + Cyrillic, Russian, English).

Images are processed in memory and never written to disk. If Tesseract is not
installed (e.g. on a laptop without it), `available()` returns False and the
bot tells the user that screenshot reading is not enabled.

Why adaptive thresholding: Tesseract binarizes with one global threshold. In a
chat screenshot that threshold often lands between the background and the
message bubble, so the text disappears into the bubble. Comparing every pixel
with its own neighbourhood keeps text readable whatever the bubble colours,
in light and dark mode.
"""

from __future__ import annotations

import io
import logging
import re
import shutil

log = logging.getLogger(__name__)

LANGS = "uzb+uzb_cyrl+rus+eng"
MAX_BYTES = 10 * 1024 * 1024
MAX_SIDE = 2400      # downscale huge photos (speed)
MIN_SIDE = 1000      # upscale small screenshots (accuracy)
TIMEOUT_S = 25


def available() -> bool:
    if shutil.which("tesseract") is None:
        return False
    try:
        import pytesseract  # noqa: F401
        from PIL import Image  # noqa: F401
    except ImportError:
        return False
    return True


def _prepare(image):
    from PIL import ImageChops, ImageFilter, ImageOps, ImageStat

    gray = ImageOps.exif_transpose(image).convert("L")
    w, h = gray.size
    longest = max(w, h)
    scale = MAX_SIDE / longest if longest > MAX_SIDE else MIN_SIDE / longest if longest < MIN_SIDE else 1.0
    if scale != 1.0:
        gray = gray.resize((max(1, int(w * scale)), max(1, int(h * scale))))
    # Dark mode: light text on a dark background -> invert so text is darker than its surroundings.
    if ImageStat.Stat(gray).mean[0] < 110:
        gray = ImageOps.invert(gray)
    # Adaptive threshold: a pixel is "ink" if it is clearly darker than its local average.
    local_mean = gray.filter(ImageFilter.BoxBlur(21))
    darker_by = ImageChops.subtract(local_mean, gray)
    return darker_by.point(lambda x: 0 if x > 12 else 255)


def _clean(text: str) -> str:
    # Re-join words and links that wrapped at a hyphen: "secure-login-\nbank.xyz"
    text = re.sub(r"(\w)-\s*\n\s*(\w)", r"\1-\2", text)
    lines = [ln.strip() for ln in text.splitlines()]
    # Drop OCR noise: very short fragments with no real word in them.
    return "\n".join(ln for ln in lines if len(re.findall(r"\w", ln)) >= 3)


def image_to_text(data: bytes) -> str:
    """Return the text found in an image (may be empty). Never raises."""
    if not data or len(data) > MAX_BYTES or not available():
        return ""
    import pytesseract
    from PIL import Image, UnidentifiedImageError

    try:
        with Image.open(io.BytesIO(data)) as img:
            prepared = _prepare(img)
        text = pytesseract.image_to_string(prepared, lang=LANGS, timeout=TIMEOUT_S)
    except (UnidentifiedImageError, RuntimeError, OSError, ValueError, pytesseract.TesseractError) as e:
        log.warning("OCR failed: %s", e)
        return ""
    return _clean(text)
