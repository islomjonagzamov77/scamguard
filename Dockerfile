# ScamGuard bot image (used by Railway, works on any Docker host)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SCAMGUARD_DATA_DIR=/data

WORKDIR /app

# OCR engine for reading screenshots: Uzbek (Latin + Cyrillic), Russian, English
RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-uzb tesseract-ocr-uzb-cyrl tesseract-ocr-rus \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# Train the baseline model during the build (models/*.joblib is not committed),
# then run the tests so a broken commit never gets deployed.
RUN python train.py && SCAMGUARD_DATA_DIR=/tmp/sg-test python -m pytest -q && rm -rf /tmp/sg-test

# Run as an unprivileged user
RUN useradd --create-home scamguard && mkdir -p /data && chown -R scamguard /app /data
USER scamguard

CMD ["python", "bot.py"]
