"""Tests for the semantic AI model (multilingual-e5). Skipped where the encoder isn't downloaded;
the Docker build downloads it before running the tests, so they always run before a deploy."""

import numpy as np
import pytest

from scamguard import model, semantic

needs_encoder = pytest.mark.skipif(not semantic.encoder_available(),
                                   reason="encoder not downloaded (python -m scamguard.semantic download)")
needs_classifier = pytest.mark.skipif(not semantic.available(), reason="encoder or semantic.joblib missing")


def test_combine_averages_whatever_models_are_there():
    assert model.combine(0.2, 0.8) == pytest.approx(0.5)
    assert model.combine(0.3, None) == 0.3        # no encoder: char n-grams alone, as before
    assert model.combine(None, None) is None


def test_private_data_is_masked_before_encoding():
    assert "8600" not in semantic.prepare("Karta: 8600 1234 5678 9012, tel +998 90 123 45 67")


@needs_encoder
def test_token_ids_follow_the_xlm_roberta_layout():
    enc = semantic.get_encoder()
    ids = enc.token_ids("query: salom")
    assert ids[0] == semantic.BOS and ids[-1] == semantic.EOS
    assert len(enc.token_ids("so'z " * 2000)) == semantic.MAX_TOKENS


@needs_encoder
def test_vectors_are_unit_length_and_batching_does_not_change_them():
    enc = semantic.get_encoder()
    texts = ["Salom", "Kartangiz bloklandi, SMS kodni yuboring darhol, aks holda pulingiz yo'qoladi"]
    together = enc.encode(texts)
    one_by_one = np.vstack([enc.encode([t]) for t in texts])
    assert np.allclose(np.linalg.norm(together, axis=1), 1, atol=1e-4)
    assert np.allclose(together, one_by_one, atol=1e-3)          # padding must not leak into the mean


@needs_encoder
def test_same_meaning_in_another_language_is_closer_than_another_topic():
    uz, ru, other = semantic.get_encoder().encode([
        "Kartangiz bloklandi. Blokdan chiqarish uchun SMS kodni yuboring",
        "Ваша карта заблокирована. Чтобы разблокировать, отправьте код из СМС",
        "Ertaga soat uchda kutubxona oldida uchrashamiz",
    ])
    assert float(uz @ ru) > float(uz @ other) + 0.05


@needs_classifier
@pytest.mark.parametrize("text", [
    # worded unlike the rules: no "SMS kod", no link, no "yutdingiz"
    "Assalomu alaykum, men Germaniyadagi zavodga ishchi yig'yapman. Viza va chipta bizdan, faqat hujjat "
    "rasmiylashtirish uchun 300 dollar oldindan kerak bo'ladi",
    "Здравствуйте, вы выиграли в розыгрыше нашего магазина. Для получения приза оплатите доставку 50 000 сум",
])
def test_semantic_model_rates_scams_high(text):
    assert semantic.predict_proba(text) > 0.5


@needs_classifier
@pytest.mark.parametrize("text", [
    "Salom, ertaga soat 3 da uchrashamizmi?",
    "Привет, мама просила купить хлеб по дороге домой",
])
def test_semantic_model_rates_normal_messages_low(text):
    assert semantic.predict_proba(text) < 0.5
