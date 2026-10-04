"""Meaning-based scam detection with a pretrained multilingual sentence encoder.

The character n-gram model (model.py) learns which *spellings* appear in scams. It only knows
the ~400 messages it was trained on, so a scam told in new words slips past it. This module
uses multilingual-e5-small, a transformer pretrained on text in ~100 languages including Uzbek
and Russian, to turn a message into a 384-number vector that captures what it *means*.
Messages with similar meaning get similar vectors, whatever the wording or script.

On top of the vectors, a logistic regression trained on our labeled messages gives a scam
probability (model.py averages it with the character n-gram model). The same vectors let the
community teach the bot new scams without retraining (see community.py).

The encoder runs with onnxruntime on the CPU (no PyTorch): 16-bit weights (235 MB on disk, same
vectors as the 32-bit original), ~400 MB of RAM, about 10 ms per message. The 8-bit version is
smaller but measurably worse on unseen scam types (see RESULTS.md). Tokens come from the original
SentencePiece model (5 MB) rather than the 17 MB tokenizer.json, which alone needs ~290 MB of RAM;
both give identical tokens (checked on all 561 training and eval messages).
Download it with `python -m scamguard.semantic download`. If the files are missing the bot simply
runs without this layer.
"""

from __future__ import annotations

import os
import sys
import urllib.request
from functools import lru_cache
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
ENCODER_DIR = Path(os.getenv("SCAMGUARD_ENCODER_DIR", ROOT / "models" / "e5-small"))
CLASSIFIER_PATH = Path(os.getenv("SCAMGUARD_SEMANTIC", ROOT / "models" / "semantic.joblib"))

HF_REPO = "intfloat/multilingual-e5-small"
# Each file is pinned to a commit so every build gets exactly the same model.
ENCODER_FILES = {
    "model.onnx": "https://huggingface.co/Xenova/multilingual-e5-small/resolve/"
                  "761b726dd34fb83930e26aab4e9ac3899aa1fa78/onnx/model_fp16.onnx",
    "sentencepiece.bpe.model": "https://huggingface.co/intfloat/multilingual-e5-small/resolve/"
                               "614241f622f53c4eeff9890bdc4f31cfecc418b3/sentencepiece.bpe.model",
}
MAX_TOKENS = 256
BOS, PAD, EOS, UNK = 0, 1, 2, 3     # XLM-RoBERTa special tokens


class Encoder:
    """multilingual-e5-small: text -> unit-length 384-dim vectors."""

    def __init__(self, model_dir: Path = ENCODER_DIR):
        import onnxruntime as ort
        import sentencepiece

        self.sp = sentencepiece.SentencePieceProcessor(model_file=str(model_dir / "sentencepiece.bpe.model"))
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = int(os.getenv("SCAMGUARD_ENCODER_THREADS", "2"))
        opts.log_severity_level = 3
        self.session = ort.InferenceSession(str(model_dir / "model.onnx"), opts, providers=["CPUExecutionProvider"])
        self.inputs = {i.name for i in self.session.get_inputs()}

    def token_ids(self, text: str) -> list[int]:
        """XLM-RoBERTa ids: SentencePiece ids shifted by one (fairseq layout), wrapped in <s> ... </s>."""
        ids = [i + 1 if i else UNK for i in self.sp.encode(text)]
        return [BOS] + ids[:MAX_TOKENS - 2] + [EOS]

    def encode(self, texts: list[str], batch_size: int = 32) -> np.ndarray:
        out = []
        for start in range(0, len(texts), batch_size):
            # e5 expects a "query: " prefix for classification and similarity tasks.
            batch = [self.token_ids(f"query: {prepare(t)}") for t in texts[start:start + batch_size]]
            width = max(len(b) for b in batch)
            ids = np.array([b + [PAD] * (width - len(b)) for b in batch], dtype=np.int64)
            mask = np.array([[1] * len(b) + [0] * (width - len(b)) for b in batch], dtype=np.int64)
            feed = {"input_ids": ids, "attention_mask": mask}
            if "token_type_ids" in self.inputs:
                feed["token_type_ids"] = np.zeros_like(ids)
            hidden = self.session.run(None, feed)[0]                       # (batch, tokens, 384)
            summed = (hidden * mask[..., None]).sum(axis=1)
            vectors = summed / np.maximum(mask.sum(axis=1, keepdims=True), 1)  # mean over real tokens
            out.append(vectors / np.linalg.norm(vectors, axis=1, keepdims=True))
        return np.vstack(out).astype(np.float32) if out else np.zeros((0, 384), dtype=np.float32)


def prepare(text: str) -> str:
    """Light cleanup only: the encoder understands both scripts and Russian, so no transliteration.
    Private data is masked so card and phone numbers don't steer the meaning."""
    from .textnorm import mask_private

    return " ".join(mask_private(text).split())[:2000]


def encoder_available() -> bool:
    return get_encoder() is not None


@lru_cache(maxsize=1)
def get_encoder() -> Encoder | None:
    if os.getenv("SCAMGUARD_SEMANTIC_OFF") == "1" or not (ENCODER_DIR / "model.onnx").exists():
        return None
    try:
        return Encoder(ENCODER_DIR)
    except ImportError:
        return None


@lru_cache(maxsize=512)
def embed(text: str) -> np.ndarray | None:
    """Vector for one message (cached: the bot may look at the same text twice)."""
    enc = get_encoder()
    return None if enc is None else enc.encode([text])[0]


# ---------- the trained part (built by train.py) ----------

@lru_cache(maxsize=1)
def _load_classifier():
    if not CLASSIFIER_PATH.exists():
        return None
    import joblib

    return joblib.load(CLASSIFIER_PATH)


def available() -> bool:
    return encoder_available() and _load_classifier() is not None


def predict_proba(text: str) -> float | None:
    """Probability that `text` is a scam, or None without the encoder or the trained classifier."""
    clf = _load_classifier()
    vec = embed(text) if clf is not None else None
    if vec is None:
        return None
    return float(clf.predict_proba(vec[None, :].astype(np.float64))[0][1])


def make_classifier(c: float = 0.1):
    """Logistic regression on standardized vectors. e5 vectors all point in nearly the same direction
    (any two messages are ~0.8 similar), so the signal is in small differences per dimension;
    standardizing them first matters a lot: on held-out scam types it raised the share caught
    at 5% false alarms from 26% to 60% (measured with the 8-bit model)."""
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    return make_pipeline(StandardScaler(), LogisticRegression(C=c, max_iter=5000, class_weight="balanced"))


# ---------- download ----------

def download(target: Path = ENCODER_DIR) -> None:
    """Fetch the ONNX encoder and its SentencePiece model from Hugging Face."""
    target.mkdir(parents=True, exist_ok=True)
    for local, url in ENCODER_FILES.items():
        dest = target / local
        if dest.exists() and dest.stat().st_size > 0:
            print(f"  {local}: already there")
            continue
        print(f"  {local} <- {url}")
        tmp = dest.with_suffix(dest.suffix + ".part")
        urllib.request.urlretrieve(url, tmp)
        tmp.replace(dest)


if __name__ == "__main__":
    if sys.argv[1:] != ["download"]:
        sys.exit("usage: python -m scamguard.semantic download")
    download()
    if __package__:   # run as part of the package (not as a lone file in the Docker build): try it out
        v = Encoder().encode(["Kartangiz bloklandi, SMS kodni yuboring", "Карта заблокирована, отправьте код из СМС"])
        print(f"OK: encoder works, similarity of an Uzbek and a Russian paraphrase = {float(v[0] @ v[1]):.2f}")
