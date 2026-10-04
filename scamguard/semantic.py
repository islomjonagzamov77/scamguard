"""Meaning-based scam detection with a pretrained multilingual sentence encoder.

The character n-gram model (model.py) learns which *spellings* appear in scams. It only knows
the ~400 messages it was trained on, so a scam told in new words slips past it. This module
uses multilingual-e5-small, a transformer pretrained on text in ~100 languages including Uzbek
and Russian, to turn a message into a 384-number vector that captures what it *means*.
Messages with similar meaning get similar vectors, whatever the wording or script.

On top of the vectors:
  * a logistic regression trained on our labeled messages gives a scam probability, and
  * a nearest-example search names the closest known scam ("similar to known fake-grant
    scams"), so the verdict stays explainable.

The encoder runs with onnxruntime on the CPU (no PyTorch), quantized to 8-bit: ~120 MB on disk,
a few milliseconds per message. Download it with `python -m scamguard.semantic download`.
If the files are missing the bot simply runs without this layer.
"""

from __future__ import annotations

import os
import sys
import urllib.request
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
ENCODER_DIR = Path(os.getenv("SCAMGUARD_ENCODER_DIR", ROOT / "models" / "e5-small"))
CLASSIFIER_PATH = Path(os.getenv("SCAMGUARD_SEMANTIC", ROOT / "models" / "semantic.joblib"))

HF_REPO = "Xenova/multilingual-e5-small"
HF_REVISION = "main"
ENCODER_FILES = {"onnx/model_quantized.onnx": "model.onnx", "tokenizer.json": "tokenizer.json"}
MAX_TOKENS = 256


class Encoder:
    """multilingual-e5-small: text -> unit-length 384-dim vectors."""

    def __init__(self, model_dir: Path = ENCODER_DIR):
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self.tokenizer = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
        self.tokenizer.enable_truncation(MAX_TOKENS)
        pad_id = self.tokenizer.token_to_id("<pad>")
        self.tokenizer.enable_padding(pad_id=pad_id, pad_token="<pad>")
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = int(os.getenv("SCAMGUARD_ENCODER_THREADS", "2"))
        opts.log_severity_level = 3
        self.session = ort.InferenceSession(str(model_dir / "model.onnx"), opts, providers=["CPUExecutionProvider"])
        self.inputs = {i.name for i in self.session.get_inputs()}

    def encode(self, texts: list[str], batch_size: int = 32) -> np.ndarray:
        out = []
        for start in range(0, len(texts), batch_size):
            # e5 expects a "query: " prefix for classification and similarity tasks.
            batch = self.tokenizer.encode_batch([f"query: {prepare(t)}" for t in texts[start:start + batch_size]])
            ids = np.array([b.ids for b in batch], dtype=np.int64)
            mask = np.array([b.attention_mask for b in batch], dtype=np.int64)
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

@dataclass
class SemanticResult:
    proba: float                  # probability that the message is a scam
    similar_category: str | None  # category of the most similar known scam, if close enough
    similarity: float             # cosine similarity to that scam (0..1)


# Two messages this close (cosine) are paraphrases of one scheme. Chosen on the training data:
# between different scam types similarity rarely goes above it. See train.py.
SIMILAR_AT = 0.90


@lru_cache(maxsize=1)
def _load_classifier():
    if not CLASSIFIER_PATH.exists():
        return None
    import joblib

    return joblib.load(CLASSIFIER_PATH)


def available() -> bool:
    return encoder_available() and _load_classifier() is not None


def predict(text: str) -> SemanticResult | None:
    bundle = _load_classifier()
    vec = embed(text) if bundle is not None else None
    if vec is None:
        return None
    proba = float(bundle["clf"].predict_proba(vec[None, :])[0][1])
    category, similarity = None, 0.0
    scams = bundle["scam_vectors"]
    if len(scams):
        sims = scams.astype(np.float32) @ vec
        best = int(sims.argmax())
        similarity = float(sims[best])
        if similarity >= SIMILAR_AT:
            category = bundle["scam_categories"][best]
    return SemanticResult(proba, category, similarity)


def build_bundle(vectors: np.ndarray, labels: np.ndarray, categories: list[str], c: float = 1.0) -> dict:
    """Fit the classifier on encoder vectors and keep the known scams for nearest-example search."""
    from sklearn.linear_model import LogisticRegression

    clf = LogisticRegression(max_iter=5000, class_weight="balanced", C=c).fit(vectors, labels)
    scam = labels == 1
    return {
        "clf": clf,
        "scam_vectors": vectors[scam].astype(np.float16),
        "scam_categories": [cat for cat, s in zip(categories, scam) if s],
        "encoder": HF_REPO,
    }


# ---------- download ----------

def download(target: Path = ENCODER_DIR, repo: str = HF_REPO, revision: str = HF_REVISION) -> None:
    """Fetch the quantized ONNX encoder and its tokenizer from Hugging Face."""
    target.mkdir(parents=True, exist_ok=True)
    for remote, local in ENCODER_FILES.items():
        dest = target / local
        if dest.exists() and dest.stat().st_size > 0:
            print(f"  {local}: already there")
            continue
        url = f"https://huggingface.co/{repo}/resolve/{revision}/{remote}"
        print(f"  {local} <- {url}")
        tmp = dest.with_suffix(dest.suffix + ".part")
        urllib.request.urlretrieve(url, tmp)
        tmp.replace(dest)


if __name__ == "__main__":
    if sys.argv[1:] == ["download"]:
        download()
        enc = Encoder()
        v = enc.encode(["Kartangiz bloklandi, SMS kodni yuboring", "Карта заблокирована, отправьте код из СМС"])
        print(f"OK: encoder works, similarity of an Uzbek and a Russian paraphrase = {float(v[0] @ v[1]):.2f}")
    else:
        print("usage: python -m scamguard.semantic download")
