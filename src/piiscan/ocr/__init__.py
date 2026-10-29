import os
from pathlib import Path

MODELS_DIR = Path(__file__).resolve().parents[3] / "models"
os.environ.setdefault("DOCTR_CACHE_DIR", str(MODELS_DIR / "doctr"))
os.environ.setdefault("DOCTR_MULTIPROCESSING_DISABLE", "TRUE")
os.environ.setdefault("HF_HUB_OFFLINE", "1")

REQUIRED_MODELS = ("fast_base", "crnn_vgg16_bn")


def models_ready() -> bool:
    found = {p.name.split("-")[0] for p in (MODELS_DIR / "doctr" / "models").glob("*.pt")}
    return all(m in found for m in REQUIRED_MODELS)


def device():
    import torch

    if torch.cuda.is_available():
        return torch.device("cuda")
    if torch.backends.mps.is_available():
        return torch.device("mps")
    return torch.device("cpu")
