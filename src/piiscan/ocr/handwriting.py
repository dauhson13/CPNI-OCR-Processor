from pathlib import Path

from . import MODELS_DIR, device

MODEL_DIR = MODELS_DIR / "handwriting"
MAX_TOKENS = 64
_loaded = None


def available() -> bool:
    return (MODEL_DIR / "config.json").exists()


def load(path: Path):
    from transformers import TrOCRProcessor, VisionEncoderDecoderModel

    proc = TrOCRProcessor.from_pretrained(path)
    model = VisionEncoderDecoderModel.from_pretrained(path)
    tok = proc.tokenizer
    for cfg in (model.config, model.generation_config):
        cfg.decoder_start_token_id, cfg.pad_token_id, cfg.eos_token_id = tok.cls_token_id, tok.pad_token_id, tok.sep_token_id
    model.generation_config.max_new_tokens = MAX_TOKENS
    return proc, model


def recognize(proc, model, images: list, batch: int = 32) -> list[tuple[str, float]]:
    import torch

    out = []
    with torch.inference_mode():
        for i in range(0, len(images), batch):
            pixel = proc(images=images[i:i + batch], return_tensors="pt").pixel_values.to(model.device)
            gen = model.generate(pixel, num_beams=1, output_scores=True, return_dict_in_generate=True)
            texts = proc.batch_decode(gen.sequences, skip_special_tokens=True)
            scores = model.compute_transition_scores(gen.sequences, gen.scores, normalize_logits=True)
            for text, s in zip(texts, scores):
                kept = s[torch.isfinite(s)]
                out.append((text.strip(), float(kept.mean().exp()) if len(kept) else 0.0))
    return out


def read(images: list) -> list[tuple[str, float]]:
    global _loaded
    if _loaded is None:
        proc, model = load(MODEL_DIR)
        _loaded = proc, model.to(device()).eval()
    return recognize(*_loaded, images)
