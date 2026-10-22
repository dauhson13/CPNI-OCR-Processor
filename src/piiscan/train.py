import hashlib
import json
import random
import shutil
from datetime import datetime, timezone
from pathlib import Path

from .labeling import TRAINING_DIR
from .ocr import MODELS_DIR, device
from .ocr.handwriting import MAX_TOKENS, MODEL_DIR, load, recognize
from .synth import handwriting as hw

BASE = MODELS_DIR / "hf" / "trocr-small-stage1"
OUT = MODEL_DIR
REAL_SHARE = 0.3
MAX_REPEATS = 20
MIN_REAL_VAL = 20
SYNTH_TOLERANCE = 0.01


def cer(pred: str, ref: str) -> float:
    prev = list(range(len(ref) + 1))
    for i, p in enumerate(pred, 1):
        cur = [i]
        for j, r in enumerate(ref, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (p != r)))
        prev = cur
    return prev[-1] / max(1, len(ref))


def held_out(label_id: str) -> bool:
    return int(hashlib.sha1(label_id.encode()).hexdigest()[:8], 16) % 10 == 0


def real_samples(store_dir: Path = TRAINING_DIR) -> tuple[list, list]:
    from PIL import Image

    path = store_dir / "labels.jsonl"
    if not path.exists():
        return [], []
    train, holdout = [], []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        crop = store_dir / "crops" / f"{rec['id']}.png"
        if crop.exists():
            item = (Image.open(crop).convert("RGB"), rec["text"])
            (holdout if held_out(rec["id"]) else train).append(item)
    return train, holdout


def mean_cer(proc, model, samples: list) -> float:
    preds = recognize(proc, model, [im for im, _ in samples])
    return sum(cer(p, t) for (p, _), (_, t) in zip(preds, samples)) / max(1, len(samples))


def train(steps: int = 3000, batch: int = 16, lr: float = 5e-5, eval_every: int = 500, synthetic_val: int = 300,
          store_dir: Path = TRAINING_DIR, out: Path = OUT, log=print) -> dict:
    import torch

    start_from = out if (out / "config.json").exists() else BASE
    if not (start_from / "config.json").exists():
        raise SystemExit("piiscan: base model missing; run `uv run scripts/setup.py`")
    proc, model = load(start_from)
    tok = proc.tokenizer
    model.to(device()).train()
    opt = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=0.01)
    warmup = min(200, steps // 10 + 1)
    sched = torch.optim.lr_scheduler.LambdaLR(
        opt, lambda s: min(1.0, (s + 1) / warmup) * max(0.05, 1 - s / max(1, steps)))
    rng = random.Random(0)
    synth = hw.lines(10**9, seed=int(datetime.now().timestamp()))
    val = list(hw.lines(synthetic_val, seed=999))
    real_train, real_val = real_samples(store_dir)
    judge = "your held-out labels" if len(real_val) >= MIN_REAL_VAL else "synthetic lines"
    log(f"training from {start_from.name}: {steps} steps x {batch}, your labels: {len(real_train)} train / "
        f"{len(real_val)} held out, device {device()}; the best version is chosen by {judge}")
    per_batch = min(batch * REAL_SHARE, len(real_train) * MAX_REPEATS / steps)
    best, report, baseline = float("inf"), {}, None
    if start_from == out:
        model.eval()
        synth_cer, real_cer, best = _score(proc, model, val, real_val)
        model.train()
        baseline = synth_cer
        log(f"current model: CER synthetic {synth_cer:.3f}" + (f", your held-out labels {real_cer:.3f}" if real_cer is not None else ""))
    for step in range(1, steps + 1):
        k = int(per_batch) + (rng.random() < per_batch % 1)
        items = [next(synth) for _ in range(batch - k)] + [rng.choice(real_train) for _ in range(k)]
        pixel = proc(images=[im for im, _ in items], return_tensors="pt").pixel_values.to(model.device)
        ids = tok([t for _, t in items], padding=True, max_length=MAX_TOKENS, truncation=True,
                  return_tensors="pt").input_ids[:, 1:]
        ids[ids == tok.pad_token_id] = -100
        loss = model(pixel_values=pixel, labels=ids.to(model.device)).loss
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        opt.step()
        sched.step()
        opt.zero_grad()
        if step % eval_every == 0 or step == steps:
            model.eval()
            synth_cer, real_cer, score = _score(proc, model, val, real_val)
            model.train()
            if baseline is not None and len(real_val) < MIN_REAL_VAL:
                keep = synth_cer <= baseline + SYNTH_TOLERANCE
            else:
                keep = score < best
            log(f"step {step}/{steps}  loss {loss.item():.3f}  CER synthetic {synth_cer:.3f}"
                + (f"  CER your held-out labels {real_cer:.3f}" if real_cer is not None else "")
                + ("  (saved)" if keep else ""))
            if keep:
                best = min(best, score)
                report = {"trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                          "started_from": start_from.name, "step": step, "cer_synthetic": round(synth_cer, 4),
                          "cer_your_labels": None if real_cer is None else round(real_cer, 4),
                          "your_labels_train": len(real_train), "your_labels_held_out": len(real_val)}
                _save(proc, model, out, report)
    log("done: saved the new version" if report else "done: no version was good enough, so the current model was kept unchanged")
    return report


def _score(proc, model, val: list, real_val: list) -> tuple[float, float | None, float]:
    synth_cer = mean_cer(proc, model, val)
    real_cer = mean_cer(proc, model, real_val) if real_val else None
    return synth_cer, real_cer, real_cer if real_cer is not None and len(real_val) >= MIN_REAL_VAL else synth_cer


def _save(proc, model, out: Path, report: dict) -> None:
    tmp = out.with_name(out.name + ".tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    model.save_pretrained(tmp)
    proc.save_pretrained(tmp)
    (tmp / "model_card.json").write_text(json.dumps(report, indent=2))
    shutil.rmtree(out, ignore_errors=True)
    tmp.rename(out)
