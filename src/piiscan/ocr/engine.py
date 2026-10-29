from PIL import Image as PILImage

from ..model import Span
from . import handwriting
from .orientation import predictor, straighten

WEAK_WORD = 0.9
SURE_DIGITS = 0.97


def read_page(img, page: int | None) -> tuple[float, list[Span]]:
    angle, upright, result = straighten(img)
    return angle, read_upright(upright, page, f"ocr, page turned {angle:+.1f}°" if abs(angle) >= 1 else "ocr", result)


def read_upright(upright, page: int | None, note: str = "ocr", result=None) -> list[Span]:
    if result is None:
        result = predictor()([upright])
    lines = [line for block in result.pages[0].blocks for line in block.lines if line.words]
    words = [[(w.value, _box(w), float(w.confidence)) for w in line.words] for line in lines]
    spans = [_span(words, page, note, "ocr_printed")]

    runs = [(i, s, e) for i, line in enumerate(words) for s, e in _runs(line)]
    if runs and handwriting.available():
        h, w = upright.shape[:2]
        boxes = [_union([b for _, b, _ in words[i][s:e]]) for i, s, e in runs]
        crops = [PILImage.fromarray(upright[int(y0 * h):int(y1 * h) + 1, int(x0 * w):int(x1 * w) + 1])
                 for x0, y0, x1, y1 in (_pad(b) for b in boxes)]
        reread = [list(line) for line in words]
        for (i, s, e), box, (text, conf) in sorted(zip(runs, boxes, handwriting.read(crops)), key=lambda r: -r[0][1]):
            reread[i][s:e] = [(text, box, conf)] if text else []
        spans.append(_span(reread, page, note.replace("ocr", "handwriting", 1), "ocr_hand"))
    return spans


def _runs(line) -> list[tuple[int, int]]:
    runs, start = [], None
    for i, (value, _, conf) in enumerate(line + [("", None, 1.0)]):
        weak = conf < WEAK_WORD or (conf < SURE_DIGITS and any(c.isdigit() for c in value))
        if weak and start is None:
            start = i
        elif not weak and start is not None:
            runs.append((start, i))
            start = None
    return runs


def _span(lines, page, locator, source) -> Span:
    index, texts, offset = [], [], 0
    for line in lines:
        for value, box, conf in line:
            index.append((offset, offset + len(value), box, conf))
            offset += len(value) + 1
        texts.append(" ".join(value for value, _, _ in line))
    return Span("\n".join(texts), page=page, locator=locator, where=_lookup(index), source=source)


def _box(word):
    (x0, y0), (x1, y1) = word.geometry
    return x0, y0, x1, y1


def _union(boxes):
    return min(b[0] for b in boxes), min(b[1] for b in boxes), max(b[2] for b in boxes), max(b[3] for b in boxes)


def _pad(box, pad: float = 0.25):
    x0, y0, x1, y1 = box
    d = (y1 - y0) * pad
    return max(0.0, x0 - d), max(0.0, y0 - d), min(1.0, x1 + d), min(1.0, y1 + d)


def _lookup(index):
    def where(start, end):
        hits = [(box, conf) for a, z, box, conf in index if a < end and start < z]
        if not hits:
            return None, None, 1.0
        return None, tuple(round(v, 5) for v in _union([b for b, _ in hits])), min(c for _, c in hits)

    return where
