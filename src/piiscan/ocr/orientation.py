import cv2
import numpy as np

from . import device

MIN_INK = 0.001
MIN_SHARPNESS = 1.5
SAMPLE_WORDS = 30
AXIS_DOUBT = 0.5
_ocr = None


def predictor():
    global _ocr
    if _ocr is None:
        from doctr.models import ocr_predictor

        _ocr = ocr_predictor(det_arch="fast_base", reco_arch="crnn_vgg16_bn", pretrained=True,
                             assume_straight_pages=True, detect_orientation=False, straighten_pages=False).to(device())
    return _ocr


def straighten(img) -> tuple[float, np.ndarray, object]:
    rgb = img.convert("RGB")
    best = None
    for angle in line_angles(cv2.cvtColor(np.asarray(rgb), cv2.COLOR_RGB2GRAY)):
        straight = np.asarray(rgb.rotate(angle, expand=True, fillcolor="white"))
        result = predictor()([straight])
        text = sum(w.confidence * len(w.value) for b in result.pages[0].blocks for line in b.lines for w in line.words)
        if best is None or text > best[3]:
            best = angle, straight, result, text
    read = best and _readability(best[1], best[2])
    if not read:
        return 0.0, np.asarray(rgb), None
    angle, straight, result, _ = best
    up, down = read
    if down > up:
        angle += 180
        straight, result = np.ascontiguousarray(straight[::-1, ::-1]), None
    angle = ((angle + 180) % 360) - 180
    return (180.0 if angle == -180 else round(angle, 1)), straight, result


def needed_rotation(img) -> float:
    return straighten(img)[0]


def line_angles(gray: np.ndarray) -> list[float]:
    scale = 1000 / max(gray.shape)
    small = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)
    ink = cv2.threshold(small, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)[1]
    if np.count_nonzero(ink) < MIN_INK * ink.size:
        return []
    side = int(np.hypot(*ink.shape)) + 2
    canvas = np.zeros((side, side), np.uint8)
    y0, x0 = (side - ink.shape[0]) // 2, (side - ink.shape[1]) // 2
    canvas[y0:y0 + ink.shape[0], x0:x0 + ink.shape[1]] = ink
    center = (side / 2, side / 2)

    def sharpness(a):
        turned = cv2.warpAffine(canvas, cv2.getRotationMatrix2D(center, a, 1), (side, side), flags=cv2.INTER_NEAREST)
        return np.var(turned.sum(axis=1, dtype=np.float64))

    coarse = {a: sharpness(a) for a in np.arange(-90.0, 90.0, 1.0)}
    best = max(coarse, key=coarse.get)
    if coarse[best] < MIN_SHARPNESS * np.median(list(coarse.values())):
        return []
    other = best + 90 if best < 0 else best - 90
    picks = [best] + ([other] if coarse[other] >= AXIS_DOUBT * coarse[best] else [])
    return [float(max(np.arange(a - 1, a + 1.01, 0.1), key=sharpness)) for a in picks]


def _readability(straight: np.ndarray, result) -> tuple[float, float] | None:
    ocr = predictor()
    h, w = straight.shape[:2]
    boxes = [(x0, y0, x1, y1) for block in result.pages[0].blocks for line in block.lines
             for (x0, y0), (x1, y1) in (word.geometry for word in line.words)]
    boxes.sort(key=lambda b: (b[2] - b[0]) * (b[3] - b[1]), reverse=True)
    crops = [straight[int(b[1] * h):int(b[3] * h), int(b[0] * w):int(b[2] * w)] for b in boxes[:SAMPLE_WORDS]]
    crops = [c for c in crops if c.shape[0] > 4 and c.shape[1] > 4]
    if len(crops) < 3:
        return None
    up = np.mean([conf for _, conf in ocr.reco_predictor(crops)])
    down = np.mean([conf for _, conf in ocr.reco_predictor([np.ascontiguousarray(c[::-1, ::-1]) for c in crops])])
    return float(up), float(down)
