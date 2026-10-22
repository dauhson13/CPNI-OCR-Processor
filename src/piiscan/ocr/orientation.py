import cv2
import numpy as np

from . import device

MIN_INK = 0.001
MIN_SHARPNESS = 1.5
SAMPLE_WORDS = 30
_ocr = None


def predictor():
    global _ocr
    if _ocr is None:
        from doctr.models import ocr_predictor

        _ocr = ocr_predictor(det_arch="fast_base", reco_arch="crnn_vgg16_bn", pretrained=True,
                             assume_straight_pages=True, detect_orientation=False, straighten_pages=False).to(device())
    return _ocr


def straighten(img) -> tuple[float, np.ndarray]:
    rgb = img.convert("RGB")
    angle = line_angle(cv2.cvtColor(np.asarray(rgb), cv2.COLOR_RGB2GRAY))
    if angle is None:
        return 0.0, np.asarray(rgb)
    straight = np.asarray(rgb.rotate(angle, expand=True, fillcolor="white"))
    flip = _upside_down(straight)
    if flip is None:
        return 0.0, np.asarray(rgb)
    if flip:
        angle += 180
        straight = np.ascontiguousarray(straight[::-1, ::-1])
    angle = ((angle + 180) % 360) - 180
    return (180.0 if angle == -180 else round(angle, 1)), straight


def needed_rotation(img) -> float:
    return straighten(img)[0]


def line_angle(gray: np.ndarray) -> float | None:
    scale = 1000 / max(gray.shape)
    small = cv2.resize(gray, None, fx=scale, fy=scale, interpolation=cv2.INTER_AREA)
    ink = cv2.threshold(small, 0, 255, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)[1]
    if np.count_nonzero(ink) < MIN_INK * ink.size:
        return None
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
        return None
    return float(max(np.arange(best - 1, best + 1.01, 0.1), key=sharpness))


def _upside_down(straight: np.ndarray) -> bool | None:
    ocr = predictor()
    h, w = straight.shape[:2]
    boxes = sorted(ocr.det_predictor([straight])[0]["words"], key=lambda b: (b[2] - b[0]) * (b[3] - b[1]), reverse=True)
    crops = [straight[int(b[1] * h):int(b[3] * h), int(b[0] * w):int(b[2] * w)] for b in boxes[:SAMPLE_WORDS]]
    crops = [c for c in crops if c.shape[0] > 4 and c.shape[1] > 4]
    if len(crops) < 3:
        return None
    up = np.mean([conf for _, conf in ocr.reco_predictor(crops)])
    down = np.mean([conf for _, conf in ocr.reco_predictor([np.ascontiguousarray(c[::-1, ::-1]) for c in crops])])
    return down > up
