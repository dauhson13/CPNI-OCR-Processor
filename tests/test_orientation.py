import random

import numpy as np
import pytest
from PIL import Image

from piiscan import ocr
from piiscan.synth import docs

pytestmark = pytest.mark.skipif(not ocr.models_ready(), reason="run `uv run scripts/setup.py` to install OCR models")


@pytest.mark.parametrize("applied", [0, 2, -3, 7, 80, 133.5, 180, 200, 265, 350])
def test_any_angle(applied):
    from piiscan.ocr.orientation import needed_rotation

    img = docs.page_image(docs.filler_lines(random.Random(applied)), rotate=applied)
    correction = needed_rotation(img)
    assert abs(((correction + applied + 180) % 360) - 180) <= 1, correction


def test_blank_and_photo_like_pages_are_left_alone():
    from piiscan.ocr.orientation import needed_rotation

    assert needed_rotation(Image.new("L", (1000, 1300), 255)) == 0
    noise = Image.fromarray(np.random.default_rng(0).integers(0, 256, (1300, 1000), dtype=np.uint8))
    assert needed_rotation(noise) == 0


@pytest.mark.parametrize("applied", [0, 3, -2, 90, 180, 268])
def test_column_aligned_bills_are_not_turned_sideways(applied):
    from piiscan.ocr.orientation import needed_rotation

    rng = random.Random(applied)
    rows = [f"2026-0{rng.randint(1, 9)}-{rng.randint(10, 28)}  Invoice {rng.randint(10**6, 10**7)}  "
            f"${rng.randint(10, 999)}.{rng.randint(10, 99)}  Acct 0{rng.randint(10**9, 10**10 - 1)}" for _ in range(30)]
    correction = needed_rotation(docs.page_image(rows, rotate=applied))
    assert abs(((correction + applied + 180) % 360) - 180) <= 1, correction
