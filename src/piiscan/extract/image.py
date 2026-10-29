from PIL import Image as PILImage
from pillow_heif import register_heif_opener

from ..model import Image

register_heif_opener()


def extract(f, name):
    im = PILImage.open(f)
    frames = getattr(im, "n_frames", 1)
    for i in range(frames):
        yield Image(page=i + 1 if frames > 1 else None, locator=None, load=lambda i=i: _frame(im, i))


def _frame(im, i):
    im.seek(i)
    return im.copy()
