import json
import random
import urllib.request
from pathlib import Path

from ..ocr import MODELS_DIR

FONTS_DIR = MODELS_DIR / "fonts"
FAMILIES = [
    "ofl/caveat", "ofl/indieflower", "ofl/patrickhand", "ofl/shadowsintolight", "ofl/reeniebeanie", "ofl/kalam",
    "ofl/gochihand", "ofl/nanumpenscript", "ofl/dancingscript", "ofl/coveredbyyourgrace", "ofl/architectsdaughter",
    "ofl/nothingyoucoulddo", "ofl/cedarvillecursive", "ofl/dawningofanewday", "ofl/labelleaurore", "ofl/zeyada",
    "ofl/gloriahallelujah", "ofl/waitingforthesunrise", "ofl/sacramento", "apache/homemadeapple",
    "apache/rocksalt", "apache/schoolbell", "apache/justanotherhand", "ofl/swankyandmoomoo", "ofl/delius",
]
STATE_SHAPES = ["A#######", "A############", "########", "#########", "A########", "AB######C", "##ABC#####"]
LABELS = ["Account No", "Account Number", "Acct #", "SSN", "DL#", "Driver's License", "Phone", "DOB",
          "Routing #", "Bank Acct", "Name", "Address", "Card #", "Passport", "Static IP", "CM MAC", "Serial #",
          "Circuit ID", "CVV", "Exp", "Data Usage", "Last Payment", "Service Address"]
HEX_DIGITS = "0123456789ABCDEF"


def download_fonts() -> int:
    FONTS_DIR.mkdir(parents=True, exist_ok=True)
    for family in FAMILIES:
        try:
            with urllib.request.urlopen(f"https://api.github.com/repos/google/fonts/contents/{family}", timeout=30) as r:
                entries = json.load(r)
        except OSError:
            continue
        for e in entries:
            if e["name"].lower().endswith(".ttf") and not (FONTS_DIR / e["name"]).exists():
                urllib.request.urlretrieve(e["download_url"], FONTS_DIR / e["name"])
    return len(fonts())


def fonts() -> list[Path]:
    return sorted(FONTS_DIR.glob("*.ttf"))


def _shape(rng: random.Random, shape: str) -> str:
    return "".join(rng.choice("0123456789") if c == "#" else rng.choice("ABCDEFGHJKLMNPRSTWXYZ") if c.isalpha() else c
                   for c in shape)


def sample_text(rng: random.Random, fake) -> str:
    d = lambda n: "".join(rng.choice("0123456789") for _ in range(n))
    h = lambda: "".join(rng.choice(HEX_DIGITS) for _ in range(2))
    values = [
        lambda: f"{rng.randint(1, 899):03d}-{rng.randint(1, 99):02d}-{rng.randint(1, 9999):04d}",
        lambda: d(9),
        lambda: "0" + d(10),
        lambda: d(10),
        lambda: d(rng.randint(4, 6)),
        lambda: _shape(rng, rng.choice(STATE_SHAPES)),
        lambda: f"({d(3)}) {d(3)}-{d(4)}" if rng.random() < 0.5 else f"{d(3)}-{d(3)}-{d(4)}",
        lambda: f"{rng.randint(1, 12)}/{rng.randint(1, 28)}/{rng.randint(1930, 2006)}",
        lambda: fake.name(),
        lambda: fake.street_address(),
        lambda: f"{fake.city()}, {fake.state_abbr()} {fake.zipcode()}",
        lambda: " ".join(d(4) for _ in range(4)),
        lambda: fake.email(),
        lambda: d(rng.randint(8, 12)),
        lambda: ".".join(str(rng.randint(1, 254)) for _ in range(4)),
        lambda: rng.choice(":-").join(h() for _ in range(6)),
        lambda: f"${rng.randint(1, 999)}.{d(2)}",
        lambda: f"{rng.randint(1, 999)}.{d(1)} {rng.choice(['GB', 'MB', 'min'])}",
        lambda: f"{_shape(rng, 'AB')}-{d(rng.randint(6, 9))}",
        lambda: f"{d(2)}/{_shape(rng, 'ABCD')}/{d(6)}",
        lambda: f"{rng.randint(1, 12):02d}/{d(2)}",
        lambda: f"{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}",
    ]
    value = rng.choice(values)()
    if rng.random() < 0.3:
        return f"{rng.choice(LABELS)}: {value}"
    return value


def render_line(text: str, font: Path, rng: random.Random):
    from PIL import Image, ImageDraw, ImageFilter, ImageFont

    size = rng.randint(34, 64)
    f = ImageFont.truetype(str(font), size)
    left, top, right, bottom = f.getbbox(text)
    pad = rng.randint(6, 24)
    img = Image.new("L", (right - left + 2 * pad, bottom - top + 2 * pad), rng.randint(215, 255))
    ImageDraw.Draw(img).text((pad - left, pad - top), text, font=f, fill=rng.randint(0, 90))
    shear = rng.uniform(-0.3, 0.3)
    img = img.transform((img.width + int(abs(shear) * img.height), img.height), Image.AFFINE,
                        (1, shear, -shear * img.height if shear > 0 else 0, 0, 1, 0), fillcolor=img.getpixel((0, 0)))
    img = img.rotate(rng.uniform(-3, 3), expand=True, fillcolor=img.getpixel((0, 0)))
    if rng.random() < 0.5:
        img = img.filter(ImageFilter.GaussianBlur(rng.uniform(0.3, 1.2)))
    if rng.random() < 0.5:
        import numpy as np

        arr = np.asarray(img, dtype=np.int16) + np.random.default_rng(rng.randrange(1 << 30)).integers(-25, 25, (img.height, img.width))
        img = Image.fromarray(arr.clip(0, 255).astype("uint8"))
    return img.convert("RGB")


def form_page(fields: list[tuple[str, str]], rng: random.Random, rotate: float = 0):
    from PIL import Image, ImageDraw, ImageFont

    page = Image.new("RGB", (2550, 3300), "white")
    draw, font, all_fonts = ImageDraw.Draw(page), ImageFont.load_default(size=42), fonts()
    y = 300
    for label, value in fields:
        draw.text((200, y), f"{label}:", fill="black", font=font)
        written = render_line(value, rng.choice(all_fonts), rng)
        x = 200 + int(draw.textlength(f"{label}:", font=font)) + 40
        page.paste(written, (x, y + 25 - written.height // 2))
        y += max(140, written.height + 60)
    return page.rotate(rotate, expand=True, fillcolor="white") if rotate else page


def lines(n: int, seed: int):
    from faker import Faker

    rng, fake, all_fonts = random.Random(seed), Faker("en_US"), fonts()
    if not all_fonts:
        raise SystemExit("piiscan: handwriting fonts are missing; run `uv run scripts/setup.py`")
    fake.seed_instance(seed)
    for _ in range(n):
        text = sample_text(rng, fake)
        yield render_line(text, rng.choice(all_fonts), rng), text
