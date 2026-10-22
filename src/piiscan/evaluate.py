import io
import json
import random
from collections import Counter, defaultdict

from . import worker
from .detect import value_hmac
from .labeling import TRAINING_DIR
from .ocr import handwriting
from .synth import docs
from .synth import handwriting as hw
from .synth.values import account, drivers_license, ssn
from .train import cer, held_out

KEY = b"eval" * 8
STREETS = ["Main", "Oak", "Cedar", "Mill", "Ranch", "Church", "Pecan", "Elm"]
SUFFIXES = ["St", "Ave", "Rd", "Dr", "Ln", "Hwy", "Way"]


def _aba(rng):
    d = [rng.randrange(10) for _ in range(8)]
    d[0], d[1] = 0, rng.randrange(1, 10)
    return "".join(map(str, d)) + str((10 - (3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + d[2] + d[5]) % 10) % 10)


def _visa(rng):
    body = [4] + [rng.randrange(10) for _ in range(14)]
    total = sum(x if i % 2 else (x * 2 - 9 if x * 2 > 9 else x * 2) for i, x in enumerate(reversed(body)))
    n = "".join(map(str, body)) + str((10 - total % 10) % 10)
    return " ".join(n[i:i + 4] for i in range(0, 16, 4)), n


def fields(rng, fake) -> list[tuple[str, str, str, str]]:
    a = account(rng)
    while a[1] == "0":
        a = account(rng)
    card, phone = _visa(rng), f"{rng.randint(2, 9)}{rng.randint(10, 99)}"
    exch = f"{rng.randint(2, 9)}{rng.randint(10, 99)}"
    line4 = f"{rng.randint(0, 9999):04d}"
    first, last = fake.first_name(), fake.last_name()
    month, day, year = rng.randint(1, 12), rng.randint(1, 28), rng.randint(1940, 2004)
    dl, sid = drivers_license(rng, rng.choice(["CA", "FL", "TX"])), drivers_license(rng, "CA")
    passport, bank, aba = f"{rng.choice('ABCDEFGHJK')}{rng.randint(10_000_000, 99_999_999)}", str(rng.randint(10**9, 10**12)), _aba(rng)
    s = ssn(rng)
    addr = f"{rng.randint(10, 9999)} {rng.choice(STREETS)} {rng.choice(SUFFIXES)}"
    return [
        ("SSN", s, "SSN", s.replace("-", "")),
        ("Account Number", a, "CUSTOMER_ACCOUNT", a),
        ("Account No", a[1:], "CUSTOMER_ACCOUNT", a),
        ("Account No (last 4)", a[-4:], "CUSTOMER_ACCOUNT", a[-4:]),
        ("Driver's License", dl, "DRIVERS_LICENSE", dl),
        ("State ID", sid, "STATE_ID", sid),
        ("Passport No", passport, "PASSPORT", passport),
        ("DOB", f"{month:02d}/{day:02d}/{year}", "DATE_OF_BIRTH", f"{year}-{month:02d}-{day:02d}"),
        ("Phone", f"({phone}) {exch}-{line4}", "PHONE_NUMBER", phone + exch + line4),
        ("Email", fake.email(), "EMAIL", None),
        ("Routing #", aba, "ROUTING_NUMBER", aba),
        ("Bank Account Number", bank, "BANK_ACCOUNT", bank),
        ("Card #", card[0], "CARD_NUMBER", card[1]),
        ("Customer Name", f"{first} {last}", "PERSON_NAME", f"{first} {last}".lower()),
        ("Service Address", addr, "ADDRESS", addr.lower()),
    ]


def synthetic_docs(n: int, seed: int = 7):
    from faker import Faker

    rng, fake = random.Random(seed), Faker("en_US")
    fake.seed_instance(seed)
    kinds = ["text", "docx", "pdf_text", "scan_typed", "form_handwritten"]
    for i in range(n):
        kind = kinds[i % len(kinds)]
        chosen = rng.sample(fields(rng, fake), rng.randint(3, 5))
        if kind == "form_handwritten":
            chosen = [f for f in chosen if f[2] not in ("EMAIL", "PERSON_NAME", "ADDRESS")] or chosen[:1]
        truth = {(t, value_hmac(KEY, t, (norm or value.lower()))) for _, value, t, norm in chosen}
        lines = [f"{label}: {value}" for label, value, _, _ in chosen]
        filler = docs.filler_lines(rng, 4)
        rotate = rng.choice([0, 0, 2, -3, 5, 90, 180, 265]) + (rng.uniform(-2, 2) if rng.random() < 0.3 else 0)
        if kind == "text":
            data, name = docs.text(filler[:2] + lines + filler[2:]), "doc.txt"
        elif kind == "docx":
            data, name = docs.docx(filler[:2] + lines + filler[2:]), "doc.docx"
        elif kind == "pdf_text":
            data, name = docs.pdf_text(filler[:2] + lines + filler[2:]), "doc.pdf"
        elif kind == "scan_typed":
            data, name = docs.pdf_scanned(filler[:2] + lines + filler[2:], rotate=rotate), "scan.pdf"
        else:
            buf = io.BytesIO()
            hw.form_page([(label, value) for label, value, _, _ in chosen], rng, rotate=rotate).save(buf, "PDF", resolution=300)
            data, name = buf.getvalue(), "form.pdf"
        yield kind, name, data, truth


def detection_metrics(n: int) -> tuple[dict, dict]:
    worker.init(KEY, quiet=False)
    tp, fp, fn = Counter(), Counter(), Counter()
    by_kind: dict[str, Counter] = defaultdict(Counter)
    for kind, name, data, truth in synthetic_docs(n):
        out: list[dict] = []
        worker.scan_blob(io.BytesIO(data), name, None, 0, out)
        found = {(f["pii_type"], f["value_hmac"]) for r in out for f in r["findings"]}
        for t, _ in truth & found:
            tp[t] += 1
        for t, _ in found - truth:
            fp[t] += 1
        for t, _ in truth - found:
            fn[t] += 1
        by_kind[kind]["found"] += len(truth & found)
        by_kind[kind]["planted"] += len(truth)
    per_type = {}
    for t in sorted(set(tp) | set(fp) | set(fn)):
        p = tp[t] / (tp[t] + fp[t]) if tp[t] + fp[t] else 0.0
        r = tp[t] / (tp[t] + fn[t]) if tp[t] + fn[t] else 0.0
        per_type[t] = {"precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0.0,
                       "planted": tp[t] + fn[t], "extra": fp[t]}
    return per_type, {k: c["found"] / c["planted"] for k, c in by_kind.items() if c["planted"]}


def printed_cer(n: int = 60) -> float:
    from PIL import Image, ImageDraw, ImageFont

    from .ocr.engine import read_page

    rng, font, total = random.Random(31), ImageFont.load_default(size=42), 0.0
    from faker import Faker

    fake = Faker("en_US")
    fake.seed_instance(31)
    for _ in range(n):
        text = hw.sample_text(rng, fake)
        img = Image.new("RGB", (2200, 140), "white")
        ImageDraw.Draw(img).text((40, 40), text, fill="black", font=font)
        _, spans = read_page(img, None)
        total += cer(spans[0].text.replace("\n", " "), text)
    return total / n


def handwritten_cer(n: int = 200) -> float | None:
    if not handwriting.available():
        return None
    samples = list(hw.lines(n, seed=4242))
    reads = handwriting.read([im for im, _ in samples])
    return sum(cer(p, t) for (p, _), (_, t) in zip(reads, samples)) / n


def your_labels(store_dir=TRAINING_DIR) -> dict:
    from PIL import Image

    from .detect import detect
    from .labeling import Store, label_types

    if not (store_dir / "labels.jsonl").exists() and not (store_dir / "completed.jsonl").exists():
        return {}
    store = Store(store_dir)
    recs = store.labels()
    pages = {(r["source"], r["page"]): (r["rotation_detected"], r["rotation_final"]) for r in recs}
    done = [json.loads(line) for line in store.done_path.read_text(encoding="utf-8").splitlines() if line.strip()] \
        if store.done_path.exists() else []
    for rec in done:
        pages.update({(rec["source"], int(p)): tuple(r) for p, r in rec["rotations"].items()})
    agree = sum(abs(((d - f + 180) % 360) - 180) <= 1 for d, f in pages.values())
    out = {"labels": len(recs), "pages": len(pages), "documents_complete": len({r["source"] for r in done}),
           "rotation_agreement": agree / len(pages) if pages else None,
           "by_type": dict(Counter(t for r in recs for t in label_types(r)))}
    crop = lambda r: store_dir / "crops" / f"{r['id']}.png"
    if not handwriting.available():
        return out
    held = [r for r in recs if held_out(r["id"]) and crop(r).exists()]
    for kind, flag in (("handwritten", True), ("printed", False)):
        group = [r for r in held if r["handwritten"] == flag]
        if group:
            reads = handwriting.read([Image.open(crop(r)).convert("RGB") for r in group])
            out[f"cer_{kind}"] = sum(cer(p, r["text"]) for (p, _), r in zip(reads, group)) / len(group)
            out[f"held_out_{kind}"] = len(group)
    nothing = [r for r in recs if label_types(r) == ["NONE"] and crop(r).exists()]
    if nothing:
        reads = handwriting.read([Image.open(crop(r)).convert("RGB") for r in nothing])
        out["none_fields"] = len(nothing)
        out["none_false_alarms"] = sum(any(True for _ in detect(text)) for text, _ in reads)
    return out


def evaluate(docs: int = 60, say=print) -> dict:
    say(f"Scanning {docs} synthetic documents with planted PII…")
    per_type, by_kind = detection_metrics(docs)
    say(f"\n{'PII type':<20}{'precision':>10}{'recall':>8}{'F1':>7}{'planted':>9}{'extra':>7}")
    for t, m in per_type.items():
        say(f"{t:<20}{m['precision']:>10.2f}{m['recall']:>8.2f}{m['f1']:>7.2f}{m['planted']:>9}{m['extra']:>7}")
    say("\nrecall by document kind: " + ", ".join(f"{k} {v:.2f}" for k, v in sorted(by_kind.items())))
    p_cer, h_cer = printed_cer(), handwritten_cer()
    say(f"\ncharacter error rate: printed {p_cer:.3f}, handwritten "
        + (f"{h_cer:.3f}" if h_cer is not None else "n/a (no handwriting model yet: `uv run main.py train`)"))
    mine = your_labels()
    if mine:
        say(f"\nyour labels: {mine['labels']} ({', '.join(f'{t} {n}' for t, n in sorted(mine['by_type'].items())) or 'none'}); "
            f"{mine['documents_complete']} documents complete; automatic rotation matched your correction on "
            + (f"{mine['rotation_agreement']:.0%} of {mine['pages']} pages" if mine["rotation_agreement"] is not None else "n/a"))
        if "none_fields" in mine:
            say(f"  fields you marked None: {mine['none_fields']}, falsely flagged as sensitive: {mine['none_false_alarms']}")
        for kind in ("handwritten", "printed"):
            if f"cer_{kind}" in mine:
                say(f"  held-out {kind}: {mine[f'held_out_{kind}']} lines, character error rate {mine[f'cer_{kind}']:.3f}")
    return {"per_type": per_type, "by_kind": by_kind, "cer_printed": p_cer, "cer_handwritten": h_cer, "your_labels": mine}
